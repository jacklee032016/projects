/**
 * Some primitive asn methods for extraction ASN.1 data.
 */

#include "crypto.h"

/* 1.2.840.113549.1.1 OID prefix :iso(1);member-body(2); US(840); rsadsi(113549); ??(1); ??(1) - handle the following */
/* md5WithRSAEncryption(4) */
/* sha1WithRSAEncryption(5) */
/* sha256WithRSAEncryption (11) */
/* sha384WithRSAEncryption (12) */
/* sha512WithRSAEncryption (13) */
static const uint8_t sig_oid_prefix[] = 
{
	0x2a/* 1*40+2*/, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01 /* more one byte : algorithm as upper definations */
};

/* 1.3.14.3.2.29 SHA1 with RSA signature :{iso(1) identified-organization(3) oiw(14) secsig(3) algorithms(2) sha-1WithRSAEncryption(29)} */
static const uint8_t sig_sha1WithRSAEncrypt[] =
{
	0x2b, 0x0e, 0x03, 0x02, 0x1d
};

/* 2.16.840.1.101.3.4.2.1 SHA-256 : 
* {joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3) nistAlgorithm(4) hashAlgs(2) sha256(1)} 
* This OID is defined in National Institute of Standards and Technology (NIST), Federal Information Processing Standard (FIPS) Publication 180-3: Secure Hash Standard
* IETF RFC 3560. See also IETF RFC 5754 and RFC 5758
* refer to 
*/
/* 840/128=6, 6+128=134=0x86; 840-128*6=74=0x84 */
static const uint8_t sig_sha256[] =
{
	0x60/*2*40+16*/, 0x86, 0x48,/* these 2 bytes 840 */ 0x01/*1*/, 0x65/*101*/, 0x03, 0x04, 0x02, 0x01
};

/* 2.16.840.1.101.3.4.2.2 SHA-384 */
static const uint8_t sig_sha384[] =
{
	0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02
};

/* 2.16.840.1.101.3.4.2.3 SHA-512 */
static const uint8_t sig_sha512[] =
{
	0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03
};

/* id-ce   OBJECT IDENTIFIER ::=  { joint-iso-ccitt(2) ds(5) 29 } */
/* { joint-iso-ccitt(2) ds(5) :0x55 } */
static const uint8_t sig_subject_alt_name[] =
{
	0x55, 0x1d, 0x11
};


/* CN, O, OU */
static const uint8_t g_dn_types[] = { X520_COMMON_NAME, X520_ORGANIZATION_NAME, X520_ORGAN_UNIT_NAME};

uint32_t get_asn1_length(const uint8_t *buf, int *offset)
{
	int i;
	uint32_t len;

	if (!(buf[*offset] & 0x80)) /* short form */
	{
		len = buf[(*offset)++];
	}
	else  /* long form */
	{
		int length_bytes = buf[(*offset)++]&0x7f;
		if (length_bytes > 4)   /* limit number of bytes */
			return 0;

		len = 0;
		for (i = 0; i < length_bytes; i++)
		{
			len <<= 8;
			len += buf[(*offset)++];
		}
	}

	return len;
}

/**
 * Skip the ASN1.1 object type and its length. Get ready to read the object's data
 * move the read pointer to this object's data, and return the data length
 */
int asn1_next_obj(const uint8_t *buf, int *offset, int obj_type)
{
	if (buf[*offset] != obj_type)
		return X509_NOT_OK;
	(*offset)++; /* type field in type-length-value of DER */
	return get_asn1_length(buf, offset);
}

/*
 * Skip over an ASN.1 object type completely. Get ready to read the next object.
 * Move the pointer to next object
 */
int asn1_skip_obj(const uint8_t *buf, int *offset, int obj_type)
{
	int len;

	if (buf[*offset] != obj_type)
		return X509_NOT_OK;
	(*offset)++;
	len = get_asn1_length(buf, offset);
	*offset += len;
	return 0;
}

/**
 * Read an integer value for ASN.1 data
 * Note: This function allocates memory which must be freed by the user.
 */
int asn1_get_int(const uint8_t *buf, int *offset, uint8_t **object)
{
	int len;

	if ((len = asn1_next_obj(buf, offset, ASN1_INTEGER)) < 0)
		goto end_int_array;

	if (len > 1 && buf[*offset] == 0x00)    /* ignore the negative byte */
	{
		len--;
		(*offset)++;
	}

	*object = (uint8_t *)malloc(len);
	memcpy(*object, &buf[*offset], len);
	*offset += len;

end_int_array:
	return len;
}

/* Get all the RSA private key specifics from an ASN.1 encoded file */
EXP_FUNC int STDCALL asn1_get_private_key(const uint8_t *buf, int len, RSA_CTX **rsa_ctx)
{
	int offset = 7;
	uint8_t *modulus = NULL, *priv_exp = NULL, *pub_exp = NULL;
	int mod_len, priv_len, pub_len;
#ifdef CONFIG_BIGINT_CRT
	uint8_t *p = NULL, *q = NULL, *dP = NULL, *dQ = NULL, *qInv = NULL;
	int p_len, q_len, dP_len, dQ_len, qInv_len;
#endif

	/* not in der format */
	if (buf[0] != ASN1_SEQUENCE) /* basic sanity check */
	{
#ifdef CONFIG_SSL_FULL_MODE
		AX_LOG("Error: This is not a valid ASN.1 file\n");
#endif
		return X509_INVALID_PRIV_KEY;
	}

	/* Use the private key to mix up the RNG if possible. */
	RNG_custom_init(buf, len);

	mod_len = asn1_get_int(buf, &offset, &modulus);
	pub_len = asn1_get_int(buf, &offset, &pub_exp);
	priv_len = asn1_get_int(buf, &offset, &priv_exp);

	if (mod_len <= 0 || pub_len <= 0 || priv_len <= 0)
		return X509_INVALID_PRIV_KEY;

#ifdef CONFIG_BIGINT_CRT
	p_len = asn1_get_int(buf, &offset, &p);
	q_len = asn1_get_int(buf, &offset, &q);
	dP_len = asn1_get_int(buf, &offset, &dP);
	dQ_len = asn1_get_int(buf, &offset, &dQ);
	qInv_len = asn1_get_int(buf, &offset, &qInv);

	if (p_len <= 0 || q_len <= 0 || dP_len <= 0 || dQ_len <= 0 || qInv_len <= 0)
		return X509_INVALID_PRIV_KEY;

	RSA_priv_key_new(rsa_ctx, 
		modulus, mod_len, pub_exp, pub_len, priv_exp, priv_len,
		p, p_len, q, p_len, dP, dP_len, dQ, dQ_len, qInv, qInv_len);

	free(p);
	free(q);
	free(dP);
	free(dQ);
	free(qInv);
#else
	RSA_priv_key_new(rsa_ctx, modulus, mod_len, pub_exp, pub_len, priv_exp, priv_len);
#endif

	free(modulus);
	free(priv_exp);
	free(pub_exp);
	return X509_OK;
}

/* Get the time of a certificate. Ignore hours/minutes/seconds */
static int asn1_get_utc_time(const uint8_t *buf, int *offset, time_t *t)
{
	int ret = X509_NOT_OK, len, t_offset, abs_year;
	struct tm tm;

	/* see rfc5280#section-4.1.2.5 */
	if (buf[*offset] == ASN1_UTC_TIME)
	{
		(*offset)++;

		len = get_asn1_length(buf, offset);
		t_offset = *offset;

		memset(&tm, 0, sizeof(struct tm));
		tm.tm_year = (buf[t_offset] - '0')*10 + (buf[t_offset+1] - '0');

		if (tm.tm_year <= 50)    /* 1951-2050 thing */
		{
			tm.tm_year += 100;
		}

		tm.tm_mon = (buf[t_offset+2] - '0')*10 + (buf[t_offset+3] - '0') - 1;
		tm.tm_mday = (buf[t_offset+4] - '0')*10 + (buf[t_offset+5] - '0');
		*t = mktime(&tm);
		*offset += len;
		ret = X509_OK;
	}
	else if (buf[*offset] == ASN1_GENERALIZED_TIME)
	{
		(*offset)++;

		len = get_asn1_length(buf, offset);
		t_offset = *offset;

		memset(&tm, 0, sizeof(struct tm));
		abs_year = ((buf[t_offset] - '0')*1000 + (buf[t_offset+1] - '0')*100 + (buf[t_offset+2] - '0')*10 + (buf[t_offset+3] - '0'));

		if (abs_year <= 1901)
		{
			tm.tm_year = 1;
			tm.tm_mon = 0;
			tm.tm_mday = 1;
		}
		else
		{
			tm.tm_year = abs_year - 1900;
			tm.tm_mon = (buf[t_offset+4] - '0')*10 + (buf[t_offset+5] - '0') - 1;
			tm.tm_mday = (buf[t_offset+6] - '0')*10 + (buf[t_offset+7] - '0');
			tm.tm_hour = (buf[t_offset+8] - '0')*10 + (buf[t_offset+9] - '0');
			tm.tm_min = (buf[t_offset+10] - '0')*10 + (buf[t_offset+11] - '0');
			tm.tm_sec = (buf[t_offset+12] - '0')*10 + (buf[t_offset+13] - '0');
			*t = mktime(&tm);
		}

		*offset += len;
		ret = X509_OK;
	}

	return ret;
}

/* Get the version type of a certificate (which we don't actually care about) */
int asn1_version(const uint8_t *buf, int *offset, X509 *x509_ctx)
{
	int ret = X509_NOT_OK;
	
	(*offset) += 2;/* get past explicit tag "0xa0 03", 0xa1 is the tag of explicit type, 0x is the length of sub-type */
#if 1
	if((ret =asn1_next_obj(buf, offset, ASN1_INTEGER) )<0)
		goto end_version;
	if(ret != 1)
	{
		ret = X509_NOT_OK;
		goto end_version;
	}
	x509_ctx->version = buf[*offset]+1;
	AX_DEBUG("VERSION: V%d\n", x509_ctx->version);
	(*offset) += ret;
#else	
	if (asn1_skip_obj(buf, offset, ASN1_INTEGER))
		goto end_version;
#endif

	ret = X509_OK;
end_version:
	return ret;
}

int asn1_serial_number(const uint8_t *buf, int *offset, X509 *_x509)
{
	int len;

	if ((len = asn1_next_obj(buf, offset, ASN1_INTEGER)) < 0)
		goto end_int_array;

	if (len > 1 && buf[*offset] == 0x00)/* ignore the negative byte : compatible with the output of openssl */
	{
		len--;
		(*offset)++;
	}
	
	AX_DEBUG("length of serial number :%d\n", len);
	_x509->serialLength = len;
	memcpy(_x509->serialNumber, buf+*offset, len);

	*offset += len;

end_int_array:
	return len;
}

/**
 * Retrieve the notbefore and notafter certificate times.
 */
int asn1_validity(const uint8_t *buf, int *offset, X509 *x509_ctx)
{
    return (asn1_next_obj(buf, offset, ASN1_SEQUENCE) < 0 ||
              asn1_get_utc_time(buf, offset, &x509_ctx->not_before) ||
              asn1_get_utc_time(buf, offset, &x509_ctx->not_after));
}

/**
 * Get the components of a distinguished name 
 */
static int asn1_get_oid_x520(const uint8_t *buf, int *offset)
{
	int dn_type = 0;
	int len;

	if ((len = asn1_next_obj(buf, offset, ASN1_OID)) < 0)
		goto end_oid;

	/* expect a sequence of 2.5.4.[x] where x is a one of distinguished name 
	components we are interested in. */
	if (len == 3 && buf[(*offset)++] == 0x55 && buf[(*offset)++] == 0x04)
		dn_type = buf[(*offset)++];
	else
	{
		*offset += len;     /* skip over it */
	}

end_oid:
	return dn_type;
}

/**
 * Obtain an ASN.1 printable string type.
 */
static int asn1_get_printable_str(const uint8_t *buf, int *offset, char **str)
{
	int len = X509_NOT_OK;
	int asn1_type = buf[*offset];

	/* some certs have this awful crud in them for some reason */
	if (asn1_type != ASN1_PRINTABLE_STR &&  
		asn1_type != ASN1_PRINTABLE_STR2 &&  
		asn1_type != ASN1_TELETEX_STR &&  
		asn1_type != ASN1_IA5_STR &&  
		asn1_type != ASN1_UNICODE_STR)
		goto end_pnt_str;

	(*offset)++;
	len = get_asn1_length(buf, offset);

	AX_DEBUG("Type of printable string is :%d; length :%d\n", asn1_type, len);
	if (asn1_type == ASN1_UNICODE_STR)
	{
		int i;
		*str = (char *)malloc(len/2+1);     /* allow for null */

		for (i = 0; i < len; i += 2)
			(*str)[i/2] = buf[*offset + i + 1];

		(*str)[len/2] = 0;                  /* null terminate */
	}
	else
	{
		*str = (char *)malloc(len+1);       /* allow for null */
		memcpy(*str, &buf[*offset], len);
		(*str)[len] = 0;                    /* null terminate */
	}

	*offset += len;

end_pnt_str:
	return len;
}

/* Get the subject name (or the issuer) of a certificate. RFC5280#sec.4.1.2.4 */
int asn1_name(const uint8_t *buf, int *offset, char *dn[])
{
	int ret = X509_NOT_OK;
	int dn_type;
	char *tmp;
	int len;
	int index = 0;

	if((len=asn1_next_obj(buf, offset, ASN1_SEQUENCE)) < 0)/* RelativeDistinguishedName: RDNSequence */
		goto end_name;

	AX_DEBUG("RDNSequence length:%d\n", len);
	while ( (len=asn1_next_obj(buf, offset, ASN1_SET)) >= 0)
	{
		int i, found = 0;
		
		
		AX_DEBUG("No. %d AttributeTypeAndValue SET length:%d\n", ++index, len);
		if( (len =asn1_next_obj(buf, offset, ASN1_SEQUENCE)) < 0 || (dn_type = asn1_get_oid_x520(buf, offset)) < 0)
			goto end_name;

		tmp = NULL;

		if (asn1_get_printable_str(buf, offset, &tmp) < 0)
		{
			free(tmp);
			goto end_name;
		}
		AX_DEBUG("No. %d AttributeTypeAndValue SEQENCE length :%d: AttributeType Type=%d, value=\"%s\"\n",
			index, len, dn_type, tmp);

		/* find the distinguished named type */
		for (i = 0; i < X509_NUM_DN_TYPES; i++)
		{
			if (dn_type == g_dn_types[i])
			{
				if (dn[i] == NULL)
				{
					dn[i] = tmp;
					found = 1;
					break;
				}
			}
		}

		if (found == 0) /* not found so get rid of it */
		{
			free(tmp);
		}
	}

	ret = X509_OK;
end_name:
	return ret;
}

/*
* The OID rsaEncryption identifies RSA public keys.
*    pkcs-1 OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 1 }
*      rsaEncryption OBJECT IDENTIFIER ::=  { pkcs-1 1}
*   0x2a(1*40+2), 0x86, 0x48, 0x86, 0xf7, 0x0d 
* refer to RFC3279#2.3.1
*/
/**
 * Read the modulus and public exponent of a certificate.
 */
int asn1_public_key(const uint8_t *buf, int *offset, X509 *x509_ctx)
{
	int ret = X509_NOT_OK, mod_len, pub_len;
	uint8_t *modulus = NULL, *pub_exp = NULL;
#if 0
	if (asn1_next_obj(buf, offset, ASN1_SEQUENCE) < 0 ||
		asn1_skip_obj(buf, offset, ASN1_SEQUENCE) ||
		asn1_next_obj(buf, offset, ASN1_BIT_STRING) < 0)
		goto end_pub_key;
#else
	int len;
	if( (len=asn1_next_obj(buf, offset, ASN1_SEQUENCE)) <0 )
	{
		goto end_pub_key;
	}
	
	if( (len=asn1_next_obj(buf, offset, ASN1_SEQUENCE)) <0 )
		goto end_pub_key;

	if ( (len = asn1_next_obj(buf, offset, ASN1_OID)) < 0)
		goto end_pub_key;
	
	if(memcmp(buf+*offset, sig_oid_prefix, sizeof(sig_oid_prefix)))
	{
		print_blob(buf+*offset, sizeof(sig_oid_prefix), "Error: Not RSA OID");
		goto end_pub_key;
	}
	*offset = *offset+sizeof(sig_oid_prefix);
	if( buf[*offset] != 1) /* RSA encryption*/
	{
		AX_DEBUG("Error: This cert is not RSA encryption(%d)\n", buf[*offset]);
		goto end_pub_key;
	}
	(*offset)++;

#if 1	
	if(asn1_skip_obj(buf, offset, ASN1_NULL) < 0)
	{
		AX_DEBUG("Error: No NULL object\n");
		goto end_pub_key;
	}
#else
	*offset = *offset+2;
#endif

	if( (len = asn1_next_obj(buf, offset, ASN1_BIT_STRING)) < 0)
	{
		AX_DEBUG("Error: Not a BIT_STRING(%d)\n", len);
		goto end_pub_key;
	}
	
#endif
	(*offset)++;        /* ignore the padding bit field */

	if (asn1_next_obj(buf, offset, ASN1_SEQUENCE) < 0)
		goto end_pub_key;

	mod_len = asn1_get_int(buf, offset, &modulus);
	pub_len = asn1_get_int(buf, offset, &pub_exp);
	AX_DEBUG("length :%d; modulo length :%d; exponentiation length:%d\n", len, mod_len, pub_len);

	RSA_pub_key_new(&x509_ctx->rsa_ctx, modulus, mod_len, pub_exp, pub_len);

	free(modulus);
	free(pub_exp);
	ret = X509_OK;

end_pub_key:
	return ret;
}

#ifdef CONFIG_SSL_CERT_VERIFICATION
/**
 * Read the signature of the certificate.
 */
int asn1_signature(const uint8_t *buf, int *offset, X509 *x509_ctx)
{
	int ret = X509_NOT_OK;

	if (buf[(*offset)++] != ASN1_BIT_STRING)
		goto end_sig;

	x509_ctx->sig_len = get_asn1_length(buf, offset)-1;
	(*offset)++;            /* ignore bit string padding bits */
	x509_ctx->signature = (uint8_t *)malloc(x509_ctx->sig_len);
	memcpy(x509_ctx->signature, &buf[*offset], x509_ctx->sig_len);
	*offset += x509_ctx->sig_len;
	ret = X509_OK;

end_sig:
	return ret;
}

/*
 * Compare 2 distinguished name components for equality 
 * @return 0 if a match
 */
static int asn1_compare_dn_comp(const char *dn1, const char *dn2)
{
    int ret;

    if (dn1 == NULL && dn2 == NULL)
        ret = 0;
    else
        ret = (dn1 && dn2) ? strcmp(dn1, dn2) : 1;

    return ret;
}

/**
 * Clean up all of the CA certificates.
 */
void remove_ca_certs(CA_CERT *ca_cert_ctx)
{
    int i = 0;

    if (ca_cert_ctx == NULL)
        return;

    while (i < CONFIG_X509_MAX_CA_CERTS && ca_cert_ctx->cert[i])
    {
        x509_free(ca_cert_ctx->cert[i]);
        ca_cert_ctx->cert[i++] = NULL;
    }

    free(ca_cert_ctx);
}

/*
 * Compare 2 distinguished names for equality 
 * @return 0 if a match
 */
int asn1_compare_dn(char * const dn1[], char * const dn2[])
{
    int i;

    for (i = 0; i < X509_NUM_DN_TYPES; i++)
    {
        if (asn1_compare_dn_comp(dn1[i], dn2[i]))
            return 1;
    }

    return 0;       /* all good */
}

int asn1_find_oid(const uint8_t* buf, int* offset, const uint8_t* oid, int oid_length)
{
    int seqlen;
    if ((seqlen = asn1_next_obj(buf, offset, ASN1_SEQUENCE))> 0)
    {
        int end = *offset + seqlen;

        while (*offset < end)
        {
            int type = buf[(*offset)++];
            int length = get_asn1_length(buf, offset);
            int noffset = *offset + length;

            if (type == ASN1_SEQUENCE)
            {
                type = buf[(*offset)++];
                length = get_asn1_length(buf, offset);

                if (type == ASN1_OID && length == oid_length && memcmp(buf + *offset, oid, oid_length) == 0)
                {
                    *offset += oid_length;
                    return 1;
                }
            }

            *offset = noffset;
        }
    }

    return 0;
}

int asn1_find_subjectaltname(const uint8_t* buf, int offset)
{
	if (asn1_find_oid(buf, &offset, sig_subject_alt_name, sizeof(sig_subject_alt_name)))
	{
		return offset;
	}

	return 0;
}

#endif /* CONFIG_SSL_CERT_VERIFICATION */

/**
 * Read the signature type of the certificate. We only support RSA-MD5 and RSA-SHA1 signature types.
 * refer to section 4.1.1.2 of RFC5280 
 */
int asn1_signature_type(const uint8_t *buf, int *offset, X509 *_x509)
{
	int ret = X509_NOT_OK, len;

	if ( (len = asn1_next_obj(buf, offset, ASN1_SEQUENCE)) < 0)
		goto end_check_sig;

	AX_DEBUG("SignatureType length :%d\n", len);

#if 0	
	if (buf[(*offset)++] != ASN1_OID)
		goto end_check_sig;
	len = get_asn1_length(buf, offset);
#else
	if ( (len = asn1_next_obj(buf, offset, ASN1_OID)) < 0)
		goto end_check_sig;
#endif
	print_blob(buf+*offset, len, "SignatureType OID length :%d", len);

	if (len == sizeof(sig_sha1WithRSAEncrypt) && memcmp(sig_sha1WithRSAEncrypt, &buf[*offset], sizeof(sig_sha1WithRSAEncrypt)) == 0)
	{
		_x509->sig_type = SIG_TYPE_SHA1;
		AX_DEBUG("SIGN: SHA1\n");
	}
	else if (len == sizeof(sig_sha256) && memcmp(sig_sha256, &buf[*offset], sizeof(sig_sha256)) == 0)
	{
		_x509->sig_type = SIG_TYPE_SHA256;
		AX_DEBUG("SIGN: SHA256\n");
	}
	else if (len == sizeof(sig_sha384) && memcmp(sig_sha384, &buf[*offset], sizeof(sig_sha384)) == 0)
	{
		_x509->sig_type = SIG_TYPE_SHA384;
		AX_DEBUG("SIGN: SHA384\n");
	}
	else if (len == sizeof(sig_sha512) && memcmp(sig_sha512, &buf[*offset], sizeof(sig_sha512)) == 0)
	{
		_x509->sig_type = SIG_TYPE_SHA512;
		AX_DEBUG("SIGN: SHA512\n");
	}
	else
	{
		if (memcmp(sig_oid_prefix, &buf[*offset], sizeof(sig_oid_prefix)))
		{
#ifdef CONFIG_SSL_FULL_MODE
			int i;
			printf("invalid digest: ");

			for (i = 0; i < len; i++)
				printf("%02x ", buf[*offset + i]);

			printf("\n");
#endif
			goto end_check_sig;     /* unrecognised cert type */
		}

		_x509->sig_type = buf[*offset + sizeof(sig_oid_prefix)];
		AX_DEBUG("SIGN: 0x%x\n", _x509->sig_type);
	}

	*offset += len;
	asn1_skip_obj(buf, offset, ASN1_NULL); /* if it's there */
	ret = X509_OK;

end_check_sig:
	return ret;
}

