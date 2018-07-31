/**
 * Certificate processing.
 */

#include "tls.h"

#ifdef CONFIG_SSL_CERT_VERIFICATION
/**
 * Retrieve the signature from a certificate.
 */
static const uint8_t *get_signature(const uint8_t *asn1_sig, int *len)
{
	int offset = 0;
	const uint8_t *ptr = NULL;

	if (asn1_next_obj(asn1_sig, &offset, ASN1_SEQUENCE) < 0 || asn1_skip_obj(asn1_sig, &offset, ASN1_SEQUENCE))
		goto end_get_sig;

	if (asn1_sig[offset++] != ASN1_OCTET_STRING)
		goto end_get_sig;
	*len = get_asn1_length(asn1_sig, &offset);
	ptr = &asn1_sig[offset];          /* all ok */

end_get_sig:
	return ptr;
}

#endif

/**
 * Construct a new x509 object.
 * @return 0 if ok. < 0 if there was a problem.
 */
EXP_FUNC int STDCALL x509_new(const uint8_t *buf, int *len, X509 **ctx)
{
	int begin_tbs, end_tbs;
	int ret = X509_NOT_OK, offset = 0, cert_size = 0;
	X509 *x509_ctx;
	BI_CTX *bi_ctx;

	*ctx = (X509 *)calloc(1, sizeof(X509));
	x509_ctx = *ctx;

//TRACE();
	/* get the certificate size */
	asn1_skip_obj(buf, &cert_size, ASN1_SEQUENCE); 

	if (asn1_next_obj(buf, &offset, ASN1_SEQUENCE) < 0)
		goto end_cert;

	AX_DEBUG("size : %d; offset : %d\n", cert_size, offset);
	
	begin_tbs = offset;         /* start of the tbs */
	end_tbs = begin_tbs;        /* work out the end of the tbs */
	asn1_skip_obj(buf, &end_tbs, ASN1_SEQUENCE);

	if (asn1_next_obj(buf, &offset, ASN1_SEQUENCE) < 0)
		goto end_cert;

	AX_DEBUG("end_tbs : %d; offset : %d\n", end_tbs, offset);
	
	if (buf[offset] == ASN1_EXPLICIT_TAG)   /* optional version */
	{
		if (asn1_version(buf, &offset, x509_ctx))
			goto end_cert;
	}
	
	/* serial number */ 
#if 0	
	if (asn1_skip_obj(cert, &offset, ASN1_INTEGER) || asn1_next_obj(cert, &offset, ASN1_SEQUENCE) < 0)
#else
	if( (asn1_serial_number(buf, &offset, x509_ctx)<0) )
#endif
		goto end_cert;

	/* make sure the signature is ok */
	if (asn1_signature_type(buf, &offset, x509_ctx))
	{
		ret = X509_VFY_ERROR_UNSUPPORTED_DIGEST;
		goto end_cert;
	}

	if (asn1_name(buf, &offset, x509_ctx->caDn) || 
		asn1_validity(buf, &offset, x509_ctx) ||
		asn1_name(buf, &offset, x509_ctx->dn) ||
		asn1_public_key(buf, &offset, x509_ctx))
	{
		goto end_cert;
	}

//TRACE();
	bi_ctx = x509_ctx->rsa_ctx->bi_ctx;

#ifdef CONFIG_SSL_CERT_VERIFICATION /* only care if doing verification */
	/* use the appropriate signature algorithm */
	switch (x509_ctx->sig_type)
	{
		case SIG_TYPE_MD5:
		{
			MD5_CTX md5_ctx;
			uint8_t md5_dgst[HASH_MD_LENGTH_MD5];
			MD5_Init(&md5_ctx);
			MD5_Update(&md5_ctx, &buf[begin_tbs], end_tbs-begin_tbs);
			MD5_Final(md5_dgst, &md5_ctx);
			x509_ctx->digest = bi_import(bi_ctx, md5_dgst, HASH_MD_LENGTH_MD5);
		}
		break;

		case SIG_TYPE_SHA1:
		{
			SHA1_CTX sha_ctx;
			uint8_t sha_dgst[HASH_MD_LENGTH_SHA1];
			SHA1_Init(&sha_ctx);
			SHA1_Update(&sha_ctx, &buf[begin_tbs], end_tbs-begin_tbs);
			SHA1_Final(sha_dgst, &sha_ctx);
			x509_ctx->digest = bi_import(bi_ctx, sha_dgst, HASH_MD_LENGTH_SHA1);
		}
		break;

		case SIG_TYPE_SHA256:
		{
			SHA256_CTX sha256_ctx;
			uint8_t sha256_dgst[HASH_MD_LENGTH_SHA256];
			SHA256_Init(&sha256_ctx);
			SHA256_Update(&sha256_ctx, &buf[begin_tbs], end_tbs-begin_tbs);
			SHA256_Final(sha256_dgst, &sha256_ctx);
			x509_ctx->digest = bi_import(bi_ctx, sha256_dgst, HASH_MD_LENGTH_SHA256);
		}
		break;

		case SIG_TYPE_SHA384:
		{
			SHA384_CTX sha384_ctx;
			uint8_t sha384_dgst[HASH_MD_LENGTH_SHA384];
			SHA384_Init(&sha384_ctx);
			SHA384_Update(&sha384_ctx, &buf[begin_tbs], end_tbs-begin_tbs);
			SHA384_Final(sha384_dgst, &sha384_ctx);
			x509_ctx->digest = bi_import(bi_ctx, sha384_dgst, HASH_MD_LENGTH_SHA384);
		}
		break;

		case SIG_TYPE_SHA512:
		{
			SHA512_CTX sha512_ctx;
			uint8_t sha512_dgst[HASH_MD_LENGTH_SHA512];
			SHA512_Init(&sha512_ctx);
			SHA512_Update(&sha512_ctx, &buf[begin_tbs], end_tbs-begin_tbs);
			SHA512_Final(sha512_dgst, &sha512_ctx);
			x509_ctx->digest = bi_import(bi_ctx, sha512_dgst, HASH_MD_LENGTH_SHA512);
		}
		break;
	}

	if (buf[offset] == ASN1_V3_DATA)
	{/* cert extension */
		int suboffset;

		++offset;
		ret = get_asn1_length(buf, &offset);
		AX_DEBUG("V3_DATA length:%d at offset 0x%2x\n", ret, offset);

		if ((suboffset = asn1_find_subjectaltname(buf, offset)) > 0)
		{
			AX_DEBUG("found subject ALT name: %d\n", suboffset);
			if ( (ret = asn1_next_obj(buf, &suboffset, ASN1_OCTET_STRING) )> 0)
			{
				int altlen;

				AX_DEBUG("Octet string length : %d\n", ret);
				if ((altlen = asn1_next_obj(buf, &suboffset, ASN1_SEQUENCE)) > 0)
				{
					int endalt = suboffset + altlen;
					int totalnames = 0;

					while (suboffset < endalt)
					{
						int type = buf[suboffset++];
						int dnslen = get_asn1_length(buf, &suboffset);

						if (type == ASN1_CONTEXT_DNSNAME)
						{
							x509_ctx->subject_alt_dnsnames = (char**)realloc(x509_ctx->subject_alt_dnsnames, (totalnames + 2) * sizeof(char*));
							x509_ctx->subject_alt_dnsnames[totalnames] = (char*)malloc(dnslen + 1);
							x509_ctx->subject_alt_dnsnames[totalnames+1] = NULL;
							memcpy(x509_ctx->subject_alt_dnsnames[totalnames], buf + suboffset, dnslen);
							x509_ctx->subject_alt_dnsnames[totalnames][dnslen] = 0;
							AX_DEBUG("ALT name:%s\n", x509_ctx->subject_alt_dnsnames[totalnames]);
							++totalnames;
						}
						else
						{
							AX_DEBUG("type=%d\n", type);
						}

						suboffset += dnslen;
					}
				}
			}
		}
	}

	offset = end_tbs;   /* skip the rest of v3 data */
	if (asn1_skip_obj(buf, &offset, ASN1_SEQUENCE) || asn1_signature(buf, &offset, x509_ctx))
		goto end_cert;
#endif

	ret = X509_OK;
end_cert:
	if (len)
	{
		*len = cert_size;
	}

	if (ret)
	{
#ifdef CONFIG_SSL_FULL_MODE
		AX_LOG("Error: Invalid X509 ASN.1 file (%s)\n", x509_display_error(ret));
#endif
		x509_free(x509_ctx);
		*ctx = NULL;
	}

	return ret;
}

/**
 * Free an X.509 object's resources.
 */
EXP_FUNC void STDCALL x509_free(X509 *x509_ctx)
{
	X509 *next;
	int i;

	if (x509_ctx == NULL)       /* if already null, then don't bother */
		return;

	for (i = 0; i < X509_NUM_DN_TYPES; i++)
	{
		free(x509_ctx->caDn[i]);
		free(x509_ctx->dn[i]);
	}

	free(x509_ctx->signature);

#ifdef CONFIG_SSL_CERT_VERIFICATION 
	if (x509_ctx->digest)
	{
		bi_free(x509_ctx->rsa_ctx->bi_ctx, x509_ctx->digest);
	}

	if (x509_ctx->subject_alt_dnsnames)
	{
		for (i = 0; x509_ctx->subject_alt_dnsnames[i]; ++i)
			free(x509_ctx->subject_alt_dnsnames[i]);

		free(x509_ctx->subject_alt_dnsnames);
	}
#endif

	RSA_free(x509_ctx->rsa_ctx);
	next = x509_ctx->next;
	free(x509_ctx);
	x509_free(next);        /* clear the chain */
}

#ifdef CONFIG_SSL_CERT_VERIFICATION
/**
 * Take a signature and decrypt it.
 */
static bigint *sig_verify(BI_CTX *ctx, const uint8_t *sig, int sig_len, bigint *modulus, bigint *pub_exp)
{
    int i, size;
    bigint *decrypted_bi, *dat_bi;
    bigint *bir = NULL;
    uint8_t *block = (uint8_t *)alloca(sig_len);

    /* decrypt */
    dat_bi = bi_import(ctx, sig, sig_len);
    ctx->mod_offset = BIGINT_M_OFFSET;

    /* convert to a normal block */
    decrypted_bi = bi_mod_power2(ctx, dat_bi, modulus, pub_exp);

    bi_export(ctx, decrypted_bi, block, sig_len);
    ctx->mod_offset = BIGINT_M_OFFSET;

    i = 10; /* start at the first possible non-padded byte */
    while (block[i++] && i < sig_len);
    size = sig_len - i;

    /* get only the bit we want */
    if (size > 0)
    {
        int len;
        const uint8_t *sig_ptr = get_signature(&block[i], &len);

        if (sig_ptr)
        {
            bir = bi_import(ctx, sig_ptr, len);
        }
    }

    /* save a few bytes of memory */
    bi_clear_cache(ctx);
    return bir;
}

/**
 * Do some basic checks on the certificate chain.
 *
 * Certificate verification consists of a number of checks:
 * - The date of the certificate is after the start date.
 * - The date of the certificate is before the finish date.
 * - A root certificate exists in the certificate store.
 * - That the certificate(s) are not self-signed.
 * - The certificate chain is valid.
 * - The signature of the certificate is valid.
 */
EXP_FUNC int STDCALL x509_verify(const CA_CERT *ca_cert_ctx, const X509 *cert) 
{
    int ret = X509_OK, i = 0;
    bigint *cert_sig;
    X509 *next_cert = NULL;
    BI_CTX *ctx = NULL;
    bigint *mod = NULL, *expn = NULL;
    int match_ca_cert = 0;
    struct timeval tv;
    uint8_t is_self_signed = 0;

    if (cert == NULL)
    {
        ret = X509_VFY_ERROR_NO_TRUSTED_CERT;       
        goto end_verify;
    }

    /* a self-signed certificate that is not in the CA store - use this  to check the signature */
    if (asn1_compare_dn(cert->caDn, cert->dn) == 0)
    {
        is_self_signed = 1;
        ctx = cert->rsa_ctx->bi_ctx;
        mod = cert->rsa_ctx->m;
        expn = cert->rsa_ctx->e;
    }

    gettimeofday(&tv, NULL);

    /* check the not before date */
    if (tv.tv_sec < cert->not_before)
    {
        ret = X509_VFY_ERROR_NOT_YET_VALID;
        goto end_verify;
    }

    /* check the not after date */
    if (tv.tv_sec > cert->not_after)
    {
        ret = X509_VFY_ERROR_EXPIRED;
        goto end_verify;
    }

    next_cert = cert->next;

    /* last cert in the chain - look for a trusted cert */
    if (next_cert == NULL)
    {
       if (ca_cert_ctx != NULL) 
       {
            /* go thu the CA store */
            while (i < CONFIG_X509_MAX_CA_CERTS && ca_cert_ctx->cert[i])
            {
                if (asn1_compare_dn(cert->caDn, ca_cert_ctx->cert[i]->dn) == 0)
                {
                    /* use this CA certificate for signature verification */
                    match_ca_cert = 1;
                    ctx = ca_cert_ctx->cert[i]->rsa_ctx->bi_ctx;
                    mod = ca_cert_ctx->cert[i]->rsa_ctx->m;
                    expn = ca_cert_ctx->cert[i]->rsa_ctx->e;
                    break;
                }

                i++;
            }
        }

        /* couldn't find a trusted cert (& let self-signed errors 
           be returned) */
        if (!match_ca_cert && !is_self_signed)
        {
            ret = X509_VFY_ERROR_NO_TRUSTED_CERT;       
            goto end_verify;
        }
    }
    else if (asn1_compare_dn(cert->caDn, next_cert->dn) != 0)
    {
        /* check the chain */
        ret = X509_VFY_ERROR_INVALID_CHAIN;
        goto end_verify;
    }
    else /* use the next certificate in the chain for signature verify */
    {
        ctx = next_cert->rsa_ctx->bi_ctx;
        mod = next_cert->rsa_ctx->m;
        expn = next_cert->rsa_ctx->e;
    }

    /* cert is self signed */
    if (!match_ca_cert && is_self_signed)
    {
        ret = X509_VFY_ERROR_SELF_SIGNED;
        goto end_verify;
    }

    /* check the signature */
    cert_sig = sig_verify(ctx, cert->signature, cert->sig_len, bi_clone(ctx, mod), bi_clone(ctx, expn));

    if (cert_sig && cert->digest)
    {
        if (bi_compare(cert_sig, cert->digest) != 0)
            ret = X509_VFY_ERROR_BAD_SIGNATURE;


        bi_free(ctx, cert_sig);
    }
    else
    {
        ret = X509_VFY_ERROR_BAD_SIGNATURE;
    }

    if (ret)
        goto end_verify;

    /* go down the certificate chain using recursion. */
    if (next_cert != NULL)
    {
        ret = x509_verify(ca_cert_ctx, next_cert);
    }

end_verify:
    return ret;
}
#endif

#if defined (CONFIG_SSL_FULL_MODE)
/**
 * Used for diagnostics.
 */
static const char *not_part_of_cert = "<Not Part Of Certificate>";
EXP_FUNC void STDCALL x509_print(const X509 *cert, CA_CERT *ca_cert_ctx) 
{
	if (cert == NULL)
		return;

	print_blob(cert->serialNumber, cert->serialLength, "Version: V%d; \tSerialNumber:", cert->version);
	printf("=== CERTIFICATE ISSUED TO ===\n");
	printf("Common Name (CN):\t\t");
	printf("%s\n", cert->dn[X509_COMMON_NAME] ? cert->dn[X509_COMMON_NAME] : not_part_of_cert);

	printf("Organization (O):\t\t");
	printf("%s\n", cert->dn[X509_ORGANIZATION] ?cert->dn[X509_ORGANIZATION] : not_part_of_cert);

	printf("Organizational Unit (OU):\t");
	printf("%s\n", cert->dn[X509_ORGANIZATIONAL_UNIT] ? cert->dn[X509_ORGANIZATIONAL_UNIT] : not_part_of_cert);

	printf("=== CERTIFICATE ISSUED BY ===\n");
	printf("Common Name (CN):\t\t");
	printf("%s\n", cert->caDn[X509_COMMON_NAME] ? cert->caDn[X509_COMMON_NAME] : not_part_of_cert);

	printf("Organization (O):\t\t");
	printf("%s\n", cert->caDn[X509_ORGANIZATION] ? cert->caDn[X509_ORGANIZATION] : not_part_of_cert);

	printf("Organizational Unit (OU):\t");
	printf("%s\n", cert->caDn[X509_ORGANIZATIONAL_UNIT] ? cert->caDn[X509_ORGANIZATIONAL_UNIT] : not_part_of_cert);

	printf("Not Before:\t\t\t%s", ctime(&cert->not_before));
	printf("Not After:\t\t\t%s", ctime(&cert->not_after));
	printf("RSA bitsize:\t\t\t%d\n", cert->rsa_ctx->num_octets*8);
	printf("Sig Type:\t\t\t");
	switch (cert->sig_type)
	{
		case SIG_TYPE_MD2:
			printf("MD2\n");
			break;
		case SIG_TYPE_MD5:
			printf("MD5\n");
			break;
		case SIG_TYPE_SHA1:
			printf("SHA1\n");
			break;
		case SIG_TYPE_SHA256:
			printf("SHA256\n");
			break;
		case SIG_TYPE_SHA384:
			printf("SHA384\n");
			break;
		case SIG_TYPE_SHA512:
			printf("SHA512\n");
			break;
		default:
			printf("Unrecognized: %d\n", cert->sig_type);
			break;
	}

	if (ca_cert_ctx)
	{
		printf("Verify:\t\t\t\t%s\n", x509_display_error(x509_verify(ca_cert_ctx, cert)));
	}

#if 1
	{
		bi_print("digest", cert->digest);
		
		print_blob(cert->signature, cert->sig_len, "Signature");
		bi_print("Modulus", cert->rsa_ctx->m);
		bi_print("Pub Exp", cert->rsa_ctx->e);
	}
#endif

	if (ca_cert_ctx)
	{
		x509_print(cert->next, ca_cert_ctx);
	}

	TTY_FLUSH();
}

EXP_FUNC const char* STDCALL x509_display_error(int error)
{
    switch (error)
    {
        case X509_OK:
            return "Certificate verify successful";

        case X509_NOT_OK:
            return "X509 not ok";

        case X509_VFY_ERROR_NO_TRUSTED_CERT:
            return "No trusted cert is available";

        case X509_VFY_ERROR_BAD_SIGNATURE:
            return "Bad signature";

        case X509_VFY_ERROR_NOT_YET_VALID:
            return "Cert is not yet valid";

        case X509_VFY_ERROR_EXPIRED:
            return "Cert has expired";

        case X509_VFY_ERROR_SELF_SIGNED:
            return "Cert is self-signed";

        case X509_VFY_ERROR_INVALID_CHAIN:
            return "Chain is invalid (check order of certs)";

        case X509_VFY_ERROR_UNSUPPORTED_DIGEST:
            return "Unsupported digest";

        case X509_INVALID_PRIV_KEY:
            return "Invalid private key";

        default:
            return "Unknown";
    }
}
#endif      /* CONFIG_SSL_FULL_MODE */

