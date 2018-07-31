/*
* called in DecodeCert.c  
*/

#include "cmnCrypto.h"

/* update altName field in DecodedCert */
static int _decodeAltNames(byte* input, int sz, DecodedCert* cert)
{
	word32 idx = 0;
	int length = 0;

	WOLFSSL_ENTER();

	if (GetSequence(input, &idx, &length, sz) < 0) {
		WOLFSSL_MSG("\tBad Sequence");
		return ASN_PARSE_E;
	}

	cert->weOwnAltNames = 1;

	while (length > 0)
	{
		byte       b = input[idx++];

		length--;

		/* Save DNS Type names in the altNames list. */
		/* Save Other Type names in the cert's OidMap */
		if (b == (ASN_CONTEXT_SPECIFIC | ASN_DNS_TYPE))
		{
			DNS_entry* dnsEntry;
			int strLen;
			word32 lenStartIdx = idx;

			if (GetLength(input, &idx, &strLen, sz) < 0) {
				WOLFSSL_MSG("\tfail: str length");
				return ASN_PARSE_E;
			}
			length -= (idx - lenStartIdx);

			dnsEntry = (DNS_entry*)XMALLOC(sizeof(DNS_entry), cert->heap, DYNAMIC_TYPE_ALTNAME);
			if (dnsEntry == NULL) {
				WOLFSSL_MSG("\tOut of Memory");
				return ASN_PARSE_E;
			}

			dnsEntry->name = (char*)XMALLOC(strLen + 1, cert->heap, DYNAMIC_TYPE_ALTNAME);
			if (dnsEntry->name == NULL) {
				WOLFSSL_MSG("\tOut of Memory");
				XFREE(dnsEntry, cert->heap, DYNAMIC_TYPE_ALTNAME);
				return ASN_PARSE_E;
			}

			XMEMCPY(dnsEntry->name, &input[idx], strLen);
			dnsEntry->name[strLen] = '\0';

			dnsEntry->next = cert->altNames;
			cert->altNames = dnsEntry;

			length -= strLen;
			idx    += strLen;
		}
#ifndef IGNORE_NAME_CONSTRAINTS
		else if (b == (ASN_CONTEXT_SPECIFIC | ASN_RFC822_TYPE))
		{
			DNS_entry* emailEntry;
			int strLen;
			word32 lenStartIdx = idx;

			if (GetLength(input, &idx, &strLen, sz) < 0) {
				WOLFSSL_MSG("\tfail: str length");
				return ASN_PARSE_E;
			}
			length -= (idx - lenStartIdx);

			emailEntry = (DNS_entry*)XMALLOC(sizeof(DNS_entry), cert->heap, DYNAMIC_TYPE_ALTNAME);
			if (emailEntry == NULL) {
				WOLFSSL_MSG("\tOut of Memory");
				return ASN_PARSE_E;
			}

			emailEntry->name = (char*)XMALLOC(strLen + 1, cert->heap, DYNAMIC_TYPE_ALTNAME);
			if (emailEntry->name == NULL) {
				WOLFSSL_MSG("\tOut of Memory");
				XFREE(emailEntry, cert->heap, DYNAMIC_TYPE_ALTNAME);
				return ASN_PARSE_E;
			}

			XMEMCPY(emailEntry->name, &input[idx], strLen);
			emailEntry->name[strLen] = '\0';

			emailEntry->next = cert->altEmailNames;
			cert->altEmailNames = emailEntry;

			length -= strLen;
			idx    += strLen;
		}
#endif /* IGNORE_NAME_CONSTRAINTS */
#ifdef WOLFSSL_SEP
		else if (b == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | ASN_OTHER_TYPE))
		{
			int strLen;
			word32 lenStartIdx = idx;
			word32 oid = 0;

			if (GetLength(input, &idx, &strLen, sz) < 0) {
				WOLFSSL_MSG("\tfail: other name length");
				return ASN_PARSE_E;
			}
			/* Consume the rest of this sequence. */
			length -= (strLen + idx - lenStartIdx);

			if (GetObjectId(input, &idx, &oid, sz) < 0) {
				WOLFSSL_MSG("\tbad OID");
				return ASN_PARSE_E;
			}

			if (oid != HW_NAME_OID) {
				WOLFSSL_MSG("\tincorrect OID");
				return ASN_PARSE_E;
			}

			if (input[idx++] != (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED)) {
				WOLFSSL_MSG("\twrong type");
				return ASN_PARSE_E;
			}

			if (GetLength(input, &idx, &strLen, sz) < 0) {
				WOLFSSL_MSG("\tfail: str len");
				return ASN_PARSE_E;
			}

			if (GetSequence(input, &idx, &strLen, sz) < 0) {
				WOLFSSL_MSG("\tBad Sequence");
				return ASN_PARSE_E;
			}

			if (input[idx++] != ASN_OBJECT_ID) {
				WOLFSSL_MSG("\texpected OID");
				return ASN_PARSE_E;
			}

			if (GetLength(input, &idx, &strLen, sz) < 0) {
				WOLFSSL_MSG("\tfailed: str len");
				return ASN_PARSE_E;
			}

			cert->hwType = (byte*)XMALLOC(strLen, cert->heap, 0);
			if (cert->hwType == NULL) {
				WOLFSSL_MSG("\tOut of Memory");
				return MEMORY_E;
			}

			XMEMCPY(cert->hwType, &input[idx], strLen);
			cert->hwTypeSz = strLen;
			idx += strLen;

			if (input[idx++] != ASN_OCTET_STRING) {
				WOLFSSL_MSG("\texpected Octet String");
				return ASN_PARSE_E;
			}

			if (GetLength(input, &idx, &strLen, sz) < 0) {
				WOLFSSL_MSG("\tfailed: str len");
				return ASN_PARSE_E;
			}

			cert->hwSerialNum = (byte*)XMALLOC(strLen + 1, cert->heap, 0);
			if (cert->hwSerialNum == NULL) {
				WOLFSSL_MSG("\tOut of Memory");
				return MEMORY_E;
			}

			XMEMCPY(cert->hwSerialNum, &input[idx], strLen);
			cert->hwSerialNum[strLen] = '\0';
			cert->hwSerialNumSz = strLen;
			idx += strLen;
		}
#endif /* WOLFSSL_SEP */
		else
		{
			int strLen;
			word32 lenStartIdx = idx;

			WOLFSSL_MSG("\tUnsupported name type, skipping");

			if (GetLength(input, &idx, &strLen, sz) < 0) {
				WOLFSSL_MSG("\tfail: unsupported name length");
				return ASN_PARSE_E;
			}
			length -= (strLen + idx - lenStartIdx);
			idx += strLen;
		}
	}
	return 0;
}


static int _decodeBasicCaConstraint(byte* input, int sz, DecodedCert* cert)
{
    word32 idx = 0;
    int length = 0;

    WOLFSSL_ENTER();
    if (GetSequence(input, &idx, &length, sz) < 0) {
        WOLFSSL_MSG("\tfail: bad SEQUENCE");
        return ASN_PARSE_E;
    }

    if (length == 0)
        return 0;

    /* If the basic ca constraint is false, this extension may be named, but
     * left empty. So, if the length is 0, just return. */

    if (input[idx++] != ASN_BOOLEAN)
    {
        WOLFSSL_MSG("\tfail: constraint not BOOLEAN");
        return ASN_PARSE_E;
    }

    if (GetLength(input, &idx, &length, sz) < 0)
    {
        WOLFSSL_MSG("\tfail: length");
        return ASN_PARSE_E;
    }

    if (input[idx++])
        cert->isCA = 1;

    #ifdef OPENSSL_EXTRA
        /* If there isn't any more data, return. */
        if (idx >= (word32)sz)
            return 0;

        /* Anything left should be the optional pathlength */
        if (input[idx++] != ASN_INTEGER) {
            WOLFSSL_MSG("\tfail: pathlen not INTEGER");
            return ASN_PARSE_E;
        }

        if (input[idx++] != 1) {
            WOLFSSL_MSG("\tfail: pathlen too long");
            return ASN_PARSE_E;
        }

        cert->pathLength = input[idx];
        cert->extBasicConstPlSet = 1;
    #endif /* OPENSSL_EXTRA */

    return 0;
}


#define CRLDP_FULL_NAME 0
    /* From RFC3280 SS4.2.1.14, Distribution Point Name*/
#define GENERALNAME_URI 6
    /* From RFC3280 SS4.2.1.7, GeneralName */

static int _decodeCrlDist(byte* input, int sz, DecodedCert* cert)
{
    word32 idx = 0;
    int length = 0;

    WOLFSSL_ENTER();

    /* Unwrap the list of Distribution Points*/
    if (GetSequence(input, &idx, &length, sz) < 0)
        return ASN_PARSE_E;

    /* Unwrap a single Distribution Point */
    if (GetSequence(input, &idx, &length, sz) < 0)
        return ASN_PARSE_E;

    /* The Distribution Point has three explicit optional members
     *  First check for a DistributionPointName
     */
    if (input[idx] == (ASN_CONSTRUCTED | ASN_CONTEXT_SPECIFIC | 0))
    {
        idx++;
        if (GetLength(input, &idx, &length, sz) < 0)
            return ASN_PARSE_E;

        if (input[idx] == 
                    (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | CRLDP_FULL_NAME))
        {
            idx++;
            if (GetLength(input, &idx, &length, sz) < 0)
                return ASN_PARSE_E;

            if (input[idx] == (ASN_CONTEXT_SPECIFIC | GENERALNAME_URI))
            {
                idx++;
                if (GetLength(input, &idx, &length, sz) < 0)
                    return ASN_PARSE_E;

                cert->extCrlInfoSz = length;
                cert->extCrlInfo = input + idx;
                idx += length;
            }
            else
                /* This isn't a URI, skip it. */
                idx += length;
        }
        else
            /* This isn't a FULLNAME, skip it. */
            idx += length;
    }

    /* Check for reasonFlags */
    if (idx < (word32)sz &&
        input[idx] == (ASN_CONSTRUCTED | ASN_CONTEXT_SPECIFIC | 1))
    {
        idx++;
        if (GetLength(input, &idx, &length, sz) < 0)
            return ASN_PARSE_E;
        idx += length;
    }

    /* Check for cRLIssuer */
    if (idx < (word32)sz &&
        input[idx] == (ASN_CONSTRUCTED | ASN_CONTEXT_SPECIFIC | 2))
    {
        idx++;
        if (GetLength(input, &idx, &length, sz) < 0)
            return ASN_PARSE_E;
        idx += length;
    }

    if (idx < (word32)sz)
    {
        WOLFSSL_MSG("\tThere are more CRL Distribution Point records, "
                   "but we only use the first one.");
    }

    return 0;
}


static int _decodeAuthInfo(byte* input, int sz, DecodedCert* cert)
/*
 *  Read the first of the Authority Information Access records. If there are
 *  any issues, return without saving the record.
 */
{
    word32 idx = 0;
    int length = 0;
    byte b;
    word32 oid;

    WOLFSSL_ENTER();

    /* Unwrap the list of AIAs */
    if (GetSequence(input, &idx, &length, sz) < 0)
        return ASN_PARSE_E;

    while (idx < (word32)sz) {
        /* Unwrap a single AIA */
        if (GetSequence(input, &idx, &length, sz) < 0)
            return ASN_PARSE_E;

        oid = 0;
        if (GetObjectId(input, &idx, &oid, sz) < 0)
            return ASN_PARSE_E;

        /* Only supporting URIs right now. */
        b = input[idx++];
        if (GetLength(input, &idx, &length, sz) < 0)
            return ASN_PARSE_E;

        if (b == (ASN_CONTEXT_SPECIFIC | GENERALNAME_URI) &&
            oid == AIA_OCSP_OID)
        {
            cert->extAuthInfoSz = length;
            cert->extAuthInfo = input + idx;
            break;
        }
        idx += length;
    }

    return 0;
}


static int _decodeAuthKeyId(byte* input, int sz, DecodedCert* cert)
{
    word32 idx = 0;
    int length = 0, ret = 0;

    WOLFSSL_ENTER();

    if (GetSequence(input, &idx, &length, sz) < 0) {
        WOLFSSL_MSG("\tfail: should be a SEQUENCE\n");
        return ASN_PARSE_E;
    }

    if (input[idx++] != (ASN_CONTEXT_SPECIFIC | 0)) {
        WOLFSSL_MSG("\tinfo: OPTIONAL item 0, not available\n");
        return 0;
    }

    if (GetLength(input, &idx, &length, sz) < 0) {
        WOLFSSL_MSG("\tfail: extension data length");
        return ASN_PARSE_E;
    }

    #ifdef OPENSSL_EXTRA
        cert->extAuthKeyIdSrc = &input[idx];
        cert->extAuthKeyIdSz = length;
    #endif /* OPENSSL_EXTRA */

    if (length == KEYID_SIZE) {
        XMEMCPY(cert->extAuthKeyId, input + idx, length);
    }
    else {
    #ifdef NO_SHA
        ret = wc_Sha256Hash(input + idx, length, cert->extAuthKeyId);
    #else
        ret = wc_ShaHash(input + idx, length, cert->extAuthKeyId);
    #endif
    }

    return ret;
}


static int _decodeSubjKeyId(byte* input, int sz, DecodedCert* cert)
{
    word32 idx = 0;
    int length = 0, ret = 0;

    WOLFSSL_ENTER();

    if (input[idx++] != ASN_OCTET_STRING) {
        WOLFSSL_MSG("\tfail: should be an OCTET STRING");
        return ASN_PARSE_E;
    }

    if (GetLength(input, &idx, &length, sz) < 0) {
        WOLFSSL_MSG("\tfail: extension data length");
        return ASN_PARSE_E;
    }

    #ifdef OPENSSL_EXTRA
        cert->extSubjKeyIdSrc = &input[idx];
        cert->extSubjKeyIdSz = length;
    #endif /* OPENSSL_EXTRA */

    if (length == SIGNER_DIGEST_SIZE) {
        XMEMCPY(cert->extSubjKeyId, input + idx, length);
    }
    else {
    #ifdef NO_SHA
        ret = wc_Sha256Hash(input + idx, length, cert->extSubjKeyId);
    #else
        ret = wc_ShaHash(input + idx, length, cert->extSubjKeyId);
    #endif
    }

    return ret;
}


static int _decodeKeyUsage(byte* input, int sz, DecodedCert* cert)
{
    word32 idx = 0;
    int length;
    byte unusedBits;
    WOLFSSL_ENTER();

    if (input[idx++] != ASN_BIT_STRING) {
        WOLFSSL_MSG("\tfail: key usage expected bit string");
        return ASN_PARSE_E;
    }

    if (GetLength(input, &idx, &length, sz) < 0) {
        WOLFSSL_MSG("\tfail: key usage bad length");
        return ASN_PARSE_E;
    }

    unusedBits = input[idx++];
    length--;

    if (length == 2) {
        cert->extKeyUsage = (word16)((input[idx] << 8) | input[idx+1]);
        cert->extKeyUsage >>= unusedBits;
    }
    else if (length == 1)
        cert->extKeyUsage = (word16)(input[idx] << 1);

    return 0;
}


static int _decodeExtKeyUsage(byte* input, int sz, DecodedCert* cert)
{
    word32 idx = 0, oid;
    int length;

    WOLFSSL_ENTER();

    if (GetSequence(input, &idx, &length, sz) < 0) {
        WOLFSSL_MSG("\tfail: should be a SEQUENCE");
        return ASN_PARSE_E;
    }

    #ifdef OPENSSL_EXTRA
        cert->extExtKeyUsageSrc = input + idx;
        cert->extExtKeyUsageSz = length;
    #endif

    while (idx < (word32)sz) {
        if (GetObjectId(input, &idx, &oid, sz) < 0)
            return ASN_PARSE_E;

        switch (oid) {
            case EKU_ANY_OID:
                cert->extExtKeyUsage |= EXTKEYUSE_ANY;
                break;
            case EKU_SERVER_AUTH_OID:
                cert->extExtKeyUsage |= EXTKEYUSE_SERVER_AUTH;
                break;
            case EKU_CLIENT_AUTH_OID:
                cert->extExtKeyUsage |= EXTKEYUSE_CLIENT_AUTH;
                break;
            case EKU_OCSP_SIGN_OID:
                cert->extExtKeyUsage |= EXTKEYUSE_OCSP_SIGN;
                break;
        }

        #ifdef OPENSSL_EXTRA
            cert->extExtKeyUsageCount++;
        #endif
    }

    return 0;
}


#ifndef IGNORE_NAME_CONSTRAINTS
static int _decodeSubtree(byte* input, int sz, Base_entry** head, void* heap)
{
    word32 idx = 0;

    (void)heap;

    while (idx < (word32)sz) {
        int seqLength, strLength;
        word32 nameIdx;
        byte b;

        if (GetSequence(input, &idx, &seqLength, sz) < 0) {
            WOLFSSL_MSG("\tfail: should be a SEQUENCE");
            return ASN_PARSE_E;
        }

        nameIdx = idx;
        b = input[nameIdx++];
        if (GetLength(input, &nameIdx, &strLength, sz) <= 0) {
            WOLFSSL_MSG("\tinvalid length");
            return ASN_PARSE_E;
        }

        if (b == (ASN_CONTEXT_SPECIFIC | ASN_DNS_TYPE) ||
            b == (ASN_CONTEXT_SPECIFIC | ASN_RFC822_TYPE) ||
            b == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | ASN_DIR_TYPE)) {

            Base_entry* entry = (Base_entry*)XMALLOC(sizeof(Base_entry),
                                                    heap, DYNAMIC_TYPE_ALTNAME);

            if (entry == NULL) {
                WOLFSSL_MSG("allocate error");
                return MEMORY_E;
            }

            entry->name = (char*)XMALLOC(strLength, heap, DYNAMIC_TYPE_ALTNAME);
            if (entry->name == NULL) {
                WOLFSSL_MSG("allocate error");
                return MEMORY_E;
            }

            XMEMCPY(entry->name, &input[nameIdx], strLength);
            entry->nameSz = strLength;
            entry->type = b & 0x0F;

            entry->next = *head;
            *head = entry;
        }

        idx += seqLength;
    }

    return 0;
}


static int _decodeNameConstraints(byte* input, int sz, DecodedCert* cert)
{
    word32 idx = 0;
    int length = 0;

    WOLFSSL_ENTER();

    if (GetSequence(input, &idx, &length, sz) < 0) {
        WOLFSSL_MSG("\tfail: should be a SEQUENCE");
        return ASN_PARSE_E;
    }

    while (idx < (word32)sz) {
        byte b = input[idx++];
        Base_entry** subtree = NULL;

        if (GetLength(input, &idx, &length, sz) <= 0) {
            WOLFSSL_MSG("\tinvalid length");
            return ASN_PARSE_E;
        }

        if (b == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | 0))
            subtree = &cert->permittedNames;
        else if (b == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | 1))
            subtree = &cert->excludedNames;
        else {
            WOLFSSL_MSG("\tinvalid subtree");
            return ASN_PARSE_E;
        }

        _decodeSubtree(input + idx, length, subtree, cert->heap);

        idx += length;
    }

    return 0;
}
#endif /* IGNORE_NAME_CONSTRAINTS */


#ifdef WOLFSSL_SEP
/* parse cert->devicetype */
static int _decodeCertPolicy(byte* input, int sz, DecodedCert* cert)
{
	word32 idx = 0;
	int length = 0;

	WOLFSSL_ENTER();

	/* Unwrap certificatePolicies */
	if (GetSequence(input, &idx, &length, sz) < 0) {
		WOLFSSL_MSG("\tdeviceType isn't OID");
		return ASN_PARSE_E;
	}

	if (GetSequence(input, &idx, &length, sz) < 0) {
		WOLFSSL_MSG("\tdeviceType isn't OID");
		return ASN_PARSE_E;
	}

	if (input[idx++] != ASN_OBJECT_ID) {
		WOLFSSL_MSG("\tdeviceType isn't OID");
		return ASN_PARSE_E;
	}

	if (GetLength(input, &idx, &length, sz) < 0) {
		WOLFSSL_MSG("\tCouldn't read length of deviceType");
		return ASN_PARSE_E;
	}

	if (length > 0) {
		cert->deviceType = (byte*)XMALLOC(length, cert->heap, 0);
		if (cert->deviceType == NULL) {
			WOLFSSL_MSG("\tCouldn't alloc memory for deviceType");
			return MEMORY_E;
		}
		
		cert->deviceTypeSz = length;
		XMEMCPY(cert->deviceType, input + idx, length);
	}

	WOLFSSL_LEAVE(0);
	return 0;
}
#endif /* WOLFSSL_SEP */

/* upper _decodeXXX functions are all called in this function */
/*
 *  Processing the Certificate Extensions. This does not modify the current
 *  index. It is works starting with the recorded extensions pointer.
 */
int decodeCertExtensions(DecodedCert* cert)
{
    word32 idx = 0;
    int sz = cert->extensionsSz;
    byte* input = cert->extensions;
    int length;
    word32 oid;
    byte critical = 0;
    byte criticalFail = 0;

    WOLFSSL_ENTER();

    if (input == NULL || sz == 0)
        return BAD_FUNC_ARG;

    if (input[idx++] != ASN_EXTENSIONS)
        return ASN_PARSE_E;

    if (GetLength(input, &idx, &length, sz) < 0)
        return ASN_PARSE_E;

    if (GetSequence(input, &idx, &length, sz) < 0)
        return ASN_PARSE_E;
    
    while (idx < (word32)sz) {
        if (GetSequence(input, &idx, &length, sz) < 0) {
            WOLFSSL_MSG("\tfail: should be a SEQUENCE");
            return ASN_PARSE_E;
        }

        oid = 0;
        if (GetObjectId(input, &idx, &oid, sz) < 0) {
            WOLFSSL_MSG("\tfail: OBJECT ID");
            return ASN_PARSE_E;
        }

        /* check for critical flag */
        critical = 0;
        if (input[idx] == ASN_BOOLEAN) {
            int boolLength = 0;
            idx++;
            if (GetLength(input, &idx, &boolLength, sz) < 0) {
                WOLFSSL_MSG("\tfail: critical boolean length");
                return ASN_PARSE_E;
            }
            if (input[idx++])
                critical = 1;
        }

        /* process the extension based on the OID */
        if (input[idx++] != ASN_OCTET_STRING) {
            WOLFSSL_MSG("\tfail: should be an OCTET STRING");
            return ASN_PARSE_E;
        }

        if (GetLength(input, &idx, &length, sz) < 0) {
            WOLFSSL_MSG("\tfail: extension data length");
            return ASN_PARSE_E;
        }

        switch (oid) {
            case BASIC_CA_OID:
                #ifdef OPENSSL_EXTRA
                    cert->extBasicConstSet = 1;
                    cert->extBasicConstCrit = critical;
                #endif
                if (_decodeBasicCaConstraint(&input[idx], length, cert) < 0)
                    return ASN_PARSE_E;
                break;

            case CRL_DIST_OID:
                if (_decodeCrlDist(&input[idx], length, cert) < 0)
                    return ASN_PARSE_E;
                break;

            case AUTH_INFO_OID:
                if (_decodeAuthInfo(&input[idx], length, cert) < 0)
                    return ASN_PARSE_E;
                break;

            case ALT_NAMES_OID:
                #ifdef OPENSSL_EXTRA
                    cert->extSubjAltNameSet = 1;
                    cert->extSubjAltNameCrit = critical;
                #endif
                if (_decodeAltNames(&input[idx], length, cert) < 0)
                    return ASN_PARSE_E;
                break;

            case AUTH_KEY_OID:
                cert->extAuthKeyIdSet = 1;
                #ifdef OPENSSL_EXTRA
                    cert->extAuthKeyIdCrit = critical;
                #endif
                if (_decodeAuthKeyId(&input[idx], length, cert) < 0)
                    return ASN_PARSE_E;
                break;

            case SUBJ_KEY_OID:
                cert->extSubjKeyIdSet = 1;
                #ifdef OPENSSL_EXTRA
                    cert->extSubjKeyIdCrit = critical;
                #endif
                if (_decodeSubjKeyId(&input[idx], length, cert) < 0)
                    return ASN_PARSE_E;
                break;

            case CERT_POLICY_OID:
                WOLFSSL_MSG("Certificate Policy extension not supported yet.");
                #ifdef WOLFSSL_SEP
                    #ifdef OPENSSL_EXTRA
                        cert->extCertPolicySet = 1;
                        cert->extCertPolicyCrit = critical;
                    #endif
                    if (_decodeCertPolicy(&input[idx], length, cert) < 0)
                        return ASN_PARSE_E;
                #endif
                break;

            case KEY_USAGE_OID:
                cert->extKeyUsageSet = 1;
                #ifdef OPENSSL_EXTRA
                    cert->extKeyUsageCrit = critical;
                #endif
                if (_decodeKeyUsage(&input[idx], length, cert) < 0)
                    return ASN_PARSE_E;
                break;

            case EXT_KEY_USAGE_OID:
                cert->extExtKeyUsageSet = 1;
                #ifdef OPENSSL_EXTRA
                    cert->extExtKeyUsageCrit = critical;
                #endif
                if (_decodeExtKeyUsage(&input[idx], length, cert) < 0)
                    return ASN_PARSE_E;
                break;

            #ifndef IGNORE_NAME_CONSTRAINTS
            case NAME_CONS_OID:
                cert->extNameConstraintSet = 1;
                #ifdef OPENSSL_EXTRA
                    cert->extNameConstraintCrit = critical;
                #endif
                if (_decodeNameConstraints(&input[idx], length, cert) < 0)
                    return ASN_PARSE_E;
                break;
            #endif /* IGNORE_NAME_CONSTRAINTS */

            case INHIBIT_ANY_OID:
                WOLFSSL_MSG("Inhibit anyPolicy extension not supported yet.");
                break;

            default:
                /* While it is a failure to not support critical extensions,
                 * still parse the certificate ignoring the unsupported
                 * extention to allow caller to accept it with the verify
                 * callback. */
                if (critical)
                    criticalFail = 1;
                break;
        }
        idx += length;
    }

    return criticalFail ? ASN_CRIT_EXT_E : 0;
}


