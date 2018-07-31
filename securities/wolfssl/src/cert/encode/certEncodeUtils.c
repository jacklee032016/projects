/*
* utils functions used in EncodeMakeCert and EncodeKey2Request
*/

#include "cmnCrypto.h"

#include "_asnCertEncoding.h"

#ifdef WOLFSSL_CERT_GEN

/* ASN Encoded Name field */
typedef struct EncodedName {
	int  nameLen;/* actual string value length */
	int  totalLen; /* total encoded length */
	int  type;  /* type of name */
	int  used;/* are we actually using this one */
	byte encoded[CTC_NAME_SIZE * 2]; /* encoding */
} EncodedName;

/* encode all extensions, return total bytes written */
int SetExtensions(byte* output, const byte* ext, int extSz, int header)
{
    byte sequence[MAX_SEQ_SZ];
    byte len[MAX_LENGTH_SZ];

    int sz = 0;
    int seqSz = SetSequence(extSz, sequence);

    if (header) {
        int lenSz = SetLength(seqSz + extSz, len);
        output[0] = ASN_EXTENSIONS; /* extensions id */
        sz++;
        XMEMCPY(&output[sz], len, lenSz);  /* length */
        sz += lenSz;
    }
    XMEMCPY(&output[sz], sequence, seqSz);  /* sequence */
    sz += seqSz;
    XMEMCPY(&output[sz], ext, extSz);  /* extensions */
    sz += extSz;

    return sz;
}


/* encode CA basic constraint true, return total bytes written */
int SetCa(byte* output)
{
	static const byte ca[] = { 0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff };

	XMEMCPY(output, ca, sizeof(ca));

	return (int)sizeof(ca);
}


/* Get Which Name from index */
static const char* __getOneName(CertName* name, int idx)
{
    switch (idx) {
    case 0:
       return name->country;

    case 1:
       return name->state;

    case 2:
       return name->locality;

    case 3:
       return name->sur;

    case 4:
       return name->org;

    case 5:
       return name->unit;

    case 6:
       return name->commonName;

    case 7:
       return name->email;

    default:
       return 0;
    }
}

/* Get Which Name Encoding from index */
static char __getNameType(CertName* name, int idx)
{
    switch (idx) {
    case 0:
       return name->countryEnc;

    case 1:
       return name->stateEnc;

    case 2:
       return name->localityEnc;

    case 3:
       return name->surEnc;

    case 4:
       return name->orgEnc;

    case 5:
       return name->unitEnc;

    case 6:
       return name->commonNameEnc;

    default:
       return 0;
    }
}


/* Get ASN Name from index */
static byte __getNameId(int idx)
{
    switch (idx) {
    case 0:
       return ASN_COUNTRY_NAME;

    case 1:
       return ASN_STATE_NAME;

    case 2:
       return ASN_LOCALITY_NAME;

    case 3:
       return ASN_SUR_NAME;

    case 4:
       return ASN_ORG_NAME;

    case 5:
       return ASN_ORGUNIT_NAME;

    case 6:
       return ASN_COMMON_NAME;

    case 7:
       /* email uses different id type */
       return 0;

    default:
       return 0;
    }
}



/* encode CertName into output, return total bytes written */
int SetName(byte* output, CertName* name)
{
    int          totalBytes = 0, i, idx;
#ifdef WOLFSSL_SMALL_STACK
    EncodedName* names = NULL;
#else
    EncodedName  names[NAME_ENTRIES];
#endif

#ifdef WOLFSSL_SMALL_STACK
    names = (EncodedName*)XMALLOC(sizeof(EncodedName) * NAME_ENTRIES, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (names == NULL)
        return MEMORY_E;
#endif

    for (i = 0; i < NAME_ENTRIES; i++) {
        const char* nameStr = __getOneName(name, i);
        if (nameStr) {
            /* bottom up */
            byte firstLen[MAX_LENGTH_SZ];
            byte secondLen[MAX_LENGTH_SZ];
            byte sequence[MAX_SEQ_SZ];
            byte set[MAX_SET_SZ];

            int email = i == (NAME_ENTRIES - 1) ? 1 : 0;
            int strLen  = (int)XSTRLEN(nameStr);
            int thisLen = strLen;
            int firstSz, secondSz, seqSz, setSz;

            if (strLen == 0) { /* no user data for this item */
                names[i].used = 0;
                continue;
            }

            secondSz = SetLength(strLen, secondLen);
            thisLen += secondSz;
            if (email) {
                thisLen += EMAIL_JOINT_LEN;
                thisLen ++;                               /* id type */
                firstSz  = SetLength(EMAIL_JOINT_LEN, firstLen);
            }
            else {
                thisLen++;                                 /* str type */
                thisLen++;                                 /* id  type */
                thisLen += JOINT_LEN;    
                firstSz = SetLength(JOINT_LEN + 1, firstLen);
            }
            thisLen += firstSz;
            thisLen++;                                /* object id */

            seqSz = SetSequence(thisLen, sequence);
            thisLen += seqSz;
            setSz = SetSet(thisLen, set);
            thisLen += setSz;

            if (thisLen > (int)sizeof(names[i].encoded)) {
#ifdef WOLFSSL_SMALL_STACK
                XFREE(names, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
                return BUFFER_E;
            }

            /* store it */
            idx = 0;
            /* set */
            XMEMCPY(names[i].encoded, set, setSz);
            idx += setSz;
            /* seq */
            XMEMCPY(names[i].encoded + idx, sequence, seqSz);
            idx += seqSz;
            /* asn object id */
            names[i].encoded[idx++] = ASN_OBJECT_ID;
            /* first length */
            XMEMCPY(names[i].encoded + idx, firstLen, firstSz);
            idx += firstSz;
            if (email) {
                const byte EMAIL_OID[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
                                           0x01, 0x09, 0x01, 0x16 };
                /* email joint id */
                XMEMCPY(names[i].encoded + idx, EMAIL_OID, sizeof(EMAIL_OID));
                idx += (int)sizeof(EMAIL_OID);
            }
            else {
                /* joint id */
                byte bType = __getNameId(i);
                names[i].encoded[idx++] = 0x55;
                names[i].encoded[idx++] = 0x04;
                /* id type */
                names[i].encoded[idx++] = bType; 
                /* str type */
                names[i].encoded[idx++] = __getNameType(name, i);
            }
            /* second length */
            XMEMCPY(names[i].encoded + idx, secondLen, secondSz);
            idx += secondSz;
            /* str value */
            XMEMCPY(names[i].encoded + idx, nameStr, strLen);
            idx += strLen;

            totalBytes += idx;
            names[i].totalLen = idx;
            names[i].used = 1;
        }
        else
            names[i].used = 0;
    }

    /* header */
    idx = SetSequence(totalBytes, output);
    totalBytes += idx;
    if (totalBytes > ASN_NAME_MAX) {
#ifdef WOLFSSL_SMALL_STACK
        XFREE(names, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return BUFFER_E;
    }

    for (i = 0; i < NAME_ENTRIES; i++) {
        if (names[i].used) {
            XMEMCPY(output + idx, names[i].encoded, names[i].totalLen);
            idx += names[i].totalLen;
        }
    }

#ifdef WOLFSSL_SMALL_STACK
    XFREE(names, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return totalBytes;
}

#endif

