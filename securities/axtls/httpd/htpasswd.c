
#include "tls.h"

int tfd;

void base64_encode(const uint8_t *in, size_t inlen, char *out, size_t outlen)
{
	static const char b64str[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	while (inlen && outlen)
	{
		*out++ = b64str[(in[0] >> 2) & 0x3f];
		if (!--outlen)
			break;

		*out++ = b64str[((in[0] << 4) + (--inlen ? in[1] >> 4 : 0)) & 0x3f];
		if (!--outlen)
			break;
		
		*out++ = (inlen? b64str[((in[1] << 2)+ (--inlen ? in[2] >> 6 : 0))& 0x3f]: '=');
		if (!--outlen)
			break;
		
		*out++ = inlen ? b64str[in[2] & 0x3f] : '=';
		if (!--outlen)
			break;
		if (inlen)
			inlen--;
		if (inlen)
			in += 3;
	}

	if (outlen)
		*out = '\0';
}

static void usage(void) 
{
	fprintf(stderr,"Usage: htpasswd username\n");
	exit(1);
}

#ifdef WIN32
static char * getpass(const char *prompt)
{
	static char buf[127];
	FILE *fp = stdin;

	printf(prompt); TTY_FLUSH();
#if 0
	fp = fopen("/dev/tty", "w");
	if (fp == NULL) 
	{
	printf("null\n"); TTY_FLUSH();
	fp = stdin;
	}
#endif

	fgets(buf, sizeof(buf), fp);
	while (buf[strlen(buf)-1] < ' ') 
	buf[strlen(buf)-1] = '\0';

	//if (fp != stdin) 
	//    fclose(fp);
	return buf;
}
#endif

int main(int argc, char *argv[]) 
{
	char* pw;
	uint8_t md5_salt[HASH_MD_LENGTH_MD5], md5_pass[HASH_MD_LENGTH_MD5];
	char b64_salt[HASH_MD_LENGTH_MD5+10], b64_pass[HASH_MD_LENGTH_MD5+10];
	MD5_CTX ctx;

	if (argc != 2)
		usage();

	pw = strdup(getpass("New password:"));
	if (strcmp(pw, getpass("Re-type new password:")) != 0)
	{
		fprintf(stderr, "They don't match, sorry.\n" );
		exit(1);
	}

	RNG_initialize();
	if (get_random(HASH_MD_LENGTH_MD5, md5_salt) < 0)
	{
		fprintf(stderr, "Can't get random data\n" );
		exit(1);
	}

	RNG_terminate();
	base64_encode(md5_salt, HASH_MD_LENGTH_MD5, b64_salt, sizeof(b64_salt));

	MD5_Init(&ctx);
	MD5_Update(&ctx, md5_salt, HASH_MD_LENGTH_MD5);
	MD5_Update(&ctx, (uint8_t *)pw, strlen(pw));
	MD5_Final(md5_pass, &ctx);
	base64_encode(md5_pass, HASH_MD_LENGTH_MD5, b64_pass, sizeof(b64_pass));

	printf("Add the following to your '.htpasswd' file\n");
	printf("%s:%s$%s\n", argv[1], b64_salt, b64_pass);
	return 0;
}

