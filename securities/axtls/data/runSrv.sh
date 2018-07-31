#!/bin/sh

# the -www option will sent back an HTML-formatted status page to any HTTP clients that request a page
# the -WWW option "emulates a simple web server. Pages will be resolved relative to the current directory.

PORT=443
#SRV=WWW
SRV=www

# this self-signed CA cert don't contains private key
SERVER_CERT=certs/tests/ecpServer.1024.x509.pem
SERVER_PRIVATE_KEY=certs/tests/ecpServer.1024.key.pem

# CA_CERT=../test/axTLS.x509_512.pem
# PRIVATE_KEY=../test/axTLS.key_512.pem

# this self-signed CA cert contains private key, self-signed cert can not used by server
# CA_CERT=mycert.pem

echo "Start TLS server at $PORT with server cert \"$SERVER_CERT\"..."
openssl s_server -accept $PORT -cert $SERVER_CERT -$SRV -key $SERVER_PRIVATE_KEY -debug  > certs/tests/srv.txt 
# > srv.log 2>&1

