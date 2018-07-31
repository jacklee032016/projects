#!/bin/sh

# create a CA certificate
# 1: RSA private key
# 2: certificate request, with private key, distinguished name,etc.
# 3: certificate: SHA1 signature, signed by the same private key

if [ -z "$1" ]; then
	echo "argument1 is CA certificate name, can not be empty"
	exit 0
fi

if [ -z "$2" ]; then
	echo "argument2 is CA private key name, can not be empty"
	exit 0
fi

if [ -z "$3" ]; then
	echo "argument3 is key length, can not be empty"
	exit 0
fi

echo "Step 1: RSA private key of $KEY_LENGTH..."
openssl genrsa -out $2 $3

#echo "Step 2(optional): From PEM into DER..."
#openssl rsa -in $CERT_NAME.key.pem -out $CERT_NAME.key -outform DER

echo "Step 3: CERT request..."
openssl req -out $1.req -key $2 -new  -config ./caCert.conf 

echo "Step 4: CERT signed with key of $2 in SHA1..."
openssl x509 -req -in $1.req -out $1 -sha1 -days 5000 -signkey $2


# openssl req -x509 -nodes -days 365 -newkey rsa:1024 -keyout mycert.pem -out mycert.pem \
#		-subj '/C=cn/ST=Sichuan/L=Chengdu/CN=127.0.0.1/O=Zhijie Li, Inc./'
