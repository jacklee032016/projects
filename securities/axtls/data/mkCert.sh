#!/bin/sh

# create a certificate signed a CA
# 1: RSA private key
# 2: certificate request, with private key, distinguished name,etc.
# 3: certificate: SHA1 signature, signed by the same private key

DATA_PATH=certs/tests
CERT_NAME=ecp
KEY_LENGTH=1024

# -n string1	 string1 is NOT NULL and does exist
# -z string1	 string1 is NULL and does exist
if [ -z "$1" ]; then
	echo "argument1 is certificate name, can not be empty"
	exit 0
fi

if [ -z "$2" ]; then
	echo "argument2 is private key name, can not be empty"
	exit 0
fi

if [ -z "$3" ]; then
	echo "argument3 is key length, can not be empty"
	exit 0
fi

if [ -z "$4" ]; then
	echo "argument4 is CA certificate, can not be empty"
	exit 0
fi

if [ -z "$5" ]; then
	echo "argument5 is CA private key, can not be empty"
	exit 0
fi

if [ -z "$6" ]; then
	echo "argument4 is DN info, can not be empty"
	exit 0
fi

echo "Step 1: RSA private key of $KEY_LENGTH..."
openssl genrsa -out $2 $3

#echo "Step 2(optional): From PEM into DER..."
#openssl rsa -in $CERT_NAME.key.pem -out $CERT_NAME.key -outform DER

echo "Step 3: CERT request..."
openssl req -out $1.req -key $2 -new  -config $6

echo "Step 4: CERT signed with key $2 of $4  in SHA1..."
openssl x509 -req -in $1.req -out $1 -sha1 -CAcreateserial -days 5000 \
            -CA $4 -CAkey $5

