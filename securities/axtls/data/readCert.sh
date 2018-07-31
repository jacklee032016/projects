#!/bin/sh

# openssl x509 -noout -in cert.pem -issuer -subject -dates

if [ -z "$1" ]; then
	echo "argument1 is certificate name, can not be empty"
	exit 0
fi

openssl x509 -text -in $1 > cert.txt 
