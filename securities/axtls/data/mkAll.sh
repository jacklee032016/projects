#!/bin/sh

DATA_PATH=certs/tests
CERT=ecp
KEY_LENGTH=1024

CA_CERT_NAME=$DATA_PATH/"$CERT"Ca.$KEY_LENGTH.x509.pem
CA_KEY=$DATA_PATH/"$CERT"Ca.$KEY_LENGTH.key.pem


CLIENT_CERT_NAME=$DATA_PATH/"$CERT"Client.$KEY_LENGTH.x509.pem
CLIENT_CERT_KEY=$DATA_PATH/"$CERT"Client.$KEY_LENGTH.key.pem

SERVER_CERT_NAME=$DATA_PATH/"$CERT"Server.$KEY_LENGTH.x509.pem
SERVER_CERT_KEY=$DATA_PATH/"$CERT"Server.$KEY_LENGTH.key.pem

mkdir -p $DATA_PATH

echo "CA cert: $CA_CERT_NAME; key: $CA_KEY"
echo "cert: $CERT_NAME; key: $CERT_KEY"

echo ""
echo "Build CA cert $CA_CERT_NAME($CA_KEY)..."
mkSelfCa.sh $CA_CERT_NAME $CA_KEY $KEY_LENGTH

echo ""
echo "Build client cert $CLIENT_CERT_NAME($CLIENT_CERT_KEY) signed by CA[$CA_CERT_NAME($CA_KEY)]..."
mkCert.sh $CLIENT_CERT_NAME $CLIENT_CERT_KEY $KEY_LENGTH $CA_CERT_NAME $CA_KEY ./clientCerts.conf 
	
echo ""
echo "Build server cert $SERVER_CERT_NAME($SERVER_CERT_KEY) signed by CA[$CA_CERT_NAME($CA_KEY)]..."
mkCert.sh $SERVER_CERT_NAME $SERVER_CERT_KEY $KEY_LENGTH $CA_CERT_NAME $CA_KEY ./serverCerts.conf 
	
