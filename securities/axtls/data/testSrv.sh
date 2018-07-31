#!/bin/sh

openssl s_client -connect 127.0.0.1:443 -CAfile certs/tests/ecpCa.1024.x509.pem > file.log 2>&1 << "GET / "
