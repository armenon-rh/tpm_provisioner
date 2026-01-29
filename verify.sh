#!/bin/bash
echo -e "Starting OpenSSL Validation"

if [ -f "ek_cert.pem" ]; then
    echo "Found ek_cert.pem. Extracting info:"
    openssl x509 -in ek_cert.pem -text -noout -modulus -issuer
else
    echo -e "ERROR: ek_cert.pem not found! Run 'cargo run' first"
fi

if [ -f "local_ca.pem" ]; then
    openssl verify -CAfile local_ca.pem -untrusted ek_cert.pem ek_cert.pem
fi
