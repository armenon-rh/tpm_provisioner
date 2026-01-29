#!/bin/bash
echo -e "Starting the TCG TPM Simulator"
/app/TPM/TPMCmd/build/Simulator/Simulator &
sleep 1

echo -e "Run tpm2_startup to initialize"
tpm2_startup -c > /dev/null 2>&1

echo -e "Simulator started. Running 'cargo run && verify' will check OpenSSL results."

exec "$@"
