# TPM EK Certificate Provisioning Tool

[![License: LGPL 2.1](https://img.shields.io/badge/License-LGPL_2.1-blue.svg)](https://www.gnu.org/licenses/old-licenses/lgpl-2.1.txt)

This Rust application automates the provisioning of a Trusted Platform Module (TPM) Endorsement Key (EK) and stores a locally generated Endorsement Certificate in the TPM's NVRAM.

# Overview

The tool performs the following steps:
1.  Connects to a TPM (defaults to simulator `mssim` on `localhost:2321`).
2.  Issues a startup command, before proceeding with anything.
3.  Creates a standard RSA 2048-bit Endorsement Key (EK) using esapi API call.
4.  Generates a local self-signed Root Certificate Authority (CA).
5.  Stores the CA cert to an external file on the disk in pem format for out of band verification, later use.
5.  Signs the EK's public key with the local CA to create an X.509 Endorsement Certificate, making sure that it follows TCG standard format and extensions.
6.  Stores the certificate in the TPM NVRAM at index `0x01c00002` (TCG standard location).
7.  Verifies the storage and provides instructions for manual verification.

# Prerequisites

Before building and running this project, ensure you have the following installed:

## 1. Rust Toolchain
Install Rust and Cargo (if not already installed):
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

## 2. System Libraries
This project depends `tpm2-tss` (specifically the ESAPI library). We install openssl to perform verification steps

**Fedora / RHEL / CentOS:**
```bash
sudo dnf install -y pkg-config openssl-devel tpm2-tss-devel
```

**Ubuntu / Debian:**
```bash
sudo apt-get install -y pkg-config libssl-dev libtss2-dev
```

## 3. TPM Simulator (Tested with TCG TPM Simulator)
For testing without hardware, you can use the TCG TPM Reference Implementation:
Checkout the steps [here](docs/steps_to_start_TCGTPM_simulator.md)

# Building

To compile the project:

```bash
cargo build
```

# Running

To run the provisioning tool:

```bash
cargo run
```

If the NVRAM index `0x01c00002` is already defined, the tool will notify you and skip the write step to prevent errors. To force an overwrite, you must clear the TPM state (e.g., delete the simulator's `NVChip` file and restart it).

# Manual Verification

After running the tool, you can verify the results using standard TPM tools (`tpm2-tools`):

1.  **Retrieve the Certificate:**
    ```bash
    tpm2_nvread -T mssim:host=localhost,port=2321 -C o 0x01c00002 -o ek_cert.der
    ```

2.  **Inspect the Certificate:**
    ```bash
    openssl x509 -in ek_cert.der -inform DER -text -noout
    ```
    *Look for `Issuer: CN = Local Root CA`.*

3.  **Verify via standard command:**
    ```bash
    tpm2_getekcertificate -T mssim:host=localhost,port=2321 -o - | openssl x509 -text -noout
    ```

# The EK signing situation

## The Normal CSR Process
  In a standard Public Key Infrastructure (PKI) workflow (like setting up a web server), the process works like this:
    - Key Generation: You generate a Key Pair (Public Key + Private Key).
    - CSR Creation: You create a Certificate Signing Request (CSR).
       - The CSR contains your Public Key and your Identity (e.g., "CN=myserver.com").
       - The CSR is signed by your Private Key.
    - Submission: You send the CSR to a Certificate Authority (CA).
    - Verification: The CA checks the signature on the CSR. This proves "Proof of Possession" (PoP)— it proves that the person asking for the certificate actually owns the corresponding Private Key.
    - Issuance: If the signature is valid, the CA signs your Public Key and gives you back a Certificate.

## Why this fails for the TPM EK:
  The Endorsement Key (EK) is a special key inside the TPM. By TCG specification, it is created as a Restricted Decryption Key.
   - Restricted: It can only decrypt data that has been specifically formatted/encrypted by the TPM (it can't just decrypt any random blob).
   - Decryption: It has the "decrypt" attribute set, but NOT the "sign" attribute.

  Because the EK **cannot sign**, it cannot generate the signature required for step 2 of the standard CSR process. If you ask the TPM to sign this CSR with the EK, it will return an error saying 'Key usage does not allow signing.'

## Our Solution: The "Trusted Local Context"
  Since we can't prove possession via a standard CSR signature, we rely on trusting the environment. We are running code on the machine that owns the TPM. We talk to the TPM driver directly. When we ask the TPM "Give me the public part of the EK," the TPM gives it to us trusted.
   - We skip the CSR entirely.
   - We act as the CA ourselves.
   - We say: "I just pulled this public key from the TPM. I know it's there. I'm going to write a certificate for it right now."

This works for provisioning because we are the "manufacturer" or "provisioner" in this scenario.
We don't need the TPM to prove it owns the key; we just created the key on it!

## EK Cert format
The TCG specification requires us to follow a specific format described in the TCG EK Credential profile. [Check out section 3.2](https://trustedcomputinggroup.org/wp-content/uploads/TCG-EK-Credential-Profile-for-TPM-Family-2.0-Level-0-Version-2.6_pub.pdf)

# Future Work
1. Define Attestation workflow.
2. Use cocoonfs to create an image out of the state file generated by this provisioning utility (NVChip).

# License

Licensed under:
- [LGPL-2.1](./LICENSE)

# Running tests
1. Build the Image that contains necessary information to start the TCG simulator
podman build -t tpm-provisioner -f Dockerfile

2. Start a container using the image and step inside it.
podman run -it --name tpm-lab tpm-provisioner

3. Run the utility and call verify to check the CA chain.
cargo run && verify

Alternatively,
4. Start the container directly and run commands on the command line
podman run -it tpm-provisioner:latest /bin/bash -c "cargo run && verify"

5. To copy the certificates to the host,
podman cp <container_name>:/app/tpm_provisioner/ek_cert.pem /path/on/host/ek_cert.pem
podman cp <container_name>:/app/tpm_provisioner/local_ca.pem /path/on/host/local_ca.pem

Note that the verification will fail if you already had the files local_ca.pem and ek_cert.pem in the source directory, because it will be copied into the container in COPY step.
