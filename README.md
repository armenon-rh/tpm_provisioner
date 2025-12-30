# TPM EK Certificate Provisioning Tool

This Rust application automates the provisioning of a Trusted Platform Module (TPM) Endorsement Key (EK) and stores a locally generated Endorsement Certificate in the TPM's NVRAM.

## Overview

The tool performs the following steps:
1.  Connects to a TPM (defaults to simulator `mssim` on `localhost:2321`).
2.  Resets the TPM (Clear Shutdown/Startup) to ensure a clean memory state.
3.  Creates a standard RSA 2048-bit Endorsement Key (EK).
4.  Generates a local self-signed Root Certificate Authority (CA) in memory.
5.  Signs the EK's public key with the local CA to create an X.509 Endorsement Certificate.
6.  Stores the certificate in the TPM NVRAM at index `0x01c00002` (TCG standard location).
7.  Verifies the storage and provides instructions for manual verification.

## Prerequisites

Before building and running this project, ensure you have the following installed:

### 1. Rust Toolchain
Install Rust and Cargo (if not already installed):
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### 2. System Libraries
This project depends on `openssl` and `tpm2-tss` (specifically the ESAPI library).

**Fedora / RHEL / CentOS:**
```bash
sudo dnf install -y pkg-config openssl-devel tpm2-tss-devel
```

**Ubuntu / Debian:**
```bash
sudo apt-get install -y pkg-config libssl-dev libtss2-dev
```

### 3. TPM Simulator (Tested with TCG TPM Simulator)
For testing without hardware, you can use the TCG TPM Reference Implementation:

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/TrustedComputingGroup/TPM.git
   cd TPM
   ```

2. **Build the Simulator:**
   ```bash
   mkdir -p TPMCmd/build
   cd TPMCmd/build
   cmake ..
   make
   ```

3. **Start the Simulator:**
   ```bash
   ./Simulator
   ```
The simulator defaults to port 2321, which this tool is configured to use.

## Building

To compile the project:

```bash
cargo build
```

## Running

To run the provisioning tool:

```bash
cargo run
```

If the NVRAM index `0x01c00002` is already defined, the tool will notify you and skip the write step to prevent errors. To force an overwrite, you must clear the TPM state (e.g., delete the simulator's `NVChip` file and restart it).

## Manual Verification

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