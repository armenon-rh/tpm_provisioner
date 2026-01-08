use anyhow::{Context as _, Result, bail};
use openssl::{
    asn1::Asn1Time,
    bn::BigNum,
    hash::MessageDigest,
    pkey::{PKey, Private},
    rsa::Rsa,
    x509::{
        X509, X509NameBuilder,
        extension::{BasicConstraints, KeyUsage},
    },
};
use std::fs::File;
use std::io::Write;
use std::str::FromStr;
use tss_esapi::{
    Context, TctiNameConf,
    abstraction::ek,
    constants::{CapabilityType, StartupType},
    handles::{KeyHandle, NvIndexTpmHandle, TpmHandle},
    interface_types::{
        algorithm::{AsymmetricAlgorithm, HashingAlgorithm},
        resource_handles::{NvAuth, Provision},
        session_handles::AuthSession,
    },
    structures::{MaxNvBuffer, NvPublicBuilder, Public},
    tcti_ldr::NetworkTPMConfig,
};

const TPM_URI: &str = "host=localhost,port=2321";
const NV_INDEX_EK_CERT: u32 = 0x01c00002;
const EK_KEY_BITS: u32 = 2048;
const NV_WRITE_CHUNK_SIZE: usize = 512;
const CA_CERT_FILENAME: &str = "local_ca.pem";

fn main() -> Result<()> {
    println!("TPM EK Certificate Provisioning");

    /* 1. Connect and Soft Reset (Clears RAM/Transient Objects) */
    let mut context = connect_and_reset_tpm()?;
    println!("Connected and reset TPM state");

    /* 2. Create Endorsement Key (EK) */
    let ek_handle = create_ek(&mut context)?;
    println!("Created Endorsement Key. Handle: {:?}", ek_handle);

    /* 3. Generate Local CA */
    let (ca_key, ca_cert) = create_ca()?;
    println!("Generated local Root CA.");

    /* 4. Write CA to a file on disk */
    write_cert_to_file(&ca_cert, CA_CERT_FILENAME)?;

    /* 5. Sign EK with CA (Issue Certificate) */
    let ek_cert_der = generate_signed_ek_cert(&mut context, ek_handle, &ca_key, &ca_cert)?;
    println!("Signed EK Certificate (Size: {} bytes).", ek_cert_der.len());

    /* 6. Store Certificate in NVRAM */
    write_cert_to_nvram(&mut context, &ek_cert_der)?;

    /* 7. Final Verification */
    verify_nvram_index(&mut context)?;
    println!("Verification Successful: EK Certificate stored in NVRAM.");

    /* 8. Print Verification Instructions */
    print_verification_instructions();

    Ok(())
}

fn print_verification_instructions() {
    println!("\nVerification Instructions");
    println!("To verify the setup manually, you can run the following commands:\n");

    println!("1. Retrieve the Certificate from NVRAM:");
    println!(
        "   tpm2_nvread -T mssim:host=localhost,port=2321 -C o {:#x} -o ek_cert.der",
        NV_INDEX_EK_CERT
    );

    println!("\n2. View the Certificate Details:");
    println!("   openssl x509 -in ek_cert.der -inform DER -text -noout");
    println!("   Check for:");
    println!("    * Issuer: CN = Local Root CA");
    println!("    * Subject: CN = TPM Endorsement Certificate");

    println!("\n3. Verify the EK Public Key Matches:");
    println!("   To confirm the certificate actually belongs to the EK inside the TPM:");

    println!("\n   A. Generate the EK Public Key from TPM:");
    println!("      tpm2_createek -T mssim:host=localhost,port=2321 -c ek.ctx -u ek.pub -G rsa");

    println!("\n   B. Extract the Public Key from the Certificate:");
    println!("      openssl x509 -in ek_cert.der -inform DER -pubkey -noout > cert_key.pem");

    println!("\n   C. Compare the Modulus:");
    println!("      From the TPM key:");
    println!("      tpm2_print -t TPM2B_PUBLIC ek.pub");
    println!("      From the Certificate:");
    println!("      openssl rsa -pubin -in cert_key.pem -text -noout");
    println!("   The \"Modulus\" sections in both outputs must match exactly.");

    println!("4. Verify the chain using OpenSSL and the local CA file:");
    println!("   openssl x509 -in ek_cert.der -inform DER -noout -subject -issuer");
    println!(
        "   openssl verify -CAfile {} -untrusted ek_cert.der ek_cert.der",
        CA_CERT_FILENAME
    );
    println!("   (Note: 'OK' means the chain is valid)");

    println!("===============================");
}

/* Connects to the TPM and performs a Shutdown(Clear) + Startup(Clear) cycle. */
fn connect_and_reset_tpm() -> Result<Context> {
    let tcti_conf = TctiNameConf::Mssim(NetworkTPMConfig::from_str(TPM_URI)?);
    let mut ctx = Context::new(tcti_conf)?;

    /* Send Shutdown(Clear). We ignore errors because the TPM might already be
       down or in a state where this isn't allowed. This is a "best effort" cleanup.
    */
    let _ = ctx.shutdown(StartupType::Clear);

    // Send Startup(Clear). This is required to make the TPM operational.
    ctx.startup(StartupType::Clear)
        .context("Failed to start up TPM")?;

    Ok(ctx)
}

/* Creates a standard 2048-bit RSA Endorsement Key. */
fn create_ek(context: &mut Context) -> Result<KeyHandle> {
    ek::create_ek_object(context, AsymmetricAlgorithm::Rsa, None)
        .context("Failed to create EK object")
}

/* Generates an in-memory Root CA using OpenSSL. */
fn create_ca() -> Result<(PKey<Private>, X509)> {
    let rsa = Rsa::generate(EK_KEY_BITS)?;
    let privkey = PKey::from_rsa(rsa)?;

    let mut name = X509NameBuilder::new()?;
    name.append_entry_by_text("CN", "Local Root CA")?;
    name.append_entry_by_text("O", "TPM Provisioning")?;
    let subject_name = name.build();

    let mut builder = X509::builder()?;
    builder.set_version(2)?;
    let serial = BigNum::from_u32(1)?.to_asn1_integer()?;
    builder.set_serial_number(&serial)?;
    builder.set_subject_name(&subject_name)?;
    builder.set_issuer_name(&subject_name)?;
    builder.set_pubkey(&privkey)?;
    let not_before = Asn1Time::days_from_now(0)?;
    builder.set_not_before(&not_before)?;
    let not_after = Asn1Time::days_from_now(365)?;
    builder.set_not_after(&not_after)?;

    builder.sign(&privkey, MessageDigest::sha256())?;
    // Basic Constraints: CA:TRUE
    // We use the builder API here for simplicity
    let bc = BasicConstraints::new().critical().ca().build()?;
    builder.append_extension(bc)?;

    Ok((privkey, builder.build()))
}

fn write_cert_to_file(ca_cert: &X509, filename: &str) -> Result<()> {
    let pem = ca_cert.to_pem()?;
    let mut file = File::create(filename).context("Failed to create CA cert file")?;
    file.write_all(&pem)
        .context("Failed to write CA cert to file")?;
    println!("Saved CA Certificate to disk: {}", filename);
    Ok(())
}

/* Signs the TPM's EK Public Key with our local CA. */
fn generate_signed_ek_cert(
    context: &mut Context,
    ek_handle: KeyHandle,
    ca_key: &PKey<Private>,
    ca_cert: &X509,
) -> Result<Vec<u8>> {
    // 1. Read Public Key from TPM
    let (public_data, _, _) = context.read_public(ek_handle)?;

    let modulus = match public_data {
        Public::Rsa { unique, .. } => unique,
        _ => bail!("EK is not an RSA key"),
    };

    // 2. Reconstruct OpenSSL Public Key, because tpm format is different from openssl
    let n = BigNum::from_slice(modulus.as_slice())?;
    let e = BigNum::from_u32(65537)?;
    let ek_pubkey = PKey::from_rsa(Rsa::from_public_components(n, e)?)?;

    // 3. Create Certificate
    let mut builder = X509::builder()?;
    builder.set_version(2)?;
    let serial = BigNum::from_u32(2)?.to_asn1_integer()?;
    builder.set_serial_number(&serial)?;

    let mut name = X509NameBuilder::new()?;
    name.append_entry_by_text("CN", "TPM Endorsement Certificate")?;
    builder.set_subject_name(&name.build())?;
    builder.set_issuer_name(ca_cert.subject_name())?;
    builder.set_pubkey(&ek_pubkey)?;

    let not_before = Asn1Time::days_from_now(0)?;
    builder.set_not_before(&not_before)?;
    let not_after = Asn1Time::days_from_now(3650)?; // 10 Years
    builder.set_not_after(&not_after)?;

    // --- Extensions ---
    // 1. Basic Constraints: CA:FALSE, Critical
    // The default BasicConstraints::new() creates an extension where CA is FALSE (omitted).
    let bc = BasicConstraints::new().critical().build()?;
    builder.append_extension(bc)?;

    // 2. Key Usage: keyEncipherment, Critical
    let ku = KeyUsage::new().critical().key_encipherment().build()?;
    builder.append_extension(ku)?;

    builder.sign(ca_key, MessageDigest::sha256())?;

    Ok(builder.build().to_der()?)
}

/* Stores the certificate in NVRAM. Handles existing indices safely. */
fn write_cert_to_nvram(context: &mut Context, cert_data: &[u8]) -> Result<()> {
    // Clear sessions to ensure clean state
    context.clear_sessions();

    // Set Password Session (Owner Auth)
    context.set_sessions((Some(AuthSession::Password), None, None));

    let nv_index = NvIndexTpmHandle::try_from(NV_INDEX_EK_CERT).unwrap();

    // Define NV Space
    // We attempt definition directly to avoid buggy existence checks.
    let nv_public = NvPublicBuilder::new()
        .with_nv_index(nv_index)
        .with_data_area_size(cert_data.len())
        .with_index_name_algorithm(HashingAlgorithm::Sha256)
        .with_index_attributes(
            tss_esapi::attributes::NvIndexAttributesBuilder::new()
                .with_owner_write(true)
                .with_owner_read(true)
                .with_auth_read(true)
                .with_no_da(true)
                .build()?,
        )
        .build()?;

    let nv_handle_obj = match context.nv_define_space(Provision::Owner, None, nv_public) {
        Ok(h) => h,
        Err(e) => {
            // Check for TPM_RC_NV_DEFINED (0x14c) by code or description
            let err_msg = e.to_string();
            if err_msg.contains("0x14c") || err_msg.contains("already defined") {
                println!(
                    "NV Index {:#x} already exists. Skipping write.",
                    NV_INDEX_EK_CERT
                );
                return Ok(());
            }
            return Err(e.into());
        }
    };

    // Write Data in Chunks
    let mut offset = 0;
    while offset < cert_data.len() {
        let size = std::cmp::min(cert_data.len() - offset, NV_WRITE_CHUNK_SIZE);
        let chunk = MaxNvBuffer::try_from(cert_data[offset..offset + size].to_vec())?;

        context
            .nv_write(NvAuth::Owner, nv_handle_obj, chunk, offset as u16)
            .context("Failed to write certificate chunk to NVRAM")?;

        offset += size;
    }
    println!(
        "Stored Certificate in NVRAM (Index: {:#x}).",
        NV_INDEX_EK_CERT
    );
    Ok(())
}

/* Verifies that the NV Index exists in the TPM. */
fn verify_nvram_index(context: &mut Context) -> Result<()> {
    context.clear_sessions(); // Critical cleanup

    let (data, _) = context
        .get_capability(CapabilityType::Handles, NV_INDEX_EK_CERT, 1)
        .context("Failed to verify NV index")?;

    match data {
        tss_esapi::structures::CapabilityData::Handles(handles) => {
            if handles.iter().any(|h| match h {
                TpmHandle::NvIndex(nv) => u32::from(*nv) == NV_INDEX_EK_CERT,
                _ => false,
            }) {
                Ok(())
            } else {
                bail!(
                    "Verification Failed: Index {:#x} not found.",
                    NV_INDEX_EK_CERT
                )
            }
        }
        _ => bail!("Verification Failed: Unexpected TPM response."),
    }
}
