mod tcg;

use anyhow::{Context as _, Result, bail};
use std::fs::File;
use std::io::Write;
use std::str::FromStr;
use std::time::Duration;

// --- Crypto Imports (RustCrypto) ---
use rand::rngs::OsRng;
use rsa::pkcs1v15::SigningKey;
use rsa::sha2::Sha256;
use rsa::{BigUint, RsaPrivateKey, RsaPublicKey, pkcs8::LineEnding};
use x509_cert::{
    attr::AttributeTypeAndValue,
    builder::{Builder, CertificateBuilder, Profile},
    der::{Any, Encode, EncodePem, Tag},
    ext::pkix::{SubjectAltName, name::GeneralName},
    name::{Name, RdnSequence, RelativeDistinguishedName},
    serial_number::SerialNumber,
    spki::{EncodePublicKey, SubjectPublicKeyInfoOwned},
    time::Validity,
};

// --- TPM Imports (tss-esapi) ---
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

// --- Constants ---
const TPM_URI: &str = "host=localhost,port=2321";
const NV_INDEX_EK_CERT: u32 = 0x01c00002;
const NV_WRITE_CHUNK_SIZE: usize = 512;
const CA_CERT_FILENAME: &str = "local_ca.pem";
const EK_CERT_FILENAME: &str = "ek_cert.pem";

fn main() -> Result<()> {
    println!("TPM EK Certificate Provisioning");

    // 1. Connect and Soft Reset
    let mut context = connect_and_reset_tpm()?;
    println!("Connected to TPM.");

    // 2. Create Endorsement Key (EK)
    let ek_handle = create_ek(&mut context)?;
    println!("Created EK. Handle: {:?}", ek_handle);

    // 3a. Read EK Public Key from TPM.
    let (public_data, _, _) = context.read_public(ek_handle)?;
    let ek_spki = convert_tpm_public_to_spki(&public_data)?;
    println!("Retrieved and converted EK Public Key.");

    // 3b. Generate Local CA
    let (ca_signer, ca_name) = generate_ca()?;
    println!("Generated Local Root CA.");

    // 4. Issue EK Certificate with TCG Extensions. Use EK and CA from step 3
    let ek_cert_der = generate_signed_ek_cert(&ek_spki, &ca_signer, &ca_name)?;
    println!("Signed EK Certificate (Size: {} bytes).", ek_cert_der.len());

    // 5. Store Certificate in NVRAM
    write_cert_to_nvram(&mut context, &ek_cert_der)?;

    // 6. Verify
    verify_nvram_index(&mut context)?;
    println!("Verification Successful: Index Exists.");

    // 7. Print Verification instruction
    print_verification_instructions();

    Ok(())
}

// ============================================================================
//   TPM Helper Functions
// ============================================================================

// Connects to the TCG TPM simulator and issues a startup command.
// Returns: tss_esapi::context structure
fn connect_and_reset_tpm() -> Result<Context> {
    let tcti_conf = TctiNameConf::Mssim(NetworkTPMConfig::from_str(TPM_URI)?);
    let mut ctx = Context::new(tcti_conf)?;
    let _ = ctx.shutdown(StartupType::Clear);
    ctx.startup(StartupType::Clear)
        .context("Failed to start up TPM")?;
    Ok(ctx)
}

// Create the endorsement key using esapi call to the TCG TPM Simulator
fn create_ek(context: &mut Context) -> Result<KeyHandle> {
    ek::create_ek_object(context, AsymmetricAlgorithm::Rsa, None)
        .context("Failed to create EK object")
}

// Store the certificate to non-volatile ram or NVChip state file.
fn write_cert_to_nvram(context: &mut Context, cert_data: &[u8]) -> Result<()> {
    context.clear_sessions();
    context.set_sessions((Some(AuthSession::Password), None, None));

    let nv_index_tpm = NvIndexTpmHandle::try_from(NV_INDEX_EK_CERT).unwrap();
    let nv_public = NvPublicBuilder::new()
        .with_nv_index(nv_index_tpm)
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
            let err_msg = e.to_string();
            if err_msg.contains("0x14c") || err_msg.contains("already defined") {
                println!(
                    "  NV Index {:#x} already exists. Skipping write.",
                    NV_INDEX_EK_CERT
                );
                return Ok(());
            }
            return Err(e.into());
        }
    };

    let mut offset = 0;
    while offset < cert_data.len() {
        let size = std::cmp::min(cert_data.len() - offset, NV_WRITE_CHUNK_SIZE);
        let chunk = MaxNvBuffer::try_from(cert_data[offset..offset + size].to_vec())?;
        context.nv_write(NvAuth::Owner, nv_handle_obj, chunk, offset as u16)?;
        offset += size;
    }
    println!("  Stored Certificate in NVRAM.");
    Ok(())
}

fn verify_nvram_index(context: &mut Context) -> Result<()> {
    context.clear_sessions();
    let (data, _) = context.get_capability(CapabilityType::Handles, NV_INDEX_EK_CERT, 1)?;
    match data {
        tss_esapi::structures::CapabilityData::Handles(handles) => {
            if handles.iter().any(|h| match h {
                TpmHandle::NvIndex(nv) => u32::from(*nv) == NV_INDEX_EK_CERT,
                _ => false,
            }) {
                Ok(())
            } else {
                bail!("Index not found")
            }
        }
        _ => bail!("Unexpected TPM response"),
    }
}

// ============================================================================
//   Crypto & Certificate Logic
// ============================================================================

// Creates a new public key from TPM public key usig rsa, and then
// converts it into x509_cert recognisable format.
// This is an ASN.1 structure called SubjectPublicKeyInfoOwned that has 2 fields,
// AlgorithmIdentifier and public key data.
fn convert_tpm_public_to_spki(public: &Public) -> Result<SubjectPublicKeyInfoOwned> {
    let modulus_bytes = match public {
        Public::Rsa { unique, .. } => unique.as_slice(),
        _ => bail!("EK is not an RSA key"),
    };

    let n = BigUint::from_bytes_be(modulus_bytes);
    let e = BigUint::from(65537u32);

    let key = RsaPublicKey::new(n, e)?;
    let der = key.to_public_key_der()?;
    Ok(SubjectPublicKeyInfoOwned::try_from(der.as_bytes())?)
}

// Creates a key pair and uses it to create a CA.
fn generate_ca() -> Result<(SigningKey<Sha256>, Name)> {
    let mut rng = OsRng;
    let priv_key = RsaPrivateKey::new(&mut rng, 2048)?;
    let pub_key = priv_key.to_public_key();

    let signer = SigningKey::<Sha256>::new(priv_key.clone());
    let name = Name::from_str("CN=Local Root CA")?;
    let pub_der = pub_key.to_public_key_der()?;
    let spki = SubjectPublicKeyInfoOwned::try_from(pub_der.as_bytes())?;

    // Private part becomes the signer and public part is put inside the cert in spki format
    let builder = CertificateBuilder::new(
        Profile::Root,
        SerialNumber::from(1u32),
        Validity::from_now(Duration::from_secs(86400))?,
        name.clone(),
        spki,
        &signer,
    )?;
    let cert = builder.build()?;
    write_to_file(CA_CERT_FILENAME, cert.to_pem(LineEnding::LF)?.as_bytes())?;

    Ok((signer, name))
}

// The EK is signed with the CA (name and private key) created using generate_ca()
fn generate_signed_ek_cert(
    ek_spki: &SubjectPublicKeyInfoOwned,
    ca_signer: &SigningKey<Sha256>,
    ca_name: &Name,
) -> Result<Vec<u8>> {
    // The TCG specifies a Subject Alternative Name (SAN) as a SEQUENCE of sets.
    // {Set1, Set2, Set3}. Each Set is inturn a multi-valued Relative
    // Distinguished Name. However the TCG spec has only one item at each level/set.
    // Each item is a AttributeTypeAndValue structure containing AttributeType a.k.a the oid
    // defined in the tcg module and an AttributeValue which is a tagged ASN.1 value.
    // Checkout certificate examples [https://trustedcomputinggroup.org/wp-content/uploads/TCG-EK-Credential-Profile-for-TPM-Family-2.0-Level-0-Version-2.6_pub.pdf] (TCG ek credential profile)

    let tcg_rdns = RdnSequence(vec![
        RelativeDistinguishedName(
            vec![AttributeTypeAndValue {
                oid: tcg::OID_TPM_MANUFACTURER,
                value: Any::new(Tag::Utf8String, b"id:123456EF".to_vec())?,
            }]
            .try_into()?,
        ),
        RelativeDistinguishedName(
            vec![AttributeTypeAndValue {
                oid: tcg::OID_TPM_MODEL,
                value: Any::new(Tag::Utf8String, b"id:00000000".to_vec())?,
            }]
            .try_into()?,
        ),
        RelativeDistinguishedName(
            vec![AttributeTypeAndValue {
                oid: tcg::OID_TPM_VERSION,
                value: Any::new(Tag::Utf8String, b"id:00020008".to_vec())?,
            }]
            .try_into()?,
        ),
    ]);

    let san = SubjectAltName(vec![GeneralName::DirectoryName(tcg_rdns)]);

    let profile = Profile::Leaf {
        issuer: ca_name.clone(),
        enable_key_agreement: false,
        enable_key_encipherment: true,
    };

    let mut builder = CertificateBuilder::new(
        profile,
        SerialNumber::from(2u32),
        Validity::from_now(Duration::from_secs(3650 * 86400))?,
        Name::from_str("CN=TPM Endorsement Certificate")?,
        ek_spki.clone(),
        ca_signer,
    )?;

    builder.add_extension(&san)?;
    let cert = builder.build()?;

    write_to_file(EK_CERT_FILENAME, cert.to_pem(LineEnding::LF)?.as_bytes())?;

    Ok(cert.to_der()?)
}

// Writes pem data to the file
fn write_to_file(path: &str, data: &[u8]) -> Result<()> {
    let mut file = File::create(path)?;
    file.write_all(data)?;
    println!("  Saved: {}", path);
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
    println!("      Or you can even check the already saved certificate file");
    println!(
        "      openssl x509 -in {} -modulus -noout -text",
        EK_CERT_FILENAME
    );
    println!("   The \"Modulus\" sections in both outputs must match exactly.");
    println!("===============================");

    println!("4. Verify the chain using OpenSSL and the local CA file:");
    println!(
        "   openssl x509 -in {} -noout -subject -issuer",
        EK_CERT_FILENAME
    );
    println!(
        "   openssl verify -CAfile {} -untrusted {} {}",
        CA_CERT_FILENAME, EK_CERT_FILENAME, EK_CERT_FILENAME
    );
    println!("   (Note: 'OK' means the chain is valid)");

    println!("===============================");
}
