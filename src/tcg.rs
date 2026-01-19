use x509_cert::der::oid::ObjectIdentifier;

/* TCG OID Root: 2.23.133.2 (Platform Attribute)
 * Reference: TCG EK Credential Profile 2.0 and TCG OID Registry Version
 * https://trustedcomputinggroup.org/wp-content/uploads/TCG-EK-Credential-Profile-for-TPM-Family-2.0-Level-0-Version-2.6_pub.pdf
 * https://trustedcomputinggroup.org/wp-content/uploads/TCG-OID-Registry-Version-1.00_pub-1.pdf
 */

pub const OID_TPM_MANUFACTURER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.23.133.2.1");

pub const OID_TPM_MODEL: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.23.133.2.2");

pub const OID_TPM_VERSION: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.23.133.2.3");

#[allow(dead_code)]
pub const OID_TPM_SPECIFICATION: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.23.133.2.16");
