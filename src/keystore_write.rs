//! JKS and PKCS#12 keystore writing.
//!
//! The format is selected from the file extension, matching official
//! `KeyStoreHelper.createKeyStoreAccordingFileType` and the `validFileType`
//! check the CLI applies. Reading lives in [`crate::SigningKey`].
//!
//! JKS output uses the crate's `rand`-backed salt generator; see the `jks`
//! dependency declaration for why that feature is mandatory.
//!
//! PKCS#12 output is a PFX built from PBES2 (PBKDF2-HMAC-SHA256 + AES-256-CBC),
//! the same family the JDK writes by default and the scheme this crate's own
//! reader prefers. Bags carry `friendlyName` and `localKeyId` attributes so
//! Java tooling can associate each private key with its certificate chain.

use std::path::Path;
use std::time::SystemTime;

use cms::content_info::ContentInfo;
use const_oid::ObjectIdentifier;
use der::asn1::{Any, OctetString, SetOfVec};
use der::{Decode, Encode, Tag};
use hmac::{Hmac, Mac};
use pkcs12::cert_type::CertBag;
use pkcs12::digest_info::DigestInfo;
use pkcs12::mac_data::MacData;
use pkcs12::pfx::{Pfx, Version};
use pkcs12::safe_bag::SafeBag;
use rand::RngCore;
use sha2::Sha256;
use spki::AlgorithmIdentifierOwned;
use x509_cert::attr::{Attribute, AttributeValue, Attributes};

use crate::error::SignError;

/// `id-data` from RFC 5652, used for unencrypted `AuthenticatedSafe` entries.
const ID_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");
/// `certTypes 1`, the `x509Certificate` identifier inside a `CertBag`.
const X509_CERTIFICATE_CERT_TYPE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.22.1");
/// `friendlyName`, the PKCS#12 alias attribute.
const FRIENDLY_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.20");
/// `localKeyId`, linking a shrouded key bag to its certificate bags.
const LOCAL_KEY_ID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.21");
/// `sha256` (`2.16.840.1.101.3.4.2.1`), the `digestAlgorithm` the JDK writes for
/// its `HmacPBESHA256` PFX MAC. The parallel `hmacWithSHA256` OID
/// (`1.2.840.113549.2.9`) is what PKCS#12 implementations disagree about, and
/// the JDK rejects the latter with "Algorithm HmacPBEHMACSHA256 not available".
const SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");

/// PBKDF2 iteration count for both the shrouded key and the archive MAC.
/// Matches the JDK 11/17 PKCS#12 keystore defaults.
const PKCS12_ITERATIONS: u32 = 10_000;
const PKCS12_SALT_LEN: usize = 16;
const AES_256_KEY_LEN: usize = 32;
const AES_BLOCK_SIZE: usize = 16;

/// Java's `JavaKeyStore` requires a store password of at least six characters.
const JKS_MIN_STORE_PASSWORD: usize = 6;

/// Keystore container format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeystoreFormat {
    /// Java KeyStore.
    Jks,
    /// PKCS#12 / PFX.
    Pkcs12,
}

impl KeystoreFormat {
    /// Infer the format from a file extension, as `FileUtils.getSuffix` does.
    pub fn from_extension(extension: &str) -> Option<Self> {
        if extension.eq_ignore_ascii_case("jks") {
            Some(Self::Jks)
        } else if extension.eq_ignore_ascii_case("p12") || extension.eq_ignore_ascii_case("pfx") {
            Some(Self::Pkcs12)
        } else {
            None
        }
    }

    /// Infer the format from a path's extension.
    pub fn from_path(path: &Path) -> Result<Self, SignError> {
        path.extension()
            .and_then(|extension| extension.to_str())
            .and_then(Self::from_extension)
            .ok_or_else(|| SignError::UnsupportedKeystoreFormat(path.display().to_string()))
    }
}

/// One private-key entry to write, with its certificate chain leaf-first.
pub struct KeystoreEntry<'a> {
    pub alias: &'a str,
    pub key_password: &'a str,
    /// PKCS#8 DER.
    pub private_key_der: &'a [u8],
    /// DER-encoded X.509 certificates, leaf first.
    pub certificate_chain: &'a [Vec<u8>],
}

/// Serialize a keystore containing a single private-key entry.
pub fn write_keystore(
    format: KeystoreFormat,
    store_password: &str,
    entry: &KeystoreEntry<'_>,
) -> Result<Vec<u8>, SignError> {
    if entry.certificate_chain.is_empty() {
        return Err(SignError::NoCertificate);
    }
    match format {
        KeystoreFormat::Jks => write_jks(store_password, entry),
        KeystoreFormat::Pkcs12 => write_pkcs12(store_password, entry),
    }
}

fn write_jks(store_password: &str, entry: &KeystoreEntry<'_>) -> Result<Vec<u8>, SignError> {
    if store_password.chars().count() < JKS_MIN_STORE_PASSWORD {
        return Err(SignError::KeystoreWrite(format!(
            "a JKS store password must be at least {JKS_MIN_STORE_PASSWORD} characters"
        )));
    }

    // Java enforces the six-character minimum on the store password only; a key
    // password may be shorter, so the crate's shared limit is lifted here.
    let options = jks::KeyStoreOptions {
        min_password_len: 0,
        ..Default::default()
    };

    let mut store = jks::KeyStore::with_options(options);
    store
        .set_private_key_entry(
            entry.alias,
            jks::PrivateKeyEntry {
                creation_time: SystemTime::now(),
                private_key: entry.private_key_der.to_vec(),
                certificate_chain: entry
                    .certificate_chain
                    .iter()
                    .map(|certificate| jks::Certificate {
                        cert_type: "X.509".to_owned(),
                        content: certificate.clone(),
                    })
                    .collect(),
            },
            entry.key_password.as_bytes(),
        )
        .map_err(|error| SignError::KeystoreWrite(format!("JKS entry: {error}")))?;

    let mut output = Vec::new();
    store
        .store(&mut output, store_password.as_bytes())
        .map_err(|error| SignError::KeystoreWrite(format!("JKS store: {error}")))?;
    Ok(output)
}

fn write_pkcs12(store_password: &str, entry: &KeystoreEntry<'_>) -> Result<Vec<u8>, SignError> {
    let mut rng = rand::thread_rng();
    let mut local_key_id = [0u8; 20];
    rng.fill_bytes(&mut local_key_id);

    let mut bags = Vec::with_capacity(entry.certificate_chain.len() + 1);
    bags.push(SafeBag {
        bag_id: pkcs12::PKCS_12_PKCS8_KEY_BAG_OID,
        // The encoder adds the `[0] EXPLICIT` wrapper around this value.
        bag_value: encrypt_private_key(entry.private_key_der, entry.key_password)?,
        bag_attributes: Some(bag_attributes(entry.alias, &local_key_id)?),
    });
    for certificate in entry.certificate_chain {
        let cert_bag = CertBag {
            cert_id: X509_CERTIFICATE_CERT_TYPE,
            cert_value: OctetString::new(certificate.as_slice())
                .map_err(|error| SignError::KeystoreWrite(error.to_string()))?,
        };
        bags.push(SafeBag {
            bag_id: pkcs12::PKCS_12_CERT_BAG_OID,
            bag_value: cert_bag
                .to_der()
                .map_err(|error| SignError::KeystoreWrite(error.to_string()))?,
            bag_attributes: Some(bag_attributes(entry.alias, &local_key_id)?),
        });
    }

    // SafeContents -> OCTET STRING -> ContentInfo -> AuthenticatedSafe
    let safe_contents: Vec<SafeBag> = bags;
    let safe_contents = safe_contents
        .to_der()
        .map_err(|error| SignError::KeystoreWrite(error.to_string()))?;
    let authenticated_safe: Vec<ContentInfo> = vec![ContentInfo {
        content_type: ID_DATA,
        content: Any::new(Tag::OctetString, safe_contents)
            .map_err(|error| SignError::KeystoreWrite(error.to_string()))?,
    }];
    let authenticated_safe = authenticated_safe
        .to_der()
        .map_err(|error| SignError::KeystoreWrite(error.to_string()))?;

    // The PFX MAC covers the AuthenticatedSafe's DER, i.e. the octets inside
    // `authSafe.content` rather than the enclosing ContentInfo.
    let mac_data = mac_data(store_password, &authenticated_safe)?;

    Pfx {
        version: Version::V3,
        auth_safe: ContentInfo {
            content_type: ID_DATA,
            content: Any::new(Tag::OctetString, authenticated_safe.clone())
                .map_err(|error| SignError::KeystoreWrite(error.to_string()))?,
        },
        mac_data: Some(mac_data),
    }
    .to_der()
    .map_err(|error| SignError::KeystoreWrite(error.to_string()))
}

fn encrypt_private_key(private_key_der: &[u8], key_password: &str) -> Result<Vec<u8>, SignError> {
    use pkcs5::EncryptionScheme;

    let mut rng = rand::thread_rng();
    let mut salt = [0u8; PKCS12_SALT_LEN];
    let mut iv = [0u8; AES_BLOCK_SIZE];
    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut iv);

    let parameters =
        pkcs5::pbes2::Parameters::pbkdf2_sha256_aes256cbc(PKCS12_ITERATIONS, &salt, &iv)
            .map_err(|error| SignError::KeystoreWrite(format!("PBES2 parameters: {error}")))?;
    let algorithm = EncryptionScheme::Pbes2(parameters);
    let ciphertext = algorithm
        .encrypt(key_password.as_bytes(), private_key_der)
        .map_err(|error| SignError::KeystoreWrite(format!("PBES2 encrypt: {error}")))?;

    pkcs8::EncryptedPrivateKeyInfo {
        encryption_algorithm: algorithm,
        encrypted_data: &ciphertext,
    }
    .to_der()
    .map_err(|error| SignError::KeystoreWrite(format!("EncryptedPrivateKeyInfo: {error}")))
}

fn mac_data(store_password: &str, authenticated_safe_der: &[u8]) -> Result<MacData, SignError> {
    let mut rng = rand::thread_rng();
    let mut salt = [0u8; PKCS12_SALT_LEN];
    rng.fill_bytes(&mut salt);

    let key = pkcs12::kdf::derive_key_utf8::<Sha256>(
        store_password,
        &salt,
        pkcs12::kdf::Pkcs12KeyType::Mac,
        PKCS12_ITERATIONS as i32,
        AES_256_KEY_LEN,
    )
    .map_err(|error| SignError::KeystoreWrite(format!("PKCS#12 MAC key: {error}")))?;

    let mut mac = Hmac::<Sha256>::new_from_slice(&key)
        .map_err(|error| SignError::KeystoreWrite(format!("HMAC-SHA256: {error}")))?;
    mac.update(authenticated_safe_der);
    let digest = mac.finalize().into_bytes();

    Ok(MacData {
        mac: DigestInfo {
            algorithm: AlgorithmIdentifierOwned {
                oid: SHA256,
                // The JDK writes an explicit NULL here.
                parameters: Some(der::Any::from(der::asn1::Null)),
            },
            digest: OctetString::new(digest.to_vec())
                .map_err(|error| SignError::KeystoreWrite(error.to_string()))?,
        },
        mac_salt: OctetString::new(salt.to_vec())
            .map_err(|error| SignError::KeystoreWrite(error.to_string()))?,
        iterations: PKCS12_ITERATIONS as i32,
    })
}

fn bag_attributes(alias: &str, local_key_id: &[u8]) -> Result<Attributes, SignError> {
    let friendly_name = der::asn1::BmpString::from_utf8(alias)
        .map_err(|error| SignError::KeystoreWrite(format!("friendlyName: {error}")))?;
    SetOfVec::try_from(vec![
        Attribute {
            oid: FRIENDLY_NAME,
            values: attribute_values(&friendly_name)?,
        },
        Attribute {
            oid: LOCAL_KEY_ID,
            values: attribute_values(
                &OctetString::new(local_key_id.to_vec())
                    .map_err(|error| SignError::KeystoreWrite(error.to_string()))?,
            )?,
        },
    ])
    .map_err(|error| SignError::KeystoreWrite(format!("bag attributes: {error}")))
}

fn attribute_values<T: Encode>(value: &T) -> Result<SetOfVec<AttributeValue>, SignError> {
    let encoded = value
        .to_der()
        .map_err(|error| SignError::KeystoreWrite(error.to_string()))?;
    let any =
        Any::from_der(&encoded).map_err(|error| SignError::KeystoreWrite(error.to_string()))?;
    SetOfVec::try_from(vec![any])
        .map_err(|error| SignError::KeystoreWrite(format!("attribute value: {error}")))
}
