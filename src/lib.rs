//! Reusable Java-free OpenHarmony HAP/HSP signing library.
//!
//! The core API accepts caller-provided signing material and has no knowledge
//! of Hvigor projects or configuration files. The optional development adapter
//! keeps the `hap-sign` QEMU workflow on the same signing implementation.

mod algorithm;
mod application;
pub mod cert_tools;
mod certificate;
mod code_sign;
mod csr;
#[cfg(feature = "development")]
pub mod development;
mod digest;
mod dn;
mod error;
mod inspector;
mod keypair;
mod keystore;
mod keystore_write;
mod material;
mod page_info;
mod pkcs7;
mod profile;
mod profile_content;
mod remote;
mod signer;
mod signing_block;
mod verifier;
mod zip;

pub use algorithm::{ContentDigestAlgorithm, SigningAlgorithm};
pub use application::InputFormat;
pub use cert_tools::{
    generate_certificate, generate_csr, generate_end_certificate, generate_key_pair_entry,
    generate_root_ca, generate_sub_ca, parse_extended_key_usage, parse_extended_key_usage_checked,
    parse_key_usage, parse_key_usage_checked, placeholder_certificate, public_key_from_der,
    CertificateOptions, CsrParameters, IssuanceParameters, KeyPairParameters, CA_VALIDITY_DAYS,
    END_CERTIFICATE_VALIDITY_DAYS,
};
pub use certificate::{
    build_certificate, CertificateLevel, CertificateParameters, CertificateSignatureAlgorithm,
    IssuingKey, SigningCapability, SigningKeyKind, CERTIFICATE_SIGNING_CAPABILITY_OID,
};
pub use csr::{build_certificate_request, certificate_request_pem, CERTIFICATE_REQUEST_PEM_LABEL};
#[cfg(feature = "development")]
pub use development::{DevelopmentMaterialBuilder, DevelopmentProfileOptions, DevelopmentSigner};
pub use dn::parse_distinguished_name;
pub use error::SignError;
pub use inspector::{SigningBlockEntry, SigningBlockInfo, SigningBlockInspector, SigningBlockType};
pub use keypair::{generate_key_pair, GeneratedKeyPair, KeyAlgorithm, KeySize};
pub use keystore::SigningKey;
pub use keystore_write::{write_keystore, KeystoreEntry, KeystoreFormat};
pub use material::{FileSigningMaterial, KeystoreMaterial, Pkcs12Material, SigningMaterial};
pub use profile::{ProfileSigner, ProfileVerification, ProfileVerifier};
pub use remote::ExternalSigner;
pub use signer::{HapSigner, SignOptions, DEFAULT_COMPATIBLE_VERSION};
pub use verifier::{ApplicationVerification, ApplicationVerifier};
pub use x509_cert::ext::pkix::{KeyUsage, KeyUsages};
