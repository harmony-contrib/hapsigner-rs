//! Reusable Java-free OpenHarmony HAP/HSP signing library.
//!
//! The core API accepts caller-provided signing material and has no knowledge
//! of Hvigor projects or configuration files. The optional development adapter
//! keeps the `hap-sign` QEMU workflow on the same signing implementation.

mod algorithm;
mod application;
mod code_sign;
#[cfg(feature = "development")]
pub mod development;
mod digest;
mod error;
mod inspector;
mod keystore;
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
#[cfg(feature = "development")]
pub use development::{DevelopmentMaterialBuilder, DevelopmentProfileOptions, DevelopmentSigner};
pub use error::SignError;
pub use inspector::{SigningBlockEntry, SigningBlockInfo, SigningBlockInspector, SigningBlockType};
pub use keystore::SigningKey;
pub use material::{FileSigningMaterial, KeystoreMaterial, Pkcs12Material, SigningMaterial};
pub use profile::{ProfileSigner, ProfileVerification, ProfileVerifier};
pub use remote::ExternalSigner;
pub use signer::{HapSigner, SignOptions, DEFAULT_COMPATIBLE_VERSION};
pub use verifier::{ApplicationVerification, ApplicationVerifier};
