use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum SignError {
    #[error("unsupported signing algorithm '{0}'")]
    UnsupportedAlgorithm(String),

    #[error("signing material '{0}' must not be empty")]
    EmptyMaterial(&'static str),

    // ZIP errors
    #[error("invalid ZIP file: {0}")]
    InvalidZip(&'static str),

    // Digest errors
    #[error("digest error: {0}")]
    DigestError(String),

    // Keystore errors
    #[error("keystore load failed: {0}")]
    KeystoreLoadFailed(&'static str),

    #[error("keystore parse error: {0}")]
    KeystoreParseError(String),

    #[error("no private key found in keystore")]
    NoPrivateKey,

    #[error("private key alias '{alias}' was not found; available aliases: {available:?}")]
    KeyAliasNotFound {
        alias: String,
        available: Vec<String>,
    },

    #[error("no certificate found in keystore")]
    NoCertificate,

    // Signing errors
    #[error("signing failed: {0}")]
    SigningFailed(String),

    #[error("verification failed: {0}")]
    VerificationFailed(String),

    #[error("unsupported operation: {0}")]
    UnsupportedOperation(String),

    #[error("PKCS#8 key loading failed: {0}")]
    Pkcs8Error(String),

    // PEM errors
    #[error("PEM decode error: {0}")]
    PemError(String),

    // DER / ASN.1 errors
    #[error("DER encoding error: {0}")]
    DerError(String),

    // Config / password decryption errors
    #[error("config error: {0}")]
    Config(String),

    #[error("HNP '{0}' is not described in module.json module.hnpPackages")]
    HnpNotDeclared(String),

    #[error("invalid HNP archive '{name}': {message}")]
    InvalidHnp { name: String, message: String },

    // IO errors
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("io error reading '{path}': {source}")]
    IoPath {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}
