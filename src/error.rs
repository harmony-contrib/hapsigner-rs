use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum SignError {
    #[error("unsupported signing algorithm '{0}'")]
    UnsupportedAlgorithm(String),

    #[error("signing material '{0}' must not be empty")]
    EmptyMaterial(&'static str),

    // Key / certificate generation errors
    #[error("unsupported key algorithm '{0}'; expected RSA or ECC")]
    UnsupportedKeyAlgorithm(String),

    #[error("key algorithm '{algorithm}' does not support size '{size}'")]
    UnsupportedKeySize { algorithm: String, size: String },

    #[error("key size '{0}' must be an integer of at most 10 digits")]
    InvalidKeySize(String),

    #[error("key alias '{alias}' already exists in {path} and cannot be overwritten")]
    KeyAliasExists { alias: String, path: String },

    #[error("distinguished name '{0}' must use the \"X=xx,XX=xxx\" form")]
    InvalidDistinguishedName(String),

    #[error("certificate generation failed: {0}")]
    CertificateBuild(String),

    #[error("PKCS#10 request generation failed: {0}")]
    CertificateRequestBuild(String),

    #[error("keystore format for '{0}' must be .jks, .p12, or .pfx")]
    UnsupportedKeystoreFormat(String),

    #[error("keystore write failed: {0}")]
    KeystoreWrite(String),

    #[error("unsupported key usage or extended key usage value '{0}'")]
    UnsupportedKeyUsage(String),

    #[error("parameter '{parameter}' is required for {command}")]
    MissingParameter {
        command: &'static str,
        parameter: &'static str,
    },

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
