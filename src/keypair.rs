//! Key pair generation for the official `generate-keypair` and `generate-ca`
//! workflows.
//!
//! Accepted algorithm names and sizes mirror `CmdUtil.judgeAlgType` /
//! `CmdUtil.judgeSize` / `KeyPairTools.generateKeyPair`: `RSA` with a
//! 2048/3072/4096-bit modulus, or `ECC` on `NIST-P-256` / `NIST-P-384`.

use std::fmt;
use std::str::FromStr;

use zeroize::Zeroizing;

use crate::error::SignError;

/// Key algorithm accepted by official `-keyAlg`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyAlgorithm {
    Rsa,
    Ecc,
}

impl KeyAlgorithm {
    /// Spelling used by the generated certificate's public-key algorithm.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rsa => "RSA",
            Self::Ecc => "ECC",
        }
    }
}

impl fmt::Display for KeyAlgorithm {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for KeyAlgorithm {
    type Err = SignError;

    /// `CmdUtil.judgeAlgType` compares with `equalsIgnoreCase`, so `rsa` and
    /// `ecc` are accepted as well as the canonical upper-case spellings.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let trimmed = value.trim();
        if trimmed.eq_ignore_ascii_case("RSA") {
            Ok(Self::Rsa)
        } else if trimmed.eq_ignore_ascii_case("ECC") {
            Ok(Self::Ecc)
        } else {
            Err(SignError::UnsupportedKeyAlgorithm(value.to_owned()))
        }
    }
}

/// Key size accepted by official `-keySize`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeySize {
    Rsa2048,
    Rsa3072,
    Rsa4096,
    EccP256,
    EccP384,
}

impl KeySize {
    /// Spelling used on the command line and stored back by `convertAlgSize`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rsa2048 => "2048",
            Self::Rsa3072 => "3072",
            Self::Rsa4096 => "4096",
            Self::EccP256 => "NIST-P-256",
            Self::EccP384 => "NIST-P-384",
        }
    }

    /// Integer handed to `KeyPairTools.generateKeyPair`, i.e. the value
    /// `CmdUtil.convertAlgSize` derives from the command-line spelling.
    pub const fn bits(self) -> u32 {
        match self {
            Self::Rsa2048 => 2048,
            Self::Rsa3072 => 3072,
            Self::Rsa4096 => 4096,
            Self::EccP256 => 256,
            Self::EccP384 => 384,
        }
    }

    pub const fn algorithm(self) -> KeyAlgorithm {
        match self {
            Self::Rsa2048 | Self::Rsa3072 | Self::Rsa4096 => KeyAlgorithm::Rsa,
            Self::EccP256 | Self::EccP384 => KeyAlgorithm::Ecc,
        }
    }

    /// Resolve a command-line `-keySize` for a given `-keyAlg`.
    ///
    /// `CmdUtil.judgeSize` requires one of the five literal spellings and then
    /// rejects a size that belongs to the other algorithm.
    pub fn parse(value: &str, algorithm: KeyAlgorithm) -> Result<Self, SignError> {
        let size = match value {
            "2048" => Self::Rsa2048,
            "3072" => Self::Rsa3072,
            "4096" => Self::Rsa4096,
            "NIST-P-256" => Self::EccP256,
            "NIST-P-384" => Self::EccP384,
            other => {
                return Err(SignError::UnsupportedKeySize {
                    algorithm: algorithm.to_string(),
                    size: other.to_owned(),
                });
            }
        };
        if size.algorithm() == algorithm {
            Ok(size)
        } else {
            Err(SignError::UnsupportedKeySize {
                algorithm: algorithm.to_string(),
                size: value.to_owned(),
            })
        }
    }
}

impl fmt::Display for KeySize {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A freshly generated key pair in the encodings the rest of the crate expects.
///
/// The private key is PKCS#8 DER and the public key is SubjectPublicKeyInfo
/// DER, matching `KeyPair.getPrivate().getEncoded()` and
/// `KeyPair.getPublic().getEncoded()` in official hapsigner.
pub struct GeneratedKeyPair {
    private_key_der: Zeroizing<Vec<u8>>,
    public_key_der: Vec<u8>,
    size: KeySize,
}

impl GeneratedKeyPair {
    pub fn private_key_der(&self) -> &[u8] {
        &self.private_key_der
    }

    pub fn public_key_der(&self) -> &[u8] {
        &self.public_key_der
    }

    pub fn size(&self) -> KeySize {
        self.size
    }

    pub fn algorithm(&self) -> KeyAlgorithm {
        self.size.algorithm()
    }
}

impl fmt::Debug for GeneratedKeyPair {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never render the private key.
        formatter
            .debug_struct("GeneratedKeyPair")
            .field("private_key_der", &"<redacted>")
            .field("public_key_der_len", &self.public_key_der.len())
            .field("size", &self.size)
            .finish()
    }
}

/// Generate a key pair using the platform CSPRNG.
pub fn generate_key_pair(size: KeySize) -> Result<GeneratedKeyPair, SignError> {
    let mut rng = rand::thread_rng();
    match size {
        KeySize::Rsa2048 | KeySize::Rsa3072 | KeySize::Rsa4096 => {
            use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};

            let private = rsa::RsaPrivateKey::new(&mut rng, size.bits() as usize)
                .map_err(|error| SignError::CertificateBuild(format!("RSA keygen: {error}")))?;
            let private_key_der = private
                .to_pkcs8_der()
                .map_err(|error| SignError::Pkcs8Error(error.to_string()))?;
            let public_key_der = rsa::RsaPublicKey::from(&private)
                .to_public_key_der()
                .map_err(|error| SignError::DerError(error.to_string()))?;
            Ok(GeneratedKeyPair {
                private_key_der: Zeroizing::new(private_key_der.as_bytes().to_vec()),
                public_key_der: public_key_der.as_bytes().to_vec(),
                size,
            })
        }
        KeySize::EccP256 => {
            let secret = p256::SecretKey::random(&mut rng);
            encode_ecc_key_pair(&secret, size)
        }
        KeySize::EccP384 => {
            let secret = p384::SecretKey::random(&mut rng);
            encode_ecc_key_pair(&secret, size)
        }
    }
}

/// Encode a P-256 or P-384 secret key as PKCS#8 + SubjectPublicKeyInfo.
fn encode_ecc_key_pair<C>(
    secret: &elliptic_curve::SecretKey<C>,
    size: KeySize,
) -> Result<GeneratedKeyPair, SignError>
where
    C: elliptic_curve::CurveArithmetic,
    elliptic_curve::SecretKey<C>: pkcs8::EncodePrivateKey,
    elliptic_curve::PublicKey<C>: pkcs8::EncodePublicKey,
{
    use pkcs8::{EncodePrivateKey, EncodePublicKey};

    let private_key_der = secret
        .to_pkcs8_der()
        .map_err(|error| SignError::Pkcs8Error(error.to_string()))?;
    let public_key_der = secret
        .public_key()
        .to_public_key_der()
        .map_err(|error| SignError::DerError(error.to_string()))?;
    Ok(GeneratedKeyPair {
        private_key_der: Zeroizing::new(private_key_der.as_bytes().to_vec()),
        public_key_der: public_key_der.as_bytes().to_vec(),
        size,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::Decode;
    use spki::SubjectPublicKeyInfoOwned;

    #[test]
    fn parses_official_algorithm_and_size_spellings() {
        assert_eq!(KeyAlgorithm::from_str("RSA").unwrap(), KeyAlgorithm::Rsa);
        assert_eq!(KeyAlgorithm::from_str("ecc").unwrap(), KeyAlgorithm::Ecc);
        assert!(KeyAlgorithm::from_str("DSA").is_err());

        assert_eq!(
            KeySize::parse("NIST-P-256", KeyAlgorithm::Ecc).unwrap(),
            KeySize::EccP256
        );
        assert_eq!(
            KeySize::parse("4096", KeyAlgorithm::Rsa).unwrap(),
            KeySize::Rsa4096
        );
    }

    #[test]
    fn rejects_sizes_that_belong_to_the_other_algorithm() {
        for (value, algorithm) in [
            ("2048", KeyAlgorithm::Ecc),
            ("NIST-P-256", KeyAlgorithm::Rsa),
            ("1024", KeyAlgorithm::Rsa),
            ("nist-p-256", KeyAlgorithm::Ecc),
        ] {
            assert!(
                matches!(
                    KeySize::parse(value, algorithm),
                    Err(SignError::UnsupportedKeySize { .. })
                ),
                "{value} for {algorithm} must be rejected"
            );
        }
    }

    #[test]
    fn generated_public_key_matches_the_declared_size() {
        let pair = generate_key_pair(KeySize::EccP256).expect("P-256 key pair");
        assert_eq!(pair.algorithm(), KeyAlgorithm::Ecc);
        let spki = SubjectPublicKeyInfoOwned::from_der(pair.public_key_der()).expect("SPKI");
        // Uncompressed P-256 point: 0x04 || X(32) || Y(32).
        assert_eq!(spki.subject_public_key.raw_bytes().len(), 65);
        assert!(pair.private_key_der().starts_with(&[0x30]));
    }

    #[test]
    fn generates_rsa_key_pairs_of_the_requested_modulus() {
        let pair = generate_key_pair(KeySize::Rsa2048).expect("RSA key pair");
        assert_eq!(pair.algorithm(), KeyAlgorithm::Rsa);
        use pkcs8::DecodePrivateKey;
        use rsa::traits::PublicKeyParts;

        let private =
            rsa::RsaPrivateKey::from_pkcs8_der(pair.private_key_der()).expect("PKCS#8 private key");
        assert_eq!(private.n().bits(), 2048);
    }

    #[test]
    fn debug_never_renders_private_key_material() {
        let pair = generate_key_pair(KeySize::EccP256).expect("P-256 key pair");
        let rendered = format!("{pair:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains(&format!("{:?}", pair.private_key_der())));
    }
}
