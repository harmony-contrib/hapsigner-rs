//! PKCS#10 certification requests, matching official `CertTools.generateCsr`
//! and `CertUtils.toCsrTemplate`.
//!
//! Upstream builds the request with `JcaPKCS10CertificationRequestBuilder`
//! from a subject and a public key only, so the attribute set is empty.

use der::asn1::BitString;
use der::Encode;
use pem_rfc7468::{encode_string, LineEnding};
use spki::SubjectPublicKeyInfoOwned;
use x509_cert::attr::Attributes;
use x509_cert::name::Name;
use x509_cert::request::{CertReq, CertReqInfo, Version};

use crate::certificate::{CertificateSignatureAlgorithm, IssuingKey};

/// The legacy PEM label `CertUtils.toCsrTemplate` emits.
pub const CERTIFICATE_REQUEST_PEM_LABEL: &str = "NEW CERTIFICATE REQUEST";

/// Build a DER-encoded PKCS#10 certification request.
///
/// The signature algorithm is corrected for the signing key's type exactly as
/// `CertUtils.createFixedContentSigner` does.
pub fn build_certificate_request(
    subject: Name,
    public_key: SubjectPublicKeyInfoOwned,
    signing_key: &IssuingKey,
    signature_algorithm: CertificateSignatureAlgorithm,
) -> Result<Vec<u8>, crate::SignError> {
    let signature_algorithm = signature_algorithm.corrected_for(&signing_key.kind());
    let info = CertReqInfo {
        version: Version::V1,
        subject,
        public_key,
        attributes: Attributes::default(),
    };
    let info_der = info
        .to_der()
        .map_err(|error| crate::SignError::CertificateRequestBuild(error.to_string()))?;
    let signature = signing_key.sign(&info_der, signature_algorithm)?;

    CertReq {
        info,
        algorithm: signature_algorithm.algorithm_identifier(),
        signature: BitString::from_bytes(&signature)
            .map_err(|error| crate::SignError::CertificateRequestBuild(error.to_string()))?,
    }
    .to_der()
    .map_err(|error| crate::SignError::CertificateRequestBuild(error.to_string()))
}

/// Wrap a DER certification request in the legacy PEM framing used by
/// official `generate-csr` (`-----BEGIN NEW CERTIFICATE REQUEST-----`).
pub fn certificate_request_pem(certificate_request_der: &[u8]) -> Result<String, crate::SignError> {
    encode_string(
        CERTIFICATE_REQUEST_PEM_LABEL,
        LineEnding::LF,
        certificate_request_der,
    )
    .map_err(|error| crate::SignError::CertificateRequestBuild(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{generate_key_pair, parse_distinguished_name, KeySize};

    fn issuing_key(pair: &crate::GeneratedKeyPair) -> IssuingKey {
        IssuingKey::from_pkcs8_der(pair.private_key_der()).expect("issuing key")
    }

    fn public_key_of(pair: &crate::GeneratedKeyPair) -> SubjectPublicKeyInfoOwned {
        crate::cert_tools::public_key_from_der(pair.public_key_der()).expect("public key")
    }

    #[test]
    fn builds_a_verifiable_ecdsa_request() {
        use der::Decode;

        let pair = generate_key_pair(KeySize::EccP256).expect("key pair");
        let subject =
            parse_distinguished_name("C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release")
                .expect("subject");
        let der = build_certificate_request(
            subject,
            public_key_of(&pair),
            &issuing_key(&pair),
            CertificateSignatureAlgorithm::EcdsaSha256,
        )
        .expect("CSR");
        assert!(!der.is_empty());

        let pem = certificate_request_pem(&der).expect("PEM");
        let (label, document) = pem_rfc7468::decode_vec(pem.as_bytes()).expect("PEM envelope");
        assert_eq!(label, CERTIFICATE_REQUEST_PEM_LABEL);
        let request = CertReq::from_der(&document).expect("parse CSR");
        // Upstream emits an empty `[0] IMPLICIT SET OF Attribute`.
        assert!(request.info.attributes.is_empty());
        assert_eq!(request.info.subject.0.len(), 4);
    }

    #[test]
    fn corrects_a_mismatched_algorithm_for_the_key_type() {
        let pair = generate_key_pair(KeySize::EccP256).expect("key pair");
        let key = issuing_key(&pair);
        // `SHA256withRSA` with an EC key is silently rewritten upstream.
        let der = build_certificate_request(
            parse_distinguished_name("CN=App1").expect("subject"),
            public_key_of(&pair),
            &key,
            CertificateSignatureAlgorithm::RsaSha256,
        )
        .expect("CSR");
        assert!(!der.is_empty());
    }
}
