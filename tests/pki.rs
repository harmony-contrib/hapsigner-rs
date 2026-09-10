//! Key, CSR, and certificate generation, including a full signing lifecycle
//! that never leaves Rust.
//!
//! `exports_artifacts_for_external_tooling` writes a keystore, a chain, and a
//! CSR to the directory named by `HAPSIGNER_INTEROP_DIR` so they can be checked
//! with `keytool`, `openssl`, and `hap-sign-tool.jar`. It is a no-op when the
//! variable is unset.

use std::fs;
use std::path::PathBuf;
use std::str::FromStr;

use der::{Decode, Encode, EncodePem};
use hapsigner::cert_tools::{
    generate_certificate, generate_csr, generate_end_certificate, generate_root_ca,
    generate_sub_ca, public_key_from_der, CertificateOptions, CsrParameters, IssuanceParameters,
    CA_VALIDITY_DAYS, END_CERTIFICATE_VALIDITY_DAYS,
};
use hapsigner::{
    generate_key_pair, parse_distinguished_name, write_keystore, CertificateSignatureAlgorithm,
    GeneratedKeyPair, HapSigner, InputFormat, IssuingKey, KeySize, KeystoreEntry, KeystoreFormat,
    ProfileSigner, ProfileVerifier, SignOptions, SigningCapability, SigningKey, SigningMaterial,
    CERTIFICATE_SIGNING_CAPABILITY_OID,
};
use x509_cert::ext::pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectKeyIdentifier};
use x509_cert::ext::Extension as X509Extension;
use x509_cert::name::Name;
use x509_cert::Certificate;

const STORE_PASSWORD: &str = "123456";
const KEY_PASSWORD: &str = "123456";
const ALIAS: &str = "oh-app1-key-v1";

fn subject() -> Name {
    parse_distinguished_name("C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release")
        .expect("subject")
}

fn ca_subject() -> Name {
    parse_distinguished_name("C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Root CA")
        .expect("CA subject")
}

fn issuing_key(pair: &GeneratedKeyPair) -> IssuingKey {
    IssuingKey::from_pkcs8_der(pair.private_key_der()).expect("issuing key")
}

fn parse(der: &[u8]) -> Certificate {
    Certificate::from_der(der).expect("parse certificate")
}

fn extension(certificate: &Certificate, oid: const_oid::ObjectIdentifier) -> &X509Extension {
    certificate
        .tbs_certificate
        .extensions
        .as_ref()
        .expect("extensions")
        .iter()
        .find(|extension| extension.extn_id == oid)
        .unwrap_or_else(|| panic!("extension {oid} is missing"))
}

/// Decode an extension's value, which is DER inside the enclosing OCTET STRING.
fn decode_extension<T: der::DecodeOwned>(
    certificate: &Certificate,
    oid: const_oid::ObjectIdentifier,
) -> T {
    T::from_der(extension(certificate, oid).extn_value.as_bytes())
        .unwrap_or_else(|error| panic!("decode extension {oid}: {error}"))
}

fn has_extension(certificate: &Certificate, oid: const_oid::ObjectIdentifier) -> bool {
    certificate
        .tbs_certificate
        .extensions
        .as_ref()
        .expect("extensions")
        .iter()
        .any(|extension| extension.extn_id == oid)
}

fn extension_order(certificate: &Certificate) -> Vec<String> {
    certificate
        .tbs_certificate
        .extensions
        .as_ref()
        .expect("extensions")
        .iter()
        .map(|extension| extension.extn_id.to_string())
        .collect()
}

const ID_CE_SUBJECT_KEY_IDENTIFIER: const_oid::ObjectIdentifier =
    const_oid::db::rfc5280::ID_CE_SUBJECT_KEY_IDENTIFIER;
const ID_CE_AUTHORITY_KEY_IDENTIFIER: const_oid::ObjectIdentifier =
    const_oid::db::rfc5280::ID_CE_AUTHORITY_KEY_IDENTIFIER;
const ID_CE_BASIC_CONSTRAINTS: const_oid::ObjectIdentifier =
    const_oid::db::rfc5280::ID_CE_BASIC_CONSTRAINTS;
const ID_CE_KEY_USAGE: const_oid::ObjectIdentifier = const_oid::db::rfc5280::ID_CE_KEY_USAGE;
const ID_CE_EXT_KEY_USAGE: const_oid::ObjectIdentifier =
    const_oid::db::rfc5280::ID_CE_EXT_KEY_USAGE;

#[test]
fn key_pair_round_trips_through_both_keystore_formats() {
    for (format, extension) in [
        (KeystoreFormat::Jks, "jks"),
        (KeystoreFormat::Pkcs12, "p12"),
    ] {
        let pair = generate_key_pair(KeySize::EccP256).expect("key pair");
        let store = write_keystore(
            format,
            STORE_PASSWORD,
            &KeystoreEntry {
                alias: ALIAS,
                key_password: KEY_PASSWORD,
                private_key_der: pair.private_key_der(),
                certificate_chain: &[placeholder(&pair)],
            },
        )
        .unwrap_or_else(|error| panic!("{extension} write: {error}"));

        let loaded = SigningKey::from_keystore(&store, STORE_PASSWORD, ALIAS, KEY_PASSWORD)
            .unwrap_or_else(|error| panic!("{extension} read: {error}"));

        assert_eq!(
            loaded.private_key_der,
            pair.private_key_der(),
            "{extension} private key does not round-trip"
        );
        assert_eq!(loaded.cert_chain.len(), 1);
    }
}

#[test]
fn jks_writer_refuses_a_short_store_password() {
    let pair = generate_key_pair(KeySize::EccP256).expect("key pair");
    let error = write_keystore(
        KeystoreFormat::Jks,
        "short",
        &KeystoreEntry {
            alias: ALIAS,
            key_password: "",
            private_key_der: pair.private_key_der(),
            certificate_chain: &[placeholder(&pair)],
        },
    )
    .expect_err("a five-character JKS store password must be rejected");
    assert!(matches!(error, hapsigner::SignError::KeystoreWrite(_)));
}

#[test]
fn jks_writer_accepts_an_empty_key_password() {
    let pair = generate_key_pair(KeySize::EccP256).expect("key pair");
    let store = write_keystore(
        KeystoreFormat::Jks,
        STORE_PASSWORD,
        &KeystoreEntry {
            alias: ALIAS,
            key_password: "",
            private_key_der: pair.private_key_der(),
            certificate_chain: &[placeholder(&pair)],
        },
    )
    .expect("JKS write");
    let loaded = SigningKey::from_jks(&store, STORE_PASSWORD, ALIAS, "").expect("JKS read");
    assert_eq!(loaded.private_key_der, pair.private_key_der());
}

#[test]
fn keystore_format_is_selected_by_extension() {
    for (name, expected) in [
        ("app.jks", KeystoreFormat::Jks),
        ("app.JKS", KeystoreFormat::Jks),
        ("app.p12", KeystoreFormat::Pkcs12),
        ("app.PFX", KeystoreFormat::Pkcs12),
    ] {
        assert_eq!(
            KeystoreFormat::from_path(&PathBuf::from(name)).expect(name),
            expected,
            "{name}"
        );
    }
    assert!(KeystoreFormat::from_path(&PathBuf::from("app.pem")).is_err());
    assert!(KeystoreFormat::from_path(&PathBuf::from("app")).is_err());
}

/// The self-signed placeholder `generate-keypair` stores alongside a new key.
fn placeholder(pair: &GeneratedKeyPair) -> Vec<u8> {
    hapsigner::placeholder_certificate(pair, ALIAS).expect("placeholder certificate")
}

#[test]
fn root_ca_certificate_matches_upstream_extension_contract() {
    let root = generate_key_pair(KeySize::EccP384).expect("root key");
    let certificate = parse(
        &generate_root_ca(
            &IssuanceParameters {
                subject: ca_subject(),
                issuer: ca_subject(),
                subject_public_key: public_key_from_der(root.public_key_der()).expect("spki"),
                issuer_key: &issuing_key(&root),
                issuer_public_key: None,
                signature_algorithm: CertificateSignatureAlgorithm::EcdsaSha384,
                validity_days: CA_VALIDITY_DAYS,
            },
            Some(2),
        )
        .expect("root CA"),
    );

    // subjectKeyIdentifier, basicConstraints, keyUsage; no authorityKeyIdentifier.
    assert_eq!(
        extension_order(&certificate),
        [
            ID_CE_SUBJECT_KEY_IDENTIFIER,
            ID_CE_BASIC_CONSTRAINTS,
            ID_CE_KEY_USAGE,
        ]
        .map(|oid| oid.to_string())
    );

    let usage = decode_extension::<KeyUsage>(&certificate, ID_CE_KEY_USAGE);
    assert!(usage.key_cert_sign());
    assert!(usage.crl_sign());
    assert!(extension(&certificate, ID_CE_KEY_USAGE).critical);

    let constraints = decode_extension::<BasicConstraints>(&certificate, ID_CE_BASIC_CONSTRAINTS);
    assert!(constraints.ca);
    assert_eq!(constraints.path_len_constraint, Some(2));
    assert!(extension(&certificate, ID_CE_BASIC_CONSTRAINTS).critical);

    assert!(!extension(&certificate, ID_CE_SUBJECT_KEY_IDENTIFIER).critical);
    // Self-signed: issuer equals subject.
    assert_eq!(
        certificate.tbs_certificate.issuer,
        certificate.tbs_certificate.subject
    );
}

#[test]
fn sub_ca_certificate_carries_an_authority_key_identifier() {
    let root = generate_key_pair(KeySize::EccP256).expect("root key");
    let sub = generate_key_pair(KeySize::EccP256).expect("sub key");
    let root_spki = public_key_from_der(root.public_key_der()).expect("spki");

    let certificate = parse(
        &generate_sub_ca(
            &IssuanceParameters {
                subject: parse_distinguished_name("CN=OpenHarmony Application CA")
                    .expect("subject"),
                issuer: ca_subject(),
                subject_public_key: public_key_from_der(sub.public_key_der()).expect("spki"),
                issuer_key: &issuing_key(&root),
                issuer_public_key: Some(root_spki),
                signature_algorithm: CertificateSignatureAlgorithm::EcdsaSha256,
                validity_days: CA_VALIDITY_DAYS,
            },
            Some(0),
        )
        .expect("sub CA"),
    );

    assert!(has_extension(&certificate, ID_CE_AUTHORITY_KEY_IDENTIFIER));
    // The key identifier is the SHA-1 of the issuer's public key bits.
    let authority = decode_extension::<x509_cert::ext::pkix::AuthorityKeyIdentifier>(
        &certificate,
        ID_CE_AUTHORITY_KEY_IDENTIFIER,
    );
    let subject_key =
        decode_extension::<SubjectKeyIdentifier>(&certificate, ID_CE_SUBJECT_KEY_IDENTIFIER);
    assert_ne!(
        authority.key_identifier.expect("key identifier").as_bytes(),
        subject_key.0.as_bytes(),
        "a sub-CA key identifier must come from the issuer, not the subject"
    );
}

#[test]
fn end_entity_certificates_differ_only_in_signing_capability() {
    let root = generate_key_pair(KeySize::EccP256).expect("root key");
    let leaf = generate_key_pair(KeySize::EccP256).expect("leaf key");
    let root_spki = public_key_from_der(root.public_key_der()).expect("spki");
    let leaf_spki = public_key_from_der(leaf.public_key_der()).expect("spki");

    let parameters = IssuanceParameters {
        subject: subject(),
        issuer: ca_subject(),
        subject_public_key: leaf_spki,
        issuer_key: &issuing_key(&root),
        issuer_public_key: Some(root_spki),
        signature_algorithm: CertificateSignatureAlgorithm::EcdsaSha256,
        validity_days: END_CERTIFICATE_VALIDITY_DAYS,
    };

    let application = parse(
        &generate_end_certificate(&parameters, SigningCapability::Application).expect("app cert"),
    );
    let profile = parse(
        &generate_end_certificate(&parameters, SigningCapability::Profile).expect("profile cert"),
    );

    for certificate in [&application, &profile] {
        assert_eq!(
            extension_order(certificate),
            [
                ID_CE_SUBJECT_KEY_IDENTIFIER,
                ID_CE_BASIC_CONSTRAINTS,
                ID_CE_KEY_USAGE,
                ID_CE_EXT_KEY_USAGE,
                CERTIFICATE_SIGNING_CAPABILITY_OID,
            ]
            .map(|oid| oid.to_string())
        );
        // End entities never carry an authority key identifier upstream.
        assert!(!has_extension(certificate, ID_CE_AUTHORITY_KEY_IDENTIFIER));

        let constraints =
            decode_extension::<BasicConstraints>(certificate, ID_CE_BASIC_CONSTRAINTS);
        assert!(!constraints.ca);
        assert_eq!(constraints.path_len_constraint, None);
        assert!(!extension(certificate, ID_CE_BASIC_CONSTRAINTS).critical);

        let usage = decode_extension::<KeyUsage>(certificate, ID_CE_KEY_USAGE);
        assert!(usage.digital_signature());
        assert!(!usage.key_cert_sign());

        let extended = decode_extension::<ExtendedKeyUsage>(certificate, ID_CE_EXT_KEY_USAGE);
        assert_eq!(extended.0, vec![const_oid::db::rfc5280::ID_KP_CODE_SIGNING]);
        assert!(!extension(certificate, ID_CE_EXT_KEY_USAGE).critical);

        let capability = extension(certificate, CERTIFICATE_SIGNING_CAPABILITY_OID);
        assert!(!capability.critical);
    }

    assert_eq!(
        extension(&application, CERTIFICATE_SIGNING_CAPABILITY_OID)
            .extn_value
            .as_bytes(),
        SigningCapability::Application.value()
    );
    assert_eq!(
        extension(&profile, CERTIFICATE_SIGNING_CAPABILITY_OID)
            .extn_value
            .as_bytes(),
        SigningCapability::Profile.value()
    );
}

#[test]
fn certificate_signing_algorithm_is_corrected_for_the_key_type() {
    let root = generate_key_pair(KeySize::EccP256).expect("root key");
    let certificate = parse(
        &generate_root_ca(
            &IssuanceParameters {
                subject: ca_subject(),
                issuer: ca_subject(),
                subject_public_key: public_key_from_der(root.public_key_der()).expect("spki"),
                issuer_key: &issuing_key(&root),
                issuer_public_key: None,
                // An EC key with an RSA algorithm name is silently rewritten.
                signature_algorithm: CertificateSignatureAlgorithm::RsaSha256,
                validity_days: CA_VALIDITY_DAYS,
            },
            Some(0),
        )
        .expect("root CA"),
    );
    assert_eq!(
        certificate.signature_algorithm.oid,
        const_oid::db::rfc5912::ECDSA_WITH_SHA_256
    );
    // BouncyCastle omits the parameters field for ECDSA identifiers.
    assert!(certificate.signature_algorithm.parameters.is_none());
}

#[test]
fn rsa_issuer_signs_with_pkcs1v15_and_a_null_parameter() {
    let root = generate_key_pair(KeySize::Rsa2048).expect("RSA key");
    let certificate = parse(
        &generate_root_ca(
            &IssuanceParameters {
                subject: ca_subject(),
                issuer: ca_subject(),
                subject_public_key: public_key_from_der(root.public_key_der()).expect("spki"),
                issuer_key: &issuing_key(&root),
                issuer_public_key: None,
                signature_algorithm: CertificateSignatureAlgorithm::RsaSha256,
                validity_days: CA_VALIDITY_DAYS,
            },
            Some(0),
        )
        .expect("RSA root CA"),
    );
    assert_eq!(
        certificate.signature_algorithm.oid,
        const_oid::db::rfc5912::SHA_256_WITH_RSA_ENCRYPTION
    );
    // RSA PKCS#1 v1.5 identifiers carry an explicit NULL.
    assert!(certificate.signature_algorithm.parameters.is_some());
}

#[test]
fn generate_cert_emits_an_empty_extended_key_usage_without_one() {
    let root = generate_key_pair(KeySize::EccP256).expect("root key");
    let leaf = generate_key_pair(KeySize::EccP256).expect("leaf key");
    let certificate = parse(
        &generate_certificate(
            &IssuanceParameters {
                subject: subject(),
                issuer: ca_subject(),
                subject_public_key: public_key_from_der(leaf.public_key_der()).expect("spki"),
                issuer_key: &issuing_key(&root),
                issuer_public_key: None,
                signature_algorithm: CertificateSignatureAlgorithm::EcdsaSha256,
                validity_days: END_CERTIFICATE_VALIDITY_DAYS,
            },
            &CertificateOptions::default(),
        )
        .expect("generate-cert"),
    );

    // Upstream always supplies a path length, so basicConstraints reports
    // CA:TRUE even though `-basicConstraintsCa` defaults to false.
    let constraints = decode_extension::<BasicConstraints>(&certificate, ID_CE_BASIC_CONSTRAINTS);
    assert!(constraints.ca);
    assert_eq!(constraints.path_len_constraint, Some(0));

    let extended = decode_extension::<ExtendedKeyUsage>(&certificate, ID_CE_EXT_KEY_USAGE);
    assert!(
        extended.0.is_empty(),
        "generate-cert with no -extKeyUsage still emits an empty extension"
    );
    assert!(!has_extension(&certificate, ID_CE_AUTHORITY_KEY_IDENTIFIER));
}

#[test]
fn csr_is_well_formed_and_verifiable() {
    let pair = generate_key_pair(KeySize::EccP256).expect("key pair");
    let der = generate_csr(&CsrParameters {
        subject: subject(),
        public_key: public_key_from_der(pair.public_key_der()).expect("spki"),
        signing_key: &issuing_key(&pair),
        signature_algorithm: CertificateSignatureAlgorithm::EcdsaSha256,
    })
    .expect("CSR");

    let request = x509_cert::request::CertReq::from_der(&der).expect("parse CSR");
    assert!(request.info.attributes.is_empty());
    assert_eq!(request.info.subject, subject());
    assert_eq!(
        request.algorithm.oid,
        const_oid::db::rfc5912::ECDSA_WITH_SHA_256
    );

    let pem = hapsigner::certificate_request_pem(&der).expect("PEM");
    assert!(pem.starts_with("-----BEGIN NEW CERTIFICATE REQUEST-----\n"));
    assert!(pem
        .trim_end()
        .ends_with("-----END NEW CERTIFICATE REQUEST-----"));
}

/// The acceptance test: bootstrap an identity and sign a HAP with it, with no
/// Java anywhere.
#[test]
fn full_lifecycle_signs_and_verifies_without_java() {
    full_lifecycle().expect("full lifecycle");
}

fn full_lifecycle() -> Result<(), Box<dyn std::error::Error>> {
    let root = generate_key_pair(KeySize::EccP256)?;
    let sub = generate_key_pair(KeySize::EccP256)?;
    let app = generate_key_pair(KeySize::EccP256)?;
    let profile_key = generate_key_pair(KeySize::EccP256)?;

    let root_subject = ca_subject();
    let sub_subject = parse_distinguished_name("CN=OpenHarmony Application CA")?;
    let app_subject = subject();

    let root_der = generate_root_ca(
        &IssuanceParameters {
            subject: root_subject.clone(),
            issuer: root_subject.clone(),
            subject_public_key: public_key_from_der(root.public_key_der())?,
            issuer_key: &issuing_key(&root),
            issuer_public_key: None,
            signature_algorithm: CertificateSignatureAlgorithm::EcdsaSha256,
            validity_days: CA_VALIDITY_DAYS,
        },
        Some(2),
    )?;
    let sub_der = generate_sub_ca(
        &IssuanceParameters {
            subject: sub_subject.clone(),
            issuer: root_subject,
            subject_public_key: public_key_from_der(sub.public_key_der())?,
            issuer_key: &issuing_key(&root),
            issuer_public_key: Some(public_key_from_der(root.public_key_der())?),
            signature_algorithm: CertificateSignatureAlgorithm::EcdsaSha256,
            validity_days: CA_VALIDITY_DAYS,
        },
        Some(0),
    )?;
    let app_der = generate_end_certificate(
        &IssuanceParameters {
            subject: app_subject.clone(),
            issuer: sub_subject.clone(),
            subject_public_key: public_key_from_der(app.public_key_der())?,
            issuer_key: &issuing_key(&sub),
            issuer_public_key: Some(public_key_from_der(sub.public_key_der())?),
            signature_algorithm: CertificateSignatureAlgorithm::EcdsaSha256,
            validity_days: END_CERTIFICATE_VALIDITY_DAYS,
        },
        SigningCapability::Application,
    )?;
    let profile_der = generate_end_certificate(
        &IssuanceParameters {
            subject: parse_distinguished_name("CN=Provision Profile Release")?,
            issuer: sub_subject,
            subject_public_key: public_key_from_der(profile_key.public_key_der())?,
            issuer_key: &issuing_key(&sub),
            issuer_public_key: Some(public_key_from_der(sub.public_key_der())?),
            signature_algorithm: CertificateSignatureAlgorithm::EcdsaSha256,
            validity_days: END_CERTIFICATE_VALIDITY_DAYS,
        },
        SigningCapability::Profile,
    )?;

    // Both chains must pass the crate's own chain validation, leaf-first.
    let app_chain = SigningKey::cert_chain_from_bytes(&concat(&[&app_der, &sub_der, &root_der]))?;
    assert_eq!(app_chain.len(), 3);
    assert_eq!(app_chain[0], app_der);
    let profile_chain =
        SigningKey::cert_chain_from_bytes(&concat(&[&profile_der, &sub_der, &root_der]))?;
    assert_eq!(profile_chain.len(), 3);

    // Sign a provisioning profile with the profile certificate.
    let profile_signing_key = SigningKey {
        private_key_der: profile_key.private_key_der().to_vec(),
        cert_chain: profile_chain,
    };
    let application_certificate = Certificate::from_der(&app_der)
        .expect("parse application certificate")
        .to_pem(der::pem::LineEnding::LF)
        .expect("application certificate PEM");
    let unsigned_profile = serde_json::to_vec(&serde_json::json!({
        "version-name": "2.0.0",
        "version-code": 2,
        "uuid": "00000000-0000-0000-0000-000000000000",
        "validity": { "not-before": 1_600_000_000u64, "not-after": 4_100_000_000u64 },
        "type": "release",
        "bundle-info": {
            "developer-id": "OpenHarmony",
            "distribution-certificate": application_certificate,
            "bundle-name": "com.example.lifecycle",
            "apl": "normal",
            "app-feature": "hos_normal_app"
        },
        "issuer": "pki_internal"
    }))?;
    let signed_profile = ProfileSigner::new(
        profile_signing_key,
        hapsigner::SigningAlgorithm::EcdsaSha256,
    )
    .sign(&unsigned_profile)?;
    let verified = ProfileVerifier::verify(&signed_profile)?;
    assert_eq!(verified.content, unsigned_profile);

    // Sign a HAP with the application certificate.
    let material = SigningMaterial::from_der(
        app.private_key_der().to_vec(),
        app_chain,
        signed_profile,
        hapsigner::SigningAlgorithm::EcdsaSha256,
    )?;
    let signed = HapSigner::new(material, SignOptions::default())
        .sign_application(&tiny_zip(), InputFormat::Zip)?;

    let verification = hapsigner::ApplicationVerifier::new(&signed).verify(InputFormat::Zip)?;
    // The CMS `certificates` field is a SET OF, so it decodes in DER order
    // rather than the leaf-first order it was supplied in.
    let mut embedded = verification.certificates.clone();
    embedded.sort();
    let mut expected = vec![app_der.clone(), sub_der.clone(), root_der.clone()];
    expected.sort();
    assert_eq!(embedded, expected);

    // The embedded chain is complete and validates once sorted leaf-first,
    // which `cert_chain_from_bytes` does itself.
    let revalidated = SigningKey::cert_chain_from_bytes(&concat(&verification.certificates))?;
    assert_eq!(revalidated, vec![app_der, sub_der, root_der]);
    Ok(())
}

fn concat<T: AsRef<[u8]>>(parts: &[T]) -> Vec<u8> {
    let mut output = Vec::new();
    for part in parts {
        output.extend_from_slice(part.as_ref());
    }
    output
}

/// A minimal STORED ZIP32 archive, matching the hand-built fixtures in
/// `tests/signing_core.rs`.
fn tiny_zip() -> Vec<u8> {
    let content = br#"{"module":{"name":"entry"}}"#;
    let name = b"module.json";
    let crc = crc32fast::hash(content);

    let mut archive = Vec::new();
    let mut central_directory = Vec::new();

    archive.extend_from_slice(b"PK\x03\x04");
    archive.extend_from_slice(&20u16.to_le_bytes());
    archive.extend_from_slice(&0u16.to_le_bytes());
    archive.extend_from_slice(&0u16.to_le_bytes());
    archive.extend_from_slice(&0u16.to_le_bytes());
    archive.extend_from_slice(&0u16.to_le_bytes());
    archive.extend_from_slice(&crc.to_le_bytes());
    archive.extend_from_slice(&(content.len() as u32).to_le_bytes());
    archive.extend_from_slice(&(content.len() as u32).to_le_bytes());
    archive.extend_from_slice(&(name.len() as u16).to_le_bytes());
    archive.extend_from_slice(&0u16.to_le_bytes());
    archive.extend_from_slice(name);
    archive.extend_from_slice(content);

    central_directory.extend_from_slice(b"PK\x01\x02");
    central_directory.extend_from_slice(&20u16.to_le_bytes());
    central_directory.extend_from_slice(&20u16.to_le_bytes());
    central_directory.extend_from_slice(&0u16.to_le_bytes());
    central_directory.extend_from_slice(&0u16.to_le_bytes());
    central_directory.extend_from_slice(&0u16.to_le_bytes());
    central_directory.extend_from_slice(&0u16.to_le_bytes());
    central_directory.extend_from_slice(&crc.to_le_bytes());
    central_directory.extend_from_slice(&(content.len() as u32).to_le_bytes());
    central_directory.extend_from_slice(&(content.len() as u32).to_le_bytes());
    central_directory.extend_from_slice(&(name.len() as u16).to_le_bytes());
    central_directory.extend_from_slice(&0u16.to_le_bytes());
    central_directory.extend_from_slice(&0u16.to_le_bytes());
    central_directory.extend_from_slice(&0u16.to_le_bytes());
    central_directory.extend_from_slice(&0u16.to_le_bytes());
    central_directory.extend_from_slice(&0u32.to_le_bytes());
    central_directory.extend_from_slice(&0u32.to_le_bytes());
    central_directory.extend_from_slice(name);

    let directory_offset = archive.len() as u32;
    archive.extend_from_slice(&central_directory);
    let directory_size = central_directory.len() as u32;

    archive.extend_from_slice(b"PK\x05\x06");
    archive.extend_from_slice(&0u16.to_le_bytes());
    archive.extend_from_slice(&0u16.to_le_bytes());
    archive.extend_from_slice(&1u16.to_le_bytes());
    archive.extend_from_slice(&1u16.to_le_bytes());
    archive.extend_from_slice(&directory_size.to_le_bytes());
    archive.extend_from_slice(&directory_offset.to_le_bytes());
    archive.extend_from_slice(&0u16.to_le_bytes());
    archive
}

/// Write artifacts for `keytool` / `openssl` / `hap-sign-tool.jar` inspection.
#[test]
fn exports_artifacts_for_external_tooling() {
    let Some(directory) = std::env::var_os("HAPSIGNER_INTEROP_DIR") else {
        return;
    };
    let directory = PathBuf::from(directory);
    fs::create_dir_all(&directory).expect("create interop directory");

    let pair = generate_key_pair(KeySize::EccP256).expect("key pair");
    for (format, name) in [
        (KeystoreFormat::Jks, "rust.jks"),
        (KeystoreFormat::Pkcs12, "rust.p12"),
    ] {
        let store = write_keystore(
            format,
            STORE_PASSWORD,
            &KeystoreEntry {
                alias: ALIAS,
                key_password: KEY_PASSWORD,
                private_key_der: pair.private_key_der(),
                certificate_chain: &[placeholder(&pair)],
            },
        )
        .expect("keystore");
        fs::write(directory.join(name), store).expect("write keystore");
    }

    let root = generate_key_pair(KeySize::EccP256).expect("root key");
    let root_der = generate_root_ca(
        &IssuanceParameters {
            subject: ca_subject(),
            issuer: ca_subject(),
            subject_public_key: public_key_from_der(root.public_key_der()).expect("spki"),
            issuer_key: &issuing_key(&root),
            issuer_public_key: None,
            signature_algorithm: CertificateSignatureAlgorithm::EcdsaSha256,
            validity_days: CA_VALIDITY_DAYS,
        },
        Some(0),
    )
    .expect("root CA");
    fs::write(
        directory.join("root-ca.pem"),
        Certificate::from_der(&root_der)
            .expect("parse")
            .to_pem(der::pem::LineEnding::LF)
            .expect("pem"),
    )
    .expect("write root CA");

    // A sub-CA key store plus the issued end-entity certificate, so external
    // tooling can exercise the full `generate-app-cert` path.
    let sub = generate_key_pair(KeySize::EccP256).expect("sub key");
    let sub_der = generate_sub_ca(
        &IssuanceParameters {
            subject: parse_distinguished_name("CN=OpenHarmony Application CA")
                .expect("sub subject"),
            issuer: ca_subject(),
            subject_public_key: public_key_from_der(sub.public_key_der()).expect("spki"),
            issuer_key: &issuing_key(&root),
            issuer_public_key: Some(public_key_from_der(root.public_key_der()).expect("spki")),
            signature_algorithm: CertificateSignatureAlgorithm::EcdsaSha256,
            validity_days: CA_VALIDITY_DAYS,
        },
        Some(0),
    )
    .expect("sub CA");
    fs::write(
        directory.join("sub-ca-chain.pem"),
        [
            Certificate::from_der(&sub_der).expect("parse"),
            Certificate::from_der(&root_der).expect("parse"),
        ]
        .iter()
        .map(|certificate| certificate.to_pem(der::pem::LineEnding::LF).expect("pem"))
        .collect::<String>(),
    )
    .expect("write sub CA chain");

    let leaf = generate_key_pair(KeySize::EccP256).expect("leaf key");
    let application = generate_end_certificate(
        &IssuanceParameters {
            subject: subject(),
            issuer: parse_distinguished_name("CN=OpenHarmony Application CA").expect("sub subject"),
            subject_public_key: public_key_from_der(leaf.public_key_der()).expect("spki"),
            issuer_key: &issuing_key(&sub),
            issuer_public_key: Some(public_key_from_der(sub.public_key_der()).expect("spki")),
            signature_algorithm: CertificateSignatureAlgorithm::EcdsaSha256,
            validity_days: END_CERTIFICATE_VALIDITY_DAYS,
        },
        SigningCapability::Application,
    )
    .expect("app cert");
    fs::write(
        directory.join("app-cert.pem"),
        Certificate::from_der(&application)
            .expect("parse")
            .to_pem(der::pem::LineEnding::LF)
            .expect("pem"),
    )
    .expect("write app cert");

    let csr = generate_csr(&CsrParameters {
        subject: subject(),
        public_key: public_key_from_der(pair.public_key_der()).expect("spki"),
        signing_key: &issuing_key(&pair),
        signature_algorithm: CertificateSignatureAlgorithm::EcdsaSha256,
    })
    .expect("CSR");
    fs::write(
        directory.join("request.csr"),
        hapsigner::certificate_request_pem(&csr).expect("pem"),
    )
    .expect("write CSR");

    println!("interop artifacts written to {}", directory.display());
}

#[test]
fn distinguished_name_parsing_matches_the_official_grammar() {
    assert!(Name::from_str("C=CN").is_ok());
    for rejected in ["", "NoSeparator", "CN=", "=value", "C=CN,CN=a=b"] {
        assert!(
            parse_distinguished_name(rejected).is_err(),
            "{rejected:?} must be rejected"
        );
    }
    // `der` re-exports `Encode`; assert the parsed name actually encodes.
    assert!(subject().to_der().expect("encode subject").len() > 2);
}
