//! HAR directory signing (`sdk-sign-tool-full.jar sign-har`) tests.

use std::fs;
use std::path::Path;

use hapsigner::cert_tools::{generate_root_ca, public_key_from_der, IssuanceParameters};
use hapsigner::{
    generate_key_pair, parse_distinguished_name, CertificateSignatureAlgorithm, HarSigner,
    HarSigningMaterial, HarVerifier, IssuingKey, KeySize, SignError, SigningAlgorithm, SigningKey,
};

fn signing_key() -> SigningKey {
    let pair = generate_key_pair(KeySize::EccP256).expect("key pair");
    let subject = parse_distinguished_name("C=CN,O=OpenHarmony,CN=HAR Test").expect("subject name");
    let certificate = generate_root_ca(
        &IssuanceParameters {
            subject: subject.clone(),
            issuer: subject,
            subject_public_key: public_key_from_der(pair.public_key_der()).expect("public key"),
            issuer_key: &IssuingKey::from_pkcs8_der(pair.private_key_der()).expect("issuing key"),
            issuer_public_key: None,
            signature_algorithm: CertificateSignatureAlgorithm::EcdsaSha256,
            validity_days: 30,
        },
        Some(0),
    )
    .expect("certificate");
    SigningKey {
        private_key_der: pair.private_key_der().to_vec(),
        cert_chain: vec![certificate],
    }
}

fn stage_directory(root: &Path) {
    fs::create_dir_all(root.join("package/ets")).expect("package directory");
    fs::write(root.join("package/index.ets"), b"export const value = 1;\n").expect("index");
    fs::write(root.join("package/ets/modules.abc"), b"abc payload").expect("abc");
    fs::write(
        root.join("package/oh-package.json5"),
        b"{\"name\":\"demo\"}\n",
    )
    .expect("metadata");
}

fn sign(root: &Path, profile: Option<&[u8]>) -> HarSigner {
    let mut signer = HarSigner::new(signing_key(), SigningAlgorithm::EcdsaSha256);
    if let Some(profile) = profile {
        signer = signer.with_profile(profile.to_vec());
    }
    signer.sign_directory(root).expect("sign directory");
    signer
}

#[test]
fn signs_and_verifies_directory() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = temporary.path().join("signing");
    stage_directory(&root);

    sign(&root, Some(b"provisioning profile"));

    for file in ["codeFileList", "profile", "signature"] {
        assert!(
            root.join(".CodeSignature").join(file).is_file(),
            ".CodeSignature/{file} is missing"
        );
    }

    let manifest = fs::read_to_string(root.join(".CodeSignature/codeFileList")).expect("manifest");
    assert!(manifest.starts_with("{\"version\":1.0,\"fileInfo\":{\"digestAlg\":\"SHA-256\""));
    assert!(manifest.contains("\"fileName\":\"package/index.ets\""));
    assert!(manifest.contains("\"fileName\":\"package/ets/modules.abc\""));
    assert!(manifest.contains("\"fileName\":\".CodeSignature/profile\""));
    assert!(!manifest.contains("\"fileName\":\".CodeSignature/codeFileList\""));
    assert!(!manifest.contains("\"fileName\":\".CodeSignature/signature\""));

    let verified = HarVerifier::verify_directory(&root).expect("verify");
    assert_eq!(verified.algorithm, SigningAlgorithm::EcdsaSha256);
    assert_eq!(
        verified.profile.as_deref(),
        Some(&b"provisioning profile"[..])
    );
    assert_eq!(verified.file_count, 4);
    assert!(!verified.certificates.is_empty());
    assert!(verified.signing_time.is_some());
}

#[test]
fn manifest_uses_gson_escaping_and_basename_order() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = temporary.path().join("signing");
    fs::create_dir_all(root.join("package/zzz")).expect("z directory");
    fs::create_dir_all(root.join("package/aaa")).expect("a directory");
    fs::write(root.join("package/zzz/aaa.ets"), b"a").expect("file");
    fs::write(root.join("package/aaa/zzz.ets"), b"z").expect("file");
    fs::write(root.join("package/a=b<c.ets"), b"escaped").expect("file");

    sign(&root, None);

    let manifest = fs::read_to_string(root.join(".CodeSignature/codeFileList")).expect("manifest");
    let aaa = manifest
        .find("\"fileName\":\"package/zzz/aaa.ets\"")
        .expect("aaa");
    let zzz = manifest
        .find("\"fileName\":\"package/aaa/zzz.ets\"")
        .expect("zzz");
    assert!(aaa < zzz, "entries are sorted by file name, not full path");
    assert!(manifest.contains("package/a\\u003db\\u003cc.ets"));
}

#[test]
fn verification_rejects_tampered_file() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = temporary.path().join("signing");
    stage_directory(&root);
    sign(&root, None);

    fs::write(root.join("package/index.ets"), b"tampered").expect("tamper");
    let error = HarVerifier::verify_directory(&root).expect_err("tamper must fail");
    assert!(matches!(error, SignError::VerificationFailed(_)), "{error}");
}

#[test]
fn verification_rejects_tampered_manifest() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = temporary.path().join("signing");
    stage_directory(&root);
    sign(&root, None);

    let manifest_path = root.join(".CodeSignature/codeFileList");
    let mut manifest = fs::read(&manifest_path).expect("manifest");
    manifest.push(b' ');
    fs::write(&manifest_path, manifest).expect("tamper manifest");
    let error = HarVerifier::verify_directory(&root).expect_err("tamper must fail");
    assert!(matches!(error, SignError::VerificationFailed(_)), "{error}");
}

#[test]
fn verification_rejects_extra_unsigned_file() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = temporary.path().join("signing");
    stage_directory(&root);
    sign(&root, None);

    fs::write(root.join("package/extra.ets"), b"extra").expect("extra file");
    let error = HarVerifier::verify_directory(&root).expect_err("extra file must fail");
    assert!(matches!(error, SignError::VerificationFailed(_)), "{error}");
}

#[test]
fn signs_without_profile_and_resigns_after_change() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = temporary.path().join("signing");
    stage_directory(&root);

    sign(&root, None);
    assert!(!root.join(".CodeSignature/profile").exists());
    let manifest = fs::read_to_string(root.join(".CodeSignature/codeFileList")).expect("manifest");
    assert!(!manifest.contains(".CodeSignature/profile"));
    let verified = HarVerifier::verify_directory(&root).expect("verify");
    assert_eq!(verified.profile, None);
    assert_eq!(verified.file_count, 3);

    fs::write(root.join("package/index.ets"), b"export const value = 2;\n").expect("change");
    assert!(HarVerifier::verify_directory(&root).is_err());

    sign(&root, None);
    let verified = HarVerifier::verify_directory(&root).expect("verify after resign");
    assert_eq!(verified.file_count, 3);
}

#[test]
fn cms_certificate_set_is_der_sorted() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = temporary.path().join("signing");
    stage_directory(&root);

    let first = signing_key();
    let second = signing_key();
    // Use the larger DER certificate as the signer so the CMS set must be
    // reordered; a leaf-first concatenation would fail this assertion.
    let (leaf, other) = if first.cert_chain[0] > second.cert_chain[0] {
        (first, second)
    } else {
        (second, first)
    };
    let chain = vec![leaf.cert_chain[0].clone(), other.cert_chain[0].clone()];
    let mut expected = chain.clone();
    expected.sort();

    HarSigner::new(
        SigningKey {
            private_key_der: leaf.private_key_der.clone(),
            cert_chain: chain,
        },
        SigningAlgorithm::EcdsaSha256,
    )
    .sign_directory(&root)
    .expect("sign");
    HarVerifier::verify_directory(&root).expect("verify");

    // `cms` re-sorts `SET OF` elements while decoding, so inspect the encoded
    // certificate set directly to assert the builder wrote DER order.
    let signature = std::fs::read(root.join(".CodeSignature/signature")).expect("signature");
    let first_offset = find_bytes(&signature, &expected[0]).expect("first certificate");
    let second_offset = find_bytes(&signature, &expected[1]).expect("second certificate");
    assert!(
        first_offset < second_offset,
        "CMS certificate SET is not DER-sorted"
    );
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[test]
fn from_keystore_uses_the_sign_certificate_chain() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = temporary.path().join("signing");
    stage_directory(&root);

    let key = signing_key();
    let keystore = hapsigner::write_keystore(
        hapsigner::KeystoreFormat::Pkcs12,
        "store-password",
        &hapsigner::KeystoreEntry {
            alias: "har",
            key_password: "key-password",
            private_key_der: &key.private_key_der,
            certificate_chain: &key.cert_chain,
        },
    )
    .expect("keystore");
    let certificate_chain = key.cert_chain[0].clone();
    let signer = HarSigner::from_keystore(HarSigningMaterial {
        keystore: &keystore,
        store_password: "store-password",
        key_alias: "har",
        key_password: "key-password",
        sign_certificate_chain: &certificate_chain,
        profile: None,
        algorithm: SigningAlgorithm::EcdsaSha256,
    })
    .expect("material");
    signer.sign_directory(&root).expect("sign");
    HarVerifier::verify_directory(&root).expect("verify");
}
