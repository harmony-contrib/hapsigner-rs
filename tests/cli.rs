//! End-to-end coverage of the `generate-*` command line surface.
//!
//! Every test drives the real `hap-sign` binary so the flag names, defaults,
//! and error messages are exercised rather than the library beneath them.

use std::path::PathBuf;
use std::process::{Command, Output};

use base64::Engine;
use tempfile::TempDir;

const BINARY: &str = env!("CARGO_BIN_EXE_hap-sign");
const STORE_PASSWORD: &str = "123456";
const KEY_PASSWORD: &str = "123456";

const ROOT_SUBJECT: &str = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Root CA";
const SUB_SUBJECT: &str = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application CA";
const APP_SUBJECT: &str = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release";
const PROFILE_SUBJECT: &str =
    "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Provision Profile Release";

struct Workspace {
    directory: TempDir,
}

impl Workspace {
    fn new() -> Self {
        Self {
            directory: TempDir::new().expect("temporary directory"),
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.directory.path().join(name)
    }

    fn read(&self, name: &str) -> Vec<u8> {
        std::fs::read(self.path(name)).unwrap_or_else(|error| panic!("read {name}: {error}"))
    }

    fn exists(&self, name: &str) -> bool {
        self.path(name).exists()
    }
}

/// Run `hap-sign`, returning stdout on success and panicking with the captured
/// output on failure.
fn run(workspace: &Workspace, args: &[&str]) -> String {
    let output = raw(workspace, args);
    assert!(
        output.status.success(),
        "hap-sign {args:?} failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("stdout is UTF-8")
}

fn raw(workspace: &Workspace, args: &[&str]) -> Output {
    Command::new(BINARY)
        .args(args)
        .current_dir(workspace.directory.path())
        .env("HAPSIGNER_STORE_PASSWORD", STORE_PASSWORD)
        .env("HAPSIGNER_KEY_PASSWORD", KEY_PASSWORD)
        .output()
        .expect("run hap-sign")
}

/// Assert that the command fails and that stderr mentions `expected`.
fn fails_with(workspace: &Workspace, args: &[&str], expected: &str) {
    let output = raw(workspace, args);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "hap-sign {args:?} unexpectedly succeeded:\n{}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        stderr.contains(expected),
        "hap-sign {args:?} stderr did not mention {expected:?}:\n{stderr}"
    );
}

/// A root CA, a sub CA, an app certificate, and a profile certificate.
fn bootstrap(workspace: &Workspace) {
    run(
        workspace,
        &[
            "generate-ca",
            "--key-alias",
            "root",
            "--key-alg",
            "ECC",
            "--key-size",
            "NIST-P-256",
            "--subject",
            ROOT_SUBJECT,
            "--keystore",
            "root.p12",
            "--sign-alg",
            "SHA256withECDSA",
            "--basic-constraints-path-len",
            "1",
            "--out-file",
            "root-ca.pem",
        ],
    );
    run(
        workspace,
        &[
            "generate-keypair",
            "--key-alias",
            "sub",
            "--key-alg",
            "ECC",
            "--key-size",
            "NIST-P-256",
            "--keystore",
            "sub.p12",
        ],
    );
    run(
        workspace,
        &[
            "generate-ca",
            "--key-alias",
            "sub",
            "--key-alg",
            "ECC",
            "--key-size",
            "NIST-P-256",
            "--subject",
            SUB_SUBJECT,
            "--issuer",
            ROOT_SUBJECT,
            "--issuer-key-alias",
            "root",
            "--issuer-keystore",
            "root.p12",
            "--keystore",
            "sub.p12",
            "--sign-alg",
            "SHA256withECDSA",
            "--out-file",
            "sub-ca.pem",
        ],
    );
    for (alias, store) in [("app", "app.p12"), ("profile", "profile.p12")] {
        run(
            workspace,
            &[
                "generate-keypair",
                "--key-alias",
                alias,
                "--key-alg",
                "ECC",
                "--key-size",
                "NIST-P-256",
                "--keystore",
                store,
            ],
        );
    }
    run(
        workspace,
        &[
            "generate-app-cert",
            "--key-alias",
            "app",
            "--subject",
            APP_SUBJECT,
            "--issuer",
            SUB_SUBJECT,
            "--issuer-key-alias",
            "sub",
            "--issuer-keystore",
            "sub.p12",
            "--keystore",
            "app.p12",
            "--out-form",
            "certChain",
            "--sub-ca-cert-file",
            "sub-ca.pem",
            "--root-ca-cert-file",
            "root-ca.pem",
            "--out-file",
            "app-cert-chain.pem",
        ],
    );
    run(
        workspace,
        &[
            "generate-profile-cert",
            "--key-alias",
            "profile",
            "--subject",
            PROFILE_SUBJECT,
            "--issuer",
            SUB_SUBJECT,
            "--issuer-key-alias",
            "sub",
            "--issuer-keystore",
            "sub.p12",
            "--keystore",
            "profile.p12",
            "--out-form",
            "certChain",
            "--sub-ca-cert-file",
            "sub-ca.pem",
            "--root-ca-cert-file",
            "root-ca.pem",
            "--out-file",
            "profile-cert-chain.pem",
        ],
    );
}

#[test]
fn generate_ca_bootstraps_a_verifiable_chain() {
    let workspace = Workspace::new();
    bootstrap(&workspace);

    let chain = reader_certificates(&workspace.read("app-cert-chain.pem"));
    assert_eq!(chain.len(), 3, "certificate chain is leaf, sub CA, root");

    // The chain must validate, which also proves the issuer links up.
    hapsigner::SigningKey::cert_chain_from_bytes(&workspace.read("app-cert-chain.pem"))
        .expect("generated chain validates");
}

#[test]
fn generate_keypair_writes_both_keystore_formats() {
    for (name, format) in [("app.jks", "jks"), ("app.p12", "p12")] {
        let workspace = Workspace::new();
        run(
            &workspace,
            &[
                "generate-keypair",
                "--key-alias",
                "key",
                "--key-alg",
                "ECC",
                "--key-size",
                "NIST-P-256",
                "--keystore",
                name,
            ],
        );
        let store = workspace.read(name);
        hapsigner::SigningKey::from_keystore(&store, STORE_PASSWORD, "key", KEY_PASSWORD)
            .unwrap_or_else(|error| panic!("{format} keystore does not load: {error}"));
    }
}

#[test]
fn camel_case_aliases_are_accepted() {
    let workspace = Workspace::new();
    run(
        &workspace,
        &[
            "generate-keypair",
            "--keyAlias",
            "key",
            "--keyAlg",
            "ECC",
            "--keySize",
            "NIST-P-256",
            "--keystoreFile",
            "app.p12",
            "--keystorePwd",
            STORE_PASSWORD,
            "--keyPwd",
            KEY_PASSWORD,
        ],
    );
    assert!(workspace.exists("app.p12"));
}

#[test]
fn generate_keypair_refuses_to_replace_a_keystore() {
    let workspace = Workspace::new();
    let args = [
        "generate-keypair",
        "--key-alias",
        "key",
        "--key-alg",
        "ECC",
        "--key-size",
        "NIST-P-256",
        "--keystore",
        "app.p12",
    ];
    run(&workspace, &args);
    let before = workspace.read("app.p12");

    fails_with(&workspace, &args, "already exists");

    let mut forced = args.to_vec();
    forced.push("--force");
    run(&workspace, &forced);
    assert_ne!(
        before,
        workspace.read("app.p12"),
        "--force must actually regenerate the keystore"
    );
}

#[test]
fn key_material_keeps_generated_certificates_signed_by_the_right_key() {
    let workspace = Workspace::new();
    bootstrap(&workspace);

    let chain = reader_certificates(&workspace.read("app-cert-chain.pem"));
    let root = parse(&chain[2]);
    let sub = parse(&chain[1]);
    let leaf = parse(&chain[0]);

    assert_eq!(root.tbs_certificate.subject, root.tbs_certificate.issuer);
    assert_eq!(sub.tbs_certificate.issuer, root.tbs_certificate.subject);
    assert_eq!(leaf.tbs_certificate.issuer, sub.tbs_certificate.subject);
    assert_ne!(
        root.tbs_certificate.serial_number,
        sub.tbs_certificate.serial_number
    );
}

#[test]
fn generate_csr_emits_the_legacy_pem_label() {
    let workspace = Workspace::new();
    run(
        &workspace,
        &[
            "generate-keypair",
            "--key-alias",
            "key",
            "--key-alg",
            "ECC",
            "--key-size",
            "NIST-P-256",
            "--keystore",
            "app.p12",
        ],
    );
    let stdout = run(
        &workspace,
        &[
            "generate-csr",
            "--key-alias",
            "key",
            "--subject",
            APP_SUBJECT,
            "--keystore",
            "app.p12",
        ],
    );
    assert!(stdout.starts_with("-----BEGIN NEW CERTIFICATE REQUEST-----\n"));
    assert!(stdout
        .trim_end()
        .ends_with("-----END NEW CERTIFICATE REQUEST-----"));
}

#[test]
fn end_certificates_reject_rsa_signature_algorithms() {
    let workspace = Workspace::new();
    bootstrap(&workspace);
    fails_with(
        &workspace,
        &[
            "generate-app-cert",
            "--key-alias",
            "app",
            "--subject",
            APP_SUBJECT,
            "--issuer",
            SUB_SUBJECT,
            "--issuer-key-alias",
            "sub",
            "--issuer-keystore",
            "sub.p12",
            "--keystore",
            "app.p12",
            "--sign-alg",
            "SHA256withRSA",
            "--out-form",
            "cert",
            "--out-file",
            "app.pem",
        ],
        "only accepts SHA256withECDSA or SHA384withECDSA",
    );
}

#[test]
fn cert_chain_output_requires_both_ca_certificates() {
    let workspace = Workspace::new();
    bootstrap(&workspace);
    fails_with(
        &workspace,
        &[
            "generate-app-cert",
            "--key-alias",
            "app",
            "--subject",
            APP_SUBJECT,
            "--issuer",
            SUB_SUBJECT,
            "--issuer-key-alias",
            "sub",
            "--issuer-keystore",
            "sub.p12",
            "--keystore",
            "app.p12",
            "--out-file",
            "app.pem",
        ],
        "--sub-ca-cert-file is required",
    );
}

#[test]
fn unknown_key_usage_names_are_rejected() {
    let workspace = Workspace::new();
    bootstrap(&workspace);
    fails_with(
        &workspace,
        &[
            "generate-cert",
            "--key-alias",
            "app",
            "--subject",
            APP_SUBJECT,
            "--issuer",
            SUB_SUBJECT,
            "--issuer-key-alias",
            "sub",
            "--issuer-keystore",
            "sub.p12",
            "--keystore",
            "app.p12",
            "--key-usage",
            "digitalSignature,notAUsage",
            "--out-file",
            "cert.pem",
        ],
        "unknown key usage 'notAUsage'",
    );
}

#[test]
fn a_root_ca_rejects_an_issuer_without_an_issuer_key() {
    let workspace = Workspace::new();
    fails_with(
        &workspace,
        &[
            "generate-ca",
            "--key-alias",
            "root",
            "--key-alg",
            "ECC",
            "--key-size",
            "NIST-P-256",
            "--subject",
            ROOT_SUBJECT,
            "--issuer",
            SUB_SUBJECT,
            "--keystore",
            "root.p12",
            "--out-file",
            "root.pem",
        ],
        "--issuer only applies to a subordinate CA",
    );
}

#[test]
fn a_missing_alias_points_at_generate_keypair() {
    let workspace = Workspace::new();
    run(
        &workspace,
        &[
            "generate-keypair",
            "--key-alias",
            "present",
            "--key-alg",
            "ECC",
            "--key-size",
            "NIST-P-256",
            "--keystore",
            "app.p12",
        ],
    );
    fails_with(
        &workspace,
        &[
            "generate-csr",
            "--key-alias",
            "absent",
            "--subject",
            APP_SUBJECT,
            "--keystore",
            "app.p12",
        ],
        "run generate-keypair first",
    );
}

#[test]
fn invalid_key_sizes_name_the_algorithm() {
    let workspace = Workspace::new();
    fails_with(
        &workspace,
        &[
            "generate-keypair",
            "--key-alias",
            "key",
            "--key-alg",
            "ECC",
            "--key-size",
            "2048",
            "--keystore",
            "app.p12",
        ],
        "does not support size",
    );
}

#[test]
fn passwords_come_from_the_environment_without_a_flag() {
    let workspace = Workspace::new();
    let output = Command::new(BINARY)
        .args([
            "generate-keypair",
            "--key-alias",
            "key",
            "--key-alg",
            "ECC",
            "--key-size",
            "NIST-P-256",
            "--keystore",
            "app.p12",
        ])
        .current_dir(workspace.directory.path())
        .output()
        .expect("run hap-sign");
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("HAPSIGNER_STORE_PASSWORD"),
        "a missing store password should name the environment variable"
    );
}

fn parse(der: &[u8]) -> x509_cert::Certificate {
    use der::Decode;

    x509_cert::Certificate::from_der(der).expect("parse certificate")
}

/// Split a concatenated PEM bundle into DER certificates.
fn reader_certificates(pem: &[u8]) -> Vec<Vec<u8>> {
    let text = std::str::from_utf8(pem).expect("PEM is UTF-8");
    let mut certificates = Vec::new();
    let mut rest = text;
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    while let Some(start) = rest.find(BEGIN) {
        let after = &rest[start + BEGIN.len()..];
        let end = after.find(END).expect("END marker");
        let encoded: String = after[..end].split_ascii_whitespace().collect();
        certificates.push(base64_decode(&encoded));
        rest = &after[end + END.len()..];
    }
    certificates
}

fn base64_decode(encoded: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .expect("certificate body is Base64")
}
