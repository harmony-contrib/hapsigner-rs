//! `generate-*` commands, mirroring the official `hap-sign-tool` surface.
//!
//! Passwords are taken from a flag first and from the matching `HAPSIGNER_*`
//! environment variable second, so a caller can keep them out of the process
//! arguments. Where the official tool would quietly accept a value it cannot
//! use, these commands report the problem instead; the differences are listed
//! in `docs/openharmony-format.md`.

use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{bail, Context, Result};
use clap::ValueEnum;
use der::pem::LineEnding;
use der::{Decode, EncodePem};
use hapsigner::cert_tools::{
    extended_key_usage_names, generate_certificate, generate_csr, generate_end_certificate,
    generate_key_pair_entry, generate_root_ca, generate_sub_ca, key_usage_names,
    public_key_from_der, CertificateOptions, CsrParameters, IssuanceParameters, KeyPairParameters,
};
use hapsigner::{
    parse_distinguished_name, parse_extended_key_usage_checked, parse_key_usage_checked,
    CertificateSignatureAlgorithm, IssuingKey, KeyAlgorithm, KeySize, KeystoreFormat, SignError,
    SigningCapability, SigningKey,
};
use spki::SubjectPublicKeyInfoOwned;
use x509_cert::Certificate;

use crate::{AtomicOutput, OutputPolicy, KEY_PASSWORD_ENV, STORE_PASSWORD_ENV};

const ISSUER_STORE_PASSWORD_ENV: &str = "HAPSIGNER_ISSUER_STORE_PASSWORD";
const ISSUER_KEY_PASSWORD_ENV: &str = "HAPSIGNER_ISSUER_KEY_PASSWORD";

// ── Arguments ───────────────────────────────────────────────────────────────

#[derive(clap::Args, Debug)]
pub(crate) struct KeyPairArgs {
    #[arg(long = "key-alias", visible_alias = "keyAlias")]
    pub(crate) key_alias: String,
    #[arg(long = "key-alg", visible_alias = "keyAlg")]
    pub(crate) key_alg: String,
    #[arg(long = "key-size", visible_alias = "keySize")]
    pub(crate) key_size: String,
    #[arg(
        long = "keystore",
        alias = "keystore-file",
        visible_alias = "keystoreFile"
    )]
    pub(crate) keystore: PathBuf,
    #[arg(long = "key-pwd", visible_alias = "keyPwd")]
    pub(crate) key_password: Option<String>,
    #[arg(long = "keystore-pwd", visible_alias = "keystorePwd")]
    pub(crate) store_password: Option<String>,
    /// Accepted for official compatibility; the upstream tool never reads it.
    #[arg(long = "ext-cfg-file", visible_alias = "extCfgFile")]
    pub(crate) _ext_cfg_file: Option<PathBuf>,
    /// Replace an existing keystore file instead of refusing to overwrite it.
    #[arg(long)]
    pub(crate) force: bool,
}

#[derive(clap::Args, Debug)]
pub(crate) struct CsrArgs {
    #[arg(long = "key-alias", visible_alias = "keyAlias")]
    pub(crate) key_alias: String,
    #[arg(long)]
    pub(crate) subject: String,
    #[arg(
        long = "sign-alg",
        visible_alias = "signAlg",
        default_value = "SHA256withECDSA"
    )]
    pub(crate) sign_alg: String,
    #[arg(
        long = "keystore",
        alias = "keystore-file",
        visible_alias = "keystoreFile"
    )]
    pub(crate) keystore: PathBuf,
    #[arg(long = "key-pwd", visible_alias = "keyPwd")]
    pub(crate) key_password: Option<String>,
    #[arg(long = "keystore-pwd", visible_alias = "keystorePwd")]
    pub(crate) store_password: Option<String>,
    #[arg(long = "out-file", alias = "out", visible_alias = "outFile")]
    pub(crate) out_file: Option<PathBuf>,
    #[arg(long = "ext-cfg-file", visible_alias = "extCfgFile")]
    pub(crate) _ext_cfg_file: Option<PathBuf>,
    #[arg(long)]
    pub(crate) force: bool,
}

/// Options shared by every command that issues a certificate from a CSR.
#[derive(clap::Args, Debug)]
pub(crate) struct IssuanceArgs {
    #[arg(long = "key-alias", visible_alias = "keyAlias")]
    pub(crate) key_alias: String,
    #[arg(long)]
    pub(crate) subject: String,
    #[arg(long)]
    pub(crate) issuer: Option<String>,
    /// Omit to make `generate-ca` issue a self-signed root CA.
    #[arg(long = "issuer-key-alias", visible_alias = "issuerKeyAlias")]
    pub(crate) issuer_key_alias: Option<String>,
    #[arg(
        long = "keystore",
        alias = "keystore-file",
        visible_alias = "keystoreFile"
    )]
    pub(crate) keystore: PathBuf,
    #[arg(
        long = "issuer-keystore",
        alias = "issuer-keystore-file",
        visible_alias = "issuerKeystoreFile"
    )]
    pub(crate) issuer_keystore: Option<PathBuf>,
    #[arg(long = "key-pwd", visible_alias = "keyPwd")]
    pub(crate) key_password: Option<String>,
    #[arg(long = "keystore-pwd", visible_alias = "keystorePwd")]
    pub(crate) store_password: Option<String>,
    #[arg(long = "issuer-key-pwd", visible_alias = "issuerKeyPwd")]
    pub(crate) issuer_key_password: Option<String>,
    #[arg(long = "issuer-keystore-pwd", visible_alias = "issuerKeystorePwd")]
    pub(crate) issuer_store_password: Option<String>,
    #[arg(
        long = "sign-alg",
        visible_alias = "signAlg",
        default_value = "SHA256withECDSA"
    )]
    pub(crate) sign_alg: String,
    #[arg(long = "out-file", alias = "out", visible_alias = "outFile")]
    pub(crate) out_file: Option<PathBuf>,
    #[arg(long = "ext-cfg-file", visible_alias = "extCfgFile")]
    pub(crate) _ext_cfg_file: Option<PathBuf>,
    #[arg(long)]
    pub(crate) force: bool,
}

#[derive(clap::Args, Debug)]
pub(crate) struct CaArgs {
    #[command(flatten)]
    pub(crate) issuance: IssuanceArgs,
    #[arg(long = "key-alg", visible_alias = "keyAlg")]
    pub(crate) key_alg: String,
    #[arg(long = "key-size", visible_alias = "keySize")]
    pub(crate) key_size: String,
    #[arg(long, default_value_t = 3650)]
    pub(crate) validity: u64,
    #[arg(
        long = "basic-constraints-path-len",
        visible_alias = "basicConstraintsPathLen",
        default_value_t = 0
    )]
    pub(crate) basic_constraints_path_len: u32,
}

#[derive(clap::Args, Debug)]
pub(crate) struct CertificateArgs {
    #[command(flatten)]
    pub(crate) issuance: IssuanceArgs,
    #[arg(long, default_value_t = 1095)]
    pub(crate) validity: u64,
    #[arg(long = "key-usage", visible_alias = "keyUsage")]
    pub(crate) key_usage: String,
    #[arg(
        long = "key-usage-critical",
        visible_alias = "keyUsageCritical",
        default_value_t = true
    )]
    pub(crate) key_usage_critical: bool,
    #[arg(
        long = "ext-key-usage",
        visible_alias = "extKeyUsage",
        default_value = ""
    )]
    pub(crate) ext_key_usage: String,
    #[arg(
        long = "ext-key-usage-critical",
        visible_alias = "extKeyUsageCritical",
        default_value_t = true
    )]
    pub(crate) ext_key_usage_critical: bool,
    #[arg(
        long = "basic-constraints-critical",
        visible_alias = "basicConstraintsCritical",
        default_value_t = false
    )]
    pub(crate) basic_constraints_critical: bool,
    #[arg(
        long = "basic-constraints-ca",
        visible_alias = "basicConstraintsCa",
        default_value_t = false
    )]
    pub(crate) basic_constraints_ca: bool,
    #[arg(
        long = "basic-constraints-path-len",
        visible_alias = "basicConstraintsPathLen",
        default_value_t = 0
    )]
    pub(crate) basic_constraints_path_len: u32,
}

#[derive(clap::Args, Debug)]
pub(crate) struct EndCertificateArgs {
    #[command(flatten)]
    pub(crate) issuance: IssuanceArgs,
    #[arg(long, default_value_t = 1095)]
    pub(crate) validity: u64,
    #[arg(
        long = "out-form",
        visible_alias = "outForm",
        default_value = "certChain"
    )]
    pub(crate) out_form: OutForm,
    #[arg(long = "sub-ca-cert-file", visible_alias = "subCaCertFile")]
    pub(crate) sub_ca_cert_file: Option<PathBuf>,
    #[arg(long = "root-ca-cert-file", visible_alias = "rootCaCertFile")]
    pub(crate) root_ca_cert_file: Option<PathBuf>,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum OutForm {
    Cert,
    #[value(name = "certChain")]
    CertChain,
}

// ── Commands ────────────────────────────────────────────────────────────────

pub(crate) fn run_generate_keypair(args: &KeyPairArgs) -> Result<()> {
    let algorithm = KeyAlgorithm::from_str(&args.key_alg)?;
    let size = KeySize::parse(&args.key_size, algorithm)?;
    let format = KeystoreFormat::from_path(&args.keystore)?;
    OutputPolicy::new(args.force).validate_new(&args.keystore)?;

    let store = generate_key_pair_entry(&KeyPairParameters {
        alias: &args.key_alias,
        size,
        key_password: &key_password(args.key_password.as_deref(), KEY_PASSWORD_ENV),
        store_password: &store_password(args.store_password.as_deref(), STORE_PASSWORD_ENV)?,
        format,
    })?;
    AtomicOutput::write(&args.keystore, &store)?;
    println!("{}", args.keystore.display());
    Ok(())
}

pub(crate) fn run_generate_csr(args: &CsrArgs) -> Result<()> {
    // The keystore extension is validated even though the file is only read,
    // matching `CmdUtil.validFileType`.
    KeystoreFormat::from_path(&args.keystore)?;
    let signing_key = load_issuing_key(
        &args.keystore,
        args.store_password.as_deref(),
        STORE_PASSWORD_ENV,
        &args.key_alias,
        args.key_password.as_deref(),
        KEY_PASSWORD_ENV,
    )?;

    let request = generate_csr(&CsrParameters {
        subject: parse_distinguished_name(&args.subject)?,
        public_key: public_key_from_der(&signing_key.public_key_der()?)?,
        signing_key: &signing_key,
        signature_algorithm: CertificateSignatureAlgorithm::from_str(&args.sign_alg)?,
    })?;
    write_text(
        args.out_file.as_deref(),
        args.force,
        &hapsigner::certificate_request_pem(&request)?,
    )
}

pub(crate) fn run_generate_cert(args: &CertificateArgs) -> Result<()> {
    let options = CertificateOptions {
        key_usage: parse_key_usage_checked(&args.key_usage)
            .map_err(|error| usage_error(error, key_usage_names()))?,
        key_usage_critical: args.key_usage_critical,
        extended_key_usage: parse_extended_key_usage_checked(&args.ext_key_usage)
            .map_err(|error| usage_error(error, extended_key_usage_names()))?,
        extended_key_usage_critical: args.ext_key_usage_critical,
        basic_constraints_critical: args.basic_constraints_critical,
        basic_constraints_ca: args.basic_constraints_ca,
        basic_constraints_path_len: Some(args.basic_constraints_path_len),
    };
    // `generate-cert` never creates a key.
    let issuer = load_issuer(&args.issuance, false)?;
    let subject_key = load_subject_key(&args.issuance)?;
    let certificate = generate_certificate(
        &issuance_parameters(
            &args.issuance,
            &subject_key,
            &issuer.key,
            issuer.public_key,
            args.validity,
        )?,
        &options,
    )?;
    write_text(
        args.issuance.out_file.as_deref(),
        args.issuance.force,
        &certificate_pem(&certificate)?,
    )
}

pub(crate) fn run_generate_ca(args: &CaArgs) -> Result<()> {
    let algorithm = KeyAlgorithm::from_str(&args.key_alg)?;
    let size = KeySize::parse(&args.key_size, algorithm)?;
    KeystoreFormat::from_path(&args.issuance.keystore)?;
    if args.issuance.issuer.is_some() && args.issuance.issuer_key_alias.is_none() {
        bail!("--issuer only applies to a subordinate CA; drop it or pass --issuer-key-alias");
    }

    let subject = parse_distinguished_name(&args.issuance.subject)?;
    let is_root = args.issuance.issuer_key_alias.is_none();
    // A root CA is self-issued, so the issuer name is the subject.
    let issuer_name = match &args.issuance.issuer {
        Some(issuer) => parse_distinguished_name(issuer)?,
        None => subject.clone(),
    };
    let signature_algorithm = CertificateSignatureAlgorithm::from_str(&args.issuance.sign_alg)?;

    // `generateCA` creates the subject key when its alias is absent.
    let subject_key = create_or_load_subject_key(&args.issuance, size)?;
    let subject_public_key = public_key_from_der(&subject_key.public_key_der()?)?;

    let certificate = if is_root {
        generate_root_ca(
            &IssuanceParameters {
                subject,
                issuer: issuer_name,
                subject_public_key,
                issuer_key: &subject_key,
                issuer_public_key: None,
                signature_algorithm,
                validity_days: args.validity,
            },
            Some(args.basic_constraints_path_len),
        )?
    } else {
        let issuer = load_issuer(&args.issuance, true)?;
        generate_sub_ca(
            &IssuanceParameters {
                subject,
                issuer: issuer_name,
                subject_public_key,
                issuer_key: &issuer.key,
                issuer_public_key: issuer.public_key,
                signature_algorithm,
                validity_days: args.validity,
            },
            Some(args.basic_constraints_path_len),
        )?
    };

    write_text(
        args.issuance.out_file.as_deref(),
        args.issuance.force,
        &certificate_pem(&certificate)?,
    )
}

pub(crate) fn run_generate_end_cert(
    args: &EndCertificateArgs,
    capability: SigningCapability,
) -> Result<()> {
    let algorithm = CertificateSignatureAlgorithm::from_str(&args.issuance.sign_alg)?;
    // `CmdUtil.judgeEndSignAlgType` accepts only the ECDSA spellings here.
    if !algorithm.is_ecdsa() {
        bail!(
            "{} only accepts SHA256withECDSA or SHA384withECDSA, got {algorithm}",
            capability_name(capability)
        );
    }

    let issuer = load_issuer(&args.issuance, true)?;
    let subject_key = load_subject_key(&args.issuance)?;
    let certificate = generate_end_certificate(
        &issuance_parameters(
            &args.issuance,
            &subject_key,
            &issuer.key,
            issuer.public_key,
            args.validity,
        )?,
        capability,
    )?;

    let output = match args.out_form {
        OutForm::Cert => certificate_pem(&certificate)?,
        OutForm::CertChain => {
            let sub_ca =
                required_certificate_file(args.sub_ca_cert_file.as_deref(), "sub-ca-cert-file")?;
            let root_ca =
                required_certificate_file(args.root_ca_cert_file.as_deref(), "root-ca-cert-file")?;
            // `getOutputCert` order: new certificate, sub CA, root CA.
            format!(
                "{}{}{}",
                certificate_pem(&certificate)?,
                certificate_pem(&sub_ca)?,
                certificate_pem(&root_ca)?
            )
        }
    };
    write_text(
        args.issuance.out_file.as_deref(),
        args.issuance.force,
        &output,
    )
}

/// Name the offending value and the accepted set, as `CmdUtil.verifyType` does.
fn usage_error(error: SignError, accepted: impl Iterator<Item = &'static str>) -> anyhow::Error {
    let SignError::UnsupportedKeyUsage(name) = error else {
        return error.into();
    };
    anyhow::anyhow!(
        "unknown key usage '{name}'; expected one of {}",
        accepted.collect::<Vec<_>>().join(", ")
    )
}

fn capability_name(capability: SigningCapability) -> &'static str {
    match capability {
        SigningCapability::Application => "generate-app-cert",
        SigningCapability::Profile => "generate-profile-cert",
    }
}

// ── Keystore helpers ────────────────────────────────────────────────────────

struct Issuer {
    key: IssuingKey,
    /// Present so a sub-CA certificate can carry an authority key identifier.
    public_key: Option<SubjectPublicKeyInfoOwned>,
}

fn issuance_parameters<'a>(
    args: &'a IssuanceArgs,
    subject_key: &IssuingKey,
    issuer_key: &'a IssuingKey,
    issuer_public_key: Option<SubjectPublicKeyInfoOwned>,
    validity_days: u64,
) -> Result<IssuanceParameters<'a>> {
    Ok(IssuanceParameters {
        subject: parse_distinguished_name(&args.subject)?,
        issuer: parse_distinguished_name(args.issuer.as_deref().unwrap_or(args.subject.as_str()))?,
        subject_public_key: public_key_from_der(&subject_key.public_key_der()?)?,
        issuer_key,
        issuer_public_key,
        signature_algorithm: CertificateSignatureAlgorithm::from_str(&args.sign_alg)?,
        validity_days,
    })
}

/// Load the issuing key, reading `authority_public_key` when the caller needs
/// it for a subordinate CA.
fn load_issuer(args: &IssuanceArgs, with_public_key: bool) -> Result<Issuer> {
    let alias = args
        .issuer_key_alias
        .as_deref()
        .filter(|alias| !alias.trim().is_empty())
        .context("--issuer-key-alias is required")?;

    // The issuing key usually shares the caller's keystore and passwords; a
    // dedicated `--issuer-keystore` still falls back to them, so a shared
    // password is never supplied twice. `HAPSIGNER_ISSUER_*` overrides the
    // fallback when the two identities really do differ.
    let keystore = args
        .issuer_keystore
        .clone()
        .unwrap_or_else(|| args.keystore.clone());
    let store_password = match args.issuer_store_password.as_deref() {
        Some(password) => password.to_owned(),
        None => std::env::var(ISSUER_STORE_PASSWORD_ENV).ok().map_or_else(
            || store_password(args.store_password.as_deref(), STORE_PASSWORD_ENV),
            Ok,
        )?,
    };
    let key_password = match args.issuer_key_password.as_deref() {
        Some(password) => password.to_owned(),
        None => std::env::var(ISSUER_KEY_PASSWORD_ENV)
            .unwrap_or_else(|_| key_password(args.key_password.as_deref(), KEY_PASSWORD_ENV)),
    };

    let key = load_issuing_key(
        &keystore,
        Some(&store_password),
        STORE_PASSWORD_ENV,
        alias,
        Some(&key_password),
        KEY_PASSWORD_ENV,
    )
    .with_context(|| format!("failed to load issuer key '{alias}'"))?;
    let public_key = match with_public_key {
        true => Some(public_key_from_der(&key.public_key_der()?)?),
        false => None,
    };
    Ok(Issuer { key, public_key })
}

fn load_subject_key(args: &IssuanceArgs) -> Result<IssuingKey> {
    load_issuing_key(
        &args.keystore,
        args.store_password.as_deref(),
        STORE_PASSWORD_ENV,
        &args.key_alias,
        args.key_password.as_deref(),
        KEY_PASSWORD_ENV,
    )
    .with_context(|| format!("failed to load key '{}'", args.key_alias))
}

/// Load the subject key, creating it and the keystore when neither exists.
///
/// `LocalizationAdapter.getAliasKey(true)` does the same. It cannot add an
/// entry to a keystore that already holds other entries, because this tool does
/// not merge keystores; that case is reported with a pointer to
/// `generate-keypair`.
fn create_or_load_subject_key(args: &IssuanceArgs, size: KeySize) -> Result<IssuingKey> {
    let format = KeystoreFormat::from_path(&args.keystore)?;
    let store_password = store_password(args.store_password.as_deref(), STORE_PASSWORD_ENV)?;
    let key_password = key_password(args.key_password.as_deref(), KEY_PASSWORD_ENV);

    if args.keystore.exists() {
        return load_issuing_key(
            &args.keystore,
            Some(&store_password),
            STORE_PASSWORD_ENV,
            &args.key_alias,
            Some(&key_password),
            KEY_PASSWORD_ENV,
        )
        .with_context(|| {
            format!(
                "keystore {} does not contain a usable key for '{}'; run generate-keypair first",
                args.keystore.display(),
                args.key_alias
            )
        });
    }

    OutputPolicy::new(args.force).validate_new(&args.keystore)?;
    let store = generate_key_pair_entry(&KeyPairParameters {
        alias: &args.key_alias,
        size,
        key_password: &key_password,
        store_password: &store_password,
        format,
    })?;
    AtomicOutput::write(&args.keystore, &store)?;
    load_issuing_key(
        &args.keystore,
        Some(&store_password),
        STORE_PASSWORD_ENV,
        &args.key_alias,
        Some(&key_password),
        KEY_PASSWORD_ENV,
    )
}

fn load_issuing_key(
    keystore: &Path,
    store_password_flag: Option<&str>,
    store_env: &str,
    alias: &str,
    key_password_flag: Option<&str>,
    key_env: &str,
) -> Result<IssuingKey> {
    let store_password = store_password(store_password_flag, store_env)?;
    let key_password = key_password(key_password_flag, key_env);
    let bytes =
        fs::read(keystore).with_context(|| format!("failed to read {}", keystore.display()))?;
    let signing_key = SigningKey::from_keystore(&bytes, &store_password, alias, &key_password)
        .map_err(|error| match error {
            SignError::KeyAliasNotFound { .. } => anyhow::anyhow!(
                "{} does not contain key alias '{alias}'; run generate-keypair first",
                keystore.display()
            ),
            other => other.into(),
        })?;
    Ok(IssuingKey::from_pkcs8_der(&signing_key.private_key_der)?)
}

// ── Passwords ───────────────────────────────────────────────────────────────

fn store_password(flag: Option<&str>, env: &str) -> Result<String> {
    if let Some(password) = flag {
        return Ok(password.to_owned());
    }
    std::env::var(env).with_context(|| format!("{env} must be set, or pass the password as a flag"))
}

/// An absent key password means an empty one, matching official
/// `KeyStoreHelper`, which turns a null `keyPwd` into `char[0]`.
fn key_password(flag: Option<&str>, env: &str) -> String {
    match flag {
        Some(password) => password.to_owned(),
        None => std::env::var(env).unwrap_or_default(),
    }
}

// ── Usage parsing and output ────────────────────────────────────────────────

fn certificate_pem(der: &[u8]) -> Result<String> {
    Ok(Certificate::from_der(der)
        .context("generated certificate could not be parsed back")?
        .to_pem(LineEnding::LF)?)
}

fn required_certificate_file(path: Option<&Path>, flag: &str) -> Result<Vec<u8>> {
    let path = path.ok_or_else(|| {
        anyhow::anyhow!(
            "--{flag} is required when --out-form is certChain \
             (pass --out-form cert for a single certificate)"
        )
    })?;
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    // `getSubCaCertFile`/`getCaCertFile` sort the file leaf-first and take the
    // first certificate.
    let mut chain = SigningKey::cert_chain_from_bytes(&bytes)
        .with_context(|| format!("{} is not a usable certificate file", path.display()))?;
    Ok(chain.remove(0))
}

fn write_text(path: Option<&Path>, force: bool, content: &str) -> Result<()> {
    match path {
        Some(path) => {
            OutputPolicy::new(force).validate_new(path)?;
            AtomicOutput::write(path, content.as_bytes())?;
            println!("{}", path.display());
        }
        // Official `outputString` logs to the console when `-outFile` is empty.
        None => print!("{content}"),
    }
    Ok(())
}
