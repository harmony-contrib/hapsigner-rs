use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use der::pem::LineEnding;
use der::{Decode, EncodePem};
use hapsigner::{
    ApplicationVerifier, DevelopmentProfileOptions, DevelopmentSigner, FileSigningMaterial,
    HapSigner, InputFormat, ProfileSigner, ProfileVerifier, SignError, SignOptions,
    SigningAlgorithm, SigningBlockInspector, SigningCapability, SigningKey, SigningMaterial,
};
use tempfile::NamedTempFile;
use x509_cert::Certificate;

mod cli_pki;

use cli_pki::{CaArgs, CertificateArgs, CsrArgs, EndCertificateArgs, KeyPairArgs};

const STORE_PASSWORD_ENV: &str = "HAPSIGNER_STORE_PASSWORD";
const KEY_PASSWORD_ENV: &str = "HAPSIGNER_KEY_PASSWORD";

#[derive(Parser, Debug)]
#[command(name = "hap-sign", version, about = "Java-free OpenHarmony HAP signer")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Sign with the embedded public development identity for QEMU/local use.
    Sign {
        input: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(long)]
        bundle_name: String,
        #[arg(long, default_value = "normal")]
        apl: String,
        #[arg(long, value_enum, default_value_t = AppFeature::Normal)]
        app_feature: AppFeature,
        #[arg(long = "acl")]
        allowed_acls: Vec<String>,
        #[arg(long = "restricted-permission")]
        restricted_permissions: Vec<String>,
        #[arg(long = "device-id", default_value = "*")]
        device_ids: Vec<String>,
        #[arg(long, default_value_t = 3650)]
        valid_days: u64,
        #[arg(long, default_value_t = 9)]
        compatible_version: u32,
        #[arg(long)]
        no_code_signing: bool,
        #[arg(long)]
        force: bool,
    },
    /// Official-compatible application package and binary signing command.
    #[command(name = "sign-app", alias = "sign-with-material")]
    SignApp {
        input: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(long)]
        keystore: PathBuf,
        #[arg(long)]
        profile: Option<PathBuf>,
        #[arg(long)]
        certificate: PathBuf,
        #[arg(long)]
        key_alias: String,
        #[arg(long, default_value = "SHA256withECDSA")]
        sign_alg: String,
        #[arg(long, default_value_t = 9)]
        compatible_version: u32,
        #[arg(long, value_enum, default_value_t = AppInputFormat::Zip)]
        in_form: AppInputFormat,
        #[arg(long, default_value_t = 1)]
        profile_signed: u8,
        #[arg(long)]
        proof: Option<PathBuf>,
        #[arg(long)]
        property: Option<PathBuf>,
        #[arg(long)]
        no_code_signing: bool,
        #[arg(long)]
        force: bool,
        #[arg(long, value_enum, default_value_t = SigningMode::LocalSign)]
        mode: SigningMode,
    },
    /// Sign an unsigned provisioning-profile JSON document.
    #[command(name = "sign-profile")]
    SignProfile {
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(long)]
        keystore: PathBuf,
        #[arg(long)]
        certificate: PathBuf,
        #[arg(long)]
        key_alias: String,
        #[arg(long, default_value = "SHA256withECDSA")]
        sign_alg: String,
        #[arg(long, value_enum, default_value_t = SigningMode::LocalSign)]
        mode: SigningMode,
        #[arg(long)]
        force: bool,
    },
    /// Verify ZIP/ELF applications and export their certificate/profile data.
    #[command(name = "verify-app")]
    VerifyApp {
        input: PathBuf,
        #[arg(long)]
        out_cert_chain: PathBuf,
        #[arg(long)]
        out_profile: PathBuf,
        #[arg(long)]
        out_proof: Option<PathBuf>,
        #[arg(long, value_enum, default_value_t = AppInputFormat::Zip)]
        in_form: AppInputFormat,
    },
    /// Verify a signed provisioning profile and print or persist its result.
    #[command(name = "verify-profile")]
    VerifyProfile {
        input: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Print signing-block metadata and the embedded provisioning profile.
    Inspect { input: PathBuf },
    /// Create a key pair inside a JKS or PKCS#12 keystore.
    #[command(name = "generate-keypair")]
    GenerateKeyPair(KeyPairArgs),
    /// Emit a PKCS#10 certification request for an existing key.
    #[command(name = "generate-csr")]
    GenerateCsr(CsrArgs),
    /// Issue a certificate with full control over its extensions.
    #[command(name = "generate-cert")]
    GenerateCert(CertificateArgs),
    /// Create a root or subordinate CA certificate.
    #[command(name = "generate-ca")]
    GenerateCa(CaArgs),
    /// Issue an application-signing certificate.
    #[command(name = "generate-app-cert")]
    GenerateAppCert(EndCertificateArgs),
    /// Issue a provisioning-profile-signing certificate.
    #[command(name = "generate-profile-cert")]
    GenerateProfileCert(EndCertificateArgs),
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum AppFeature {
    Normal,
    System,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum AppInputFormat {
    Zip,
    Elf,
    Bin,
}

#[derive(Copy, Clone, Debug, ValueEnum, PartialEq, Eq)]
enum SigningMode {
    #[value(name = "localSign", alias = "local-sign")]
    LocalSign,
    #[value(name = "remoteSign", alias = "remote-sign")]
    RemoteSign,
    #[value(name = "remoteResign", alias = "remote-resign")]
    RemoteResign,
}

impl SigningMode {
    fn require_local(self) -> Result<()> {
        match self {
            Self::LocalSign => Ok(()),
            Self::RemoteSign => Err(SignError::UnsupportedOperation(
                "remoteSign requires an injected ExternalSigner; official RemoteSigner is not implemented"
                    .to_owned(),
            )
            .into()),
            Self::RemoteResign => Err(SignError::UnsupportedOperation(
                "official SignToolServiceImpl.remoteResign is not implemented".to_owned(),
            )
            .into()),
        }
    }
}

impl From<AppInputFormat> for InputFormat {
    fn from(value: AppInputFormat) -> Self {
        match value {
            AppInputFormat::Zip => Self::Zip,
            AppInputFormat::Elf => Self::Elf,
            AppInputFormat::Bin => Self::Bin,
        }
    }
}

pub(crate) struct OutputPolicy {
    force: bool,
}

impl OutputPolicy {
    pub(crate) fn new(force: bool) -> Self {
        Self { force }
    }

    /// Refuse to replace an existing file unless `--force` was given.
    pub(crate) fn validate_new(&self, output: &Path) -> Result<()> {
        if output
            .try_exists()
            .with_context(|| format!("failed to inspect output path {}", output.display()))?
            && !self.force
        {
            bail!(
                "output already exists (pass --force to replace it): {}",
                output.display()
            );
        }
        Ok(())
    }

    fn validate(&self, input: &Path, output: &Path) -> Result<()> {
        if output
            .try_exists()
            .with_context(|| format!("failed to inspect output path {}", output.display()))?
            && !Self::paths_overlap(input, output)?
            && !self.force
        {
            bail!(
                "output already exists (pass --force to replace it): {}",
                output.display()
            );
        }
        Ok(())
    }

    fn paths_overlap(input: &Path, output: &Path) -> Result<bool> {
        if input == output {
            return Ok(true);
        }
        let input = fs::canonicalize(input)
            .with_context(|| format!("failed to resolve input path {}", input.display()))?;
        let output = fs::canonicalize(output)
            .with_context(|| format!("failed to resolve output path {}", output.display()))?;
        Ok(input == output)
    }

    fn signed_output_path(input: &Path) -> PathBuf {
        let stem = input
            .file_stem()
            .unwrap_or_else(|| OsStr::new("application"));
        let mut file_name = OsString::from(stem);
        file_name.push("-signed");
        if let Some(extension) = input.extension().filter(|value| !value.is_empty()) {
            file_name.push(".");
            file_name.push(extension);
        }
        input.with_file_name(file_name)
    }
}

struct EnvironmentPasswords {
    store: String,
    key: String,
}

pub(crate) struct AtomicOutput;

impl AtomicOutput {
    pub(crate) fn write(path: &Path, bytes: &[u8]) -> Result<()> {
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
        let mut temporary = NamedTempFile::new_in(parent)
            .with_context(|| format!("failed to create temporary file in {}", parent.display()))?;
        temporary
            .write_all(bytes)
            .with_context(|| format!("failed to write temporary output for {}", path.display()))?;
        temporary.as_file().sync_all()?;
        temporary.persist(path).map_err(|error| error.error)?;
        Ok(())
    }
}

struct VerificationOutput;

impl VerificationOutput {
    fn certificate_chain(path: &Path, certificates: &[Vec<u8>]) -> Result<()> {
        let mut output = String::new();
        for certificate in certificates {
            let certificate = Certificate::from_der(certificate).with_context(|| {
                format!("invalid verification certificate for {}", path.display())
            })?;
            output.push_str(&certificate.tbs_certificate.subject.to_string());
            output.push('\n');
            output.push_str(&certificate.to_pem(LineEnding::LF)?);
        }
        AtomicOutput::write(path, output.as_bytes())
    }

    fn profile_result(content: &[u8]) -> Result<Vec<u8>> {
        let content: serde_json::Value = serde_json::from_slice(content)?;
        Ok(serde_json::to_vec_pretty(&serde_json::json!({
            "verifiedPassed": true,
            "message": "OK",
            "content": content,
        }))?)
    }
}

impl EnvironmentPasswords {
    fn load() -> Result<Self> {
        Ok(Self {
            store: Self::required(STORE_PASSWORD_ENV)?,
            key: Self::required(KEY_PASSWORD_ENV)?,
        })
    }

    fn required(name: &str) -> Result<String> {
        std::env::var(name).with_context(|| format!("{name} must be set for sign-with-material"))
    }
}

impl AppFeature {
    fn profile_value(self) -> &'static str {
        match self {
            Self::Normal => "hos_normal_app",
            Self::System => "hos_system_app",
        }
    }
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Sign {
            input,
            output,
            bundle_name,
            apl,
            app_feature,
            allowed_acls,
            restricted_permissions,
            device_ids,
            valid_days,
            compatible_version,
            no_code_signing,
            force,
        } => {
            let output = output.unwrap_or_else(|| OutputPolicy::signed_output_path(&input));
            OutputPolicy { force }.validate(&input, &output)?;
            let signer = DevelopmentSigner::new(
                DevelopmentProfileOptions {
                    bundle_name,
                    apl,
                    app_feature: app_feature.profile_value().into(),
                    allowed_acls,
                    restricted_permissions,
                    device_ids,
                    valid_days,
                },
                SignOptions {
                    compatible_version,
                    code_signing: !no_code_signing,
                },
            )?;
            signer.sign_file(&input, &output)?;
            println!("{}", output.display());
        }
        Command::SignApp {
            input,
            output,
            keystore,
            profile,
            certificate,
            key_alias,
            sign_alg,
            compatible_version,
            in_form,
            profile_signed,
            proof,
            property,
            no_code_signing,
            force,
            mode,
        } => {
            mode.require_local()?;
            let output = output.unwrap_or_else(|| OutputPolicy::signed_output_path(&input));
            OutputPolicy { force }.validate(&input, &output)?;
            let passwords = EnvironmentPasswords::load()?;
            let profile_signed = match profile_signed {
                0 => false,
                1 => true,
                value => bail!("profile-signed must be 0 or 1, got {value}"),
            };
            let algorithm = SigningAlgorithm::from_str(&sign_alg)?;
            let mut material = if let Some(profile) = profile {
                FileSigningMaterial {
                    keystore_path: keystore,
                    profile_path: profile,
                    certificate_path: certificate,
                    key_alias: key_alias.into(),
                    store_password: passwords.store.into(),
                    key_password: passwords.key.into(),
                    profile_signed,
                    algorithm,
                }
                .load()?
            } else {
                if !matches!(in_form, AppInputFormat::Elf) {
                    bail!("profile is required for ZIP and BIN input");
                }
                if !profile_signed {
                    bail!("official sign-app forbids profileSigned=0 for ELF input");
                }
                let keystore_bytes = fs::read(&keystore)
                    .with_context(|| format!("failed to read {}", keystore.display()))?;
                let certificate_bytes = fs::read(&certificate)
                    .with_context(|| format!("failed to read {}", certificate.display()))?;
                let mut signing_key = SigningKey::from_keystore(
                    &keystore_bytes,
                    &passwords.store,
                    &key_alias,
                    &passwords.key,
                )?;
                signing_key.cert_chain = SigningKey::cert_chain_from_bytes(&certificate_bytes)?;
                SigningMaterial::without_profile(signing_key, algorithm)
            };
            if let Some(path) = proof {
                material =
                    material.with_proof_of_rotation(fs::read(&path).with_context(|| {
                        format!("failed to read proof-of-rotation file {}", path.display())
                    })?)?;
            }
            if let Some(path) = property {
                material = material.with_property(fs::read(&path).with_context(|| {
                    format!("failed to read property file {}", path.display())
                })?)?;
            }
            HapSigner::new(
                material,
                SignOptions {
                    compatible_version,
                    code_signing: !no_code_signing,
                },
            )
            .sign_application_file(&input, &output, in_form.into())?;
            println!("{}", output.display());
        }
        Command::SignProfile {
            input,
            output,
            keystore,
            certificate,
            key_alias,
            sign_alg,
            mode,
            force,
        } => {
            mode.require_local()?;
            OutputPolicy { force }.validate(&input, &output)?;
            let passwords = EnvironmentPasswords::load()?;
            let keystore_bytes = fs::read(&keystore)
                .with_context(|| format!("failed to read {}", keystore.display()))?;
            let certificate_bytes = fs::read(&certificate)
                .with_context(|| format!("failed to read {}", certificate.display()))?;
            let mut signing_key = SigningKey::from_keystore(
                &keystore_bytes,
                &passwords.store,
                &key_alias,
                &passwords.key,
            )?;
            signing_key.cert_chain = SigningKey::cert_chain_from_bytes(&certificate_bytes)?;
            let profile =
                fs::read(&input).with_context(|| format!("failed to read {}", input.display()))?;
            let signed = ProfileSigner::new(signing_key, SigningAlgorithm::from_str(&sign_alg)?)
                .sign(&profile)?;
            AtomicOutput::write(&output, &signed)?;
            println!("{}", output.display());
        }
        Command::VerifyApp {
            input,
            out_cert_chain,
            out_profile,
            out_proof,
            in_form,
        } => {
            let bytes =
                fs::read(&input).with_context(|| format!("failed to read {}", input.display()))?;
            let verified = ApplicationVerifier::new(&bytes).verify(in_form.into())?;
            VerificationOutput::certificate_chain(&out_cert_chain, &verified.certificates)?;
            if let Some(profile) = verified.profile {
                AtomicOutput::write(&out_profile, &profile)?;
            }
            if let (Some(path), Some(proof)) = (out_proof, verified.proof_of_rotation) {
                AtomicOutput::write(&path, &proof)?;
            }
            println!("verify signature success");
        }
        Command::VerifyProfile { input, output } => {
            let bytes =
                fs::read(&input).with_context(|| format!("failed to read {}", input.display()))?;
            let verified = ProfileVerifier::verify(&bytes)?;
            let result = VerificationOutput::profile_result(&verified.content)?;
            if let Some(output) = output {
                AtomicOutput::write(&output, &result)?;
                println!("{}", output.display());
            } else {
                println!("{}", String::from_utf8(result)?);
            }
        }
        Command::GenerateKeyPair(args) => cli_pki::run_generate_keypair(&args)?,
        Command::GenerateCsr(args) => cli_pki::run_generate_csr(&args)?,
        Command::GenerateCert(args) => cli_pki::run_generate_cert(&args)?,
        Command::GenerateCa(args) => cli_pki::run_generate_ca(&args)?,
        Command::GenerateAppCert(args) => {
            cli_pki::run_generate_end_cert(&args, SigningCapability::Application)?
        }
        Command::GenerateProfileCert(args) => {
            cli_pki::run_generate_end_cert(&args, SigningCapability::Profile)?
        }
        Command::Inspect { input } => {
            let data =
                fs::read(&input).with_context(|| format!("failed to read {}", input.display()))?;
            let inspector = SigningBlockInspector::new(&data);
            let info = inspector.inspect()?;
            println!(
                "signing-block: version={}, size={}, sub-blocks={}",
                info.version,
                info.size,
                info.blocks.len()
            );
            for block in &info.blocks {
                println!(
                    "sub-block: type=0x{:08x}, offset={}, length={}",
                    block.block_type, block.offset, block.length
                );
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&inspector.embedded_profile()?)?
            );
        }
    }
    Ok(())
}
