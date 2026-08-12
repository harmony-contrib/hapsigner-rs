use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use hapsigner::{
    DevelopmentProfileOptions, DevelopmentSigner, FileSigningMaterial, HapSigner, SignOptions,
    SigningAlgorithm, SigningBlockInspector,
};

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
    /// Sign with caller-provided Hvigor-compatible PKCS#12 material.
    SignWithMaterial {
        input: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(long)]
        keystore: PathBuf,
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        certificate: PathBuf,
        #[arg(long)]
        key_alias: String,
        #[arg(long, default_value = "SHA256withECDSA")]
        sign_alg: String,
        #[arg(long, default_value_t = 9)]
        compatible_version: u32,
        #[arg(long)]
        no_code_signing: bool,
        #[arg(long)]
        force: bool,
    },
    /// Print signing-block metadata and the embedded provisioning profile.
    Inspect { input: PathBuf },
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum AppFeature {
    Normal,
    System,
}

struct OutputPolicy {
    force: bool,
}

impl OutputPolicy {
    fn validate(&self, output: &Path) -> Result<()> {
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
}

struct EnvironmentPasswords {
    store: String,
    key: String,
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
            let output = output.unwrap_or_else(|| signed_output_path(&input));
            OutputPolicy { force }.validate(&output)?;
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
        Command::SignWithMaterial {
            input,
            output,
            keystore,
            profile,
            certificate,
            key_alias,
            sign_alg,
            compatible_version,
            no_code_signing,
            force,
        } => {
            let output = output.unwrap_or_else(|| signed_output_path(&input));
            OutputPolicy { force }.validate(&output)?;
            let passwords = EnvironmentPasswords::load()?;
            let material = FileSigningMaterial {
                keystore_path: keystore,
                profile_path: profile,
                certificate_path: certificate,
                key_alias: key_alias.into(),
                store_password: passwords.store.into(),
                key_password: passwords.key.into(),
                algorithm: SigningAlgorithm::from_str(&sign_alg)?,
            };
            HapSigner::new(
                material.load()?,
                SignOptions {
                    compatible_version,
                    code_signing: !no_code_signing,
                },
            )
            .sign_file(&input, &output)?;
            println!("{}", output.display());
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
