use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use hapsigner::{
    default_output_path, embedded_profile, sign_file, signing_block_info, SignOptions,
};

#[derive(Parser, Debug)]
#[command(name = "hap-sign", version, about = "Java-free OpenHarmony HAP signer")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Sign an unsigned HAP or replace its existing signing block.
    Sign {
        /// Input HAP file.
        input: PathBuf,
        /// Output HAP file (defaults to <input>-signed.hap).
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Bundle name from AppScope/app.json5.
        #[arg(long)]
        bundle_name: String,
        /// Application privilege level.
        #[arg(long, default_value = "normal")]
        apl: String,
        /// Application feature recorded in the provisioning profile.
        #[arg(long, value_enum, default_value_t = AppFeature::Normal)]
        app_feature: AppFeature,
        /// Add an allowed ACL to the provisioning profile; may be repeated.
        #[arg(long = "acl")]
        allowed_acls: Vec<String>,
        /// Add a restricted permission to the profile; may be repeated.
        #[arg(long = "restricted-permission")]
        restricted_permissions: Vec<String>,
        /// Authorize a device UDID; may be repeated. QEMU developer images accept the default marker.
        #[arg(long = "device-id", default_value = "*")]
        device_ids: Vec<String>,
        /// Profile lifetime in days (maximum 3650).
        #[arg(long, default_value_t = 3650)]
        valid_days: u64,
        /// Replace an existing output file.
        #[arg(long)]
        force: bool,
    },
    /// Print signing-block metadata and the embedded provisioning profile.
    Inspect {
        /// Signed HAP file.
        input: PathBuf,
    },
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum AppFeature {
    Normal,
    System,
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
            force,
        } => {
            let output = output.unwrap_or_else(|| default_output_path(&input));
            let options = SignOptions {
                bundle_name,
                apl,
                app_feature: app_feature.profile_value().into(),
                allowed_acls,
                restricted_permissions,
                device_ids,
                valid_days,
            };
            sign_file(&input, &output, &options, force)?;
            println!("{}", output.display());
        }
        Command::Inspect { input } => {
            let data =
                fs::read(&input).with_context(|| format!("failed to read {}", input.display()))?;
            let info = signing_block_info(&data)?;
            let profile = embedded_profile(&data)?;
            println!(
                "signing-block: version={}, size={}, sub-blocks={}",
                info.version,
                info.size,
                info.blocks.len()
            );
            for (block_type, offset, length) in &info.blocks {
                println!("sub-block: type=0x{block_type:08x}, offset={offset}, length={length}");
            }
            println!("{}", serde_json::to_string_pretty(&profile)?);
        }
    }
    Ok(())
}
