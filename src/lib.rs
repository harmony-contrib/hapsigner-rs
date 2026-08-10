//! OpenHarmony HAP signing primitives used by the `hap-sign` CLI.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use cms::builder::{create_signing_time_attribute, SignedDataBuilder, SignerInfoBuilder};
use cms::cert::{CertificateChoices, IssuerAndSerialNumber};
use cms::content_info::ContentInfo;
use cms::signed_data::{EncapsulatedContentInfo, SignedData, SignerIdentifier};
use der::asn1::Any;
use der::{Decode, Encode, EncodePem, Tag};
use p256::ecdsa::{DerSignature, SigningKey};
use p256::pkcs8::DecodePrivateKey;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use spki::AlgorithmIdentifierOwned;
use tempfile::NamedTempFile;
use uuid::Uuid;
use x509_cert::Certificate;

const APP_KEY: &[u8] = include_bytes!("assets/app-key.pk8");
const PROFILE_KEY: &[u8] = include_bytes!("assets/profile-key.pk8");
const APP_LEAF: &[u8] = include_bytes!("assets/app-leaf.der");
const PROFILE_LEAF: &[u8] = include_bytes!("assets/profile-leaf.der");
const APP_CA: &[u8] = include_bytes!("assets/app-ca.der");
const APP_ROOT: &[u8] = include_bytes!("assets/app-root.der");

const EOCD_MAGIC: &[u8; 4] = b"PK\x05\x06";
const SIGNING_MAGIC_V3: &[u8; 16] = b"<hap sign block>";
const SIGNING_BLOCK_VERSION: u32 = 3;
const PROFILE_BLOCK_ID: u32 = 0x2000_0002;
const SIGNATURE_BLOCK_ID: u32 = 0x2000_0000;
const SIGNATURE_ALGORITHM_SHA256_ECDSA: u32 = 0x0000_0201;
const CHUNK_SIZE: usize = 1024 * 1024;

#[derive(Clone, Debug)]
pub struct SignOptions {
    pub bundle_name: String,
    pub apl: String,
    pub app_feature: String,
    pub allowed_acls: Vec<String>,
    pub restricted_permissions: Vec<String>,
    pub device_ids: Vec<String>,
    pub valid_days: u64,
}

impl Default for SignOptions {
    fn default() -> Self {
        Self {
            bundle_name: String::new(),
            apl: "normal".into(),
            app_feature: "hos_normal_app".into(),
            allowed_acls: Vec::new(),
            restricted_permissions: Vec::new(),
            device_ids: vec!["*".into()],
            valid_days: 3650,
        }
    }
}

#[derive(Clone, Debug)]
struct ZipSections {
    sign_start: usize,
    central_directory_start: usize,
    eocd_start: usize,
}

#[derive(Clone, Debug)]
pub struct SigningBlockInfo {
    pub start: usize,
    pub size: usize,
    pub version: u32,
    pub blocks: Vec<(u32, usize, usize)>,
}

/// Sign an unsigned HAP, or replace the existing HAP signing block.
pub fn sign_hap(input: &[u8], options: &SignOptions) -> Result<Vec<u8>> {
    validate_options(options)?;
    let sections = locate_zip_sections(input)?;

    let profile_json = create_profile(options)?;
    let profile = create_cms(&profile_json, PROFILE_KEY, PROFILE_LEAF)?;

    let mut eocd_for_digest = input[sections.eocd_start..].to_vec();
    write_u32_at(
        &mut eocd_for_digest,
        16,
        u32::try_from(sections.sign_start).context("HAP is too large for ZIP32")?,
    )?;

    let chunk_digests = chunk_digests(&[
        &input[..sections.sign_start],
        &input[sections.central_directory_start..sections.eocd_start],
        &eocd_for_digest,
    ]);
    let mut final_digest_input = chunk_digests;
    final_digest_input.extend_from_slice(&profile);
    let content_digest = Sha256::digest(&final_digest_input);

    let digest_message = encode_digest_message(&content_digest);
    let signature = create_cms(&digest_message, APP_KEY, APP_LEAF)?;
    let signing_block =
        create_signing_block(&[(PROFILE_BLOCK_ID, profile), (SIGNATURE_BLOCK_ID, signature)])?;

    let new_cd_offset = sections
        .sign_start
        .checked_add(signing_block.len())
        .context("signed HAP offset overflow")?;
    let mut output_eocd = input[sections.eocd_start..].to_vec();
    write_u32_at(
        &mut output_eocd,
        16,
        u32::try_from(new_cd_offset).context("signed HAP is too large for ZIP32")?,
    )?;

    let mut output = Vec::with_capacity(input.len() + signing_block.len());
    output.extend_from_slice(&input[..sections.sign_start]);
    output.extend_from_slice(&signing_block);
    output.extend_from_slice(&input[sections.central_directory_start..sections.eocd_start]);
    output.extend_from_slice(&output_eocd);
    Ok(output)
}

pub fn sign_file(input: &Path, output: &Path, options: &SignOptions, force: bool) -> Result<()> {
    if input == output {
        bail!("input and output must be different files");
    }
    if output.exists() && !force {
        bail!(
            "output already exists (pass --force to replace it): {}",
            output.display()
        );
    }
    let input_data =
        fs::read(input).with_context(|| format!("failed to read {}", input.display()))?;
    let signed = sign_hap(&input_data, options)?;
    let parent = output.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).with_context(|| format!("failed to create {}", parent.display()))?;
    let mut temporary = NamedTempFile::new_in(parent)
        .with_context(|| format!("failed to create a temporary file in {}", parent.display()))?;
    temporary.write_all(&signed)?;
    temporary.as_file().sync_all()?;
    if force && output.exists() {
        fs::remove_file(output)
            .with_context(|| format!("failed to replace {}", output.display()))?;
    }
    temporary
        .persist(output)
        .map_err(|error| error.error)
        .with_context(|| format!("failed to persist {}", output.display()))?;
    Ok(())
}

pub fn default_output_path(input: &Path) -> PathBuf {
    let stem = input
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("application");
    input.with_file_name(format!("{stem}-signed.hap"))
}

pub fn signing_block_info(hap: &[u8]) -> Result<SigningBlockInfo> {
    let sections = locate_zip_sections(hap)?;
    if sections.sign_start == sections.central_directory_start {
        bail!("HAP has no signing block");
    }
    let cd = sections.central_directory_start;
    let size = read_u64(hap, cd - 28)? as usize;
    let version = read_u32(hap, cd - 4)?;
    let count = read_u32(hap, cd - 32)? as usize;
    let mut blocks = Vec::with_capacity(count);
    for index in 0..count {
        let entry = sections.sign_start + index * 12;
        let block_type = read_u32(hap, entry)?;
        let length = read_u32(hap, entry + 4)? as usize;
        let offset = read_u32(hap, entry + 8)? as usize;
        let value_start = sections
            .sign_start
            .checked_add(offset)
            .context("signing block offset overflow")?;
        let value_end = value_start
            .checked_add(length)
            .context("signing block length overflow")?;
        if value_end > cd - 32 {
            bail!("invalid signing sub-block range");
        }
        blocks.push((block_type, value_start, length));
    }
    Ok(SigningBlockInfo {
        start: sections.sign_start,
        size,
        version,
        blocks,
    })
}

pub fn embedded_profile(hap: &[u8]) -> Result<Value> {
    let info = signing_block_info(hap)?;
    let (_, start, length) = info
        .blocks
        .iter()
        .find(|(block_type, _, _)| *block_type == PROFILE_BLOCK_ID)
        .context("HAP signing block has no provisioning profile")?;
    let cms = &hap[*start..*start + *length];
    let content_info = ContentInfo::from_der(cms).context("invalid profile CMS ContentInfo")?;
    let signed_data = SignedData::from_der(&content_info.content.to_der()?)
        .context("invalid profile CMS SignedData")?;
    let content = signed_data
        .encap_content_info
        .econtent
        .context("profile CMS has no embedded content")?;
    serde_json::from_slice(content.value()).context("profile CMS content is not valid JSON")
}

fn validate_options(options: &SignOptions) -> Result<()> {
    if options.bundle_name.trim().is_empty() {
        bail!("bundle name must not be empty");
    }
    if !matches!(
        options.apl.as_str(),
        "normal" | "system_basic" | "system_core"
    ) {
        bail!("APL must be normal, system_basic, or system_core");
    }
    if !matches!(
        options.app_feature.as_str(),
        "hos_normal_app" | "hos_system_app"
    ) {
        bail!("app feature must be hos_normal_app or hos_system_app");
    }
    if options.valid_days == 0 || options.valid_days > 3650 {
        bail!("valid days must be between 1 and 3650");
    }
    if options.device_ids.is_empty()
        || options
            .device_ids
            .iter()
            .any(|device_id| device_id.trim().is_empty())
    {
        bail!("at least one non-empty device ID is required");
    }
    Ok(())
}

fn create_profile(options: &SignOptions) -> Result<Vec<u8>> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_secs();
    let not_before = now.saturating_sub(300);
    let validity = options
        .valid_days
        .checked_mul(86_400)
        .context("profile validity overflow")?;
    let not_after = now
        .checked_add(validity)
        .context("profile validity overflow")?;

    let app_certificate = Certificate::from_der(APP_LEAF)?
        .to_pem(der::pem::LineEnding::LF)
        .context("failed to encode the application certificate")?;
    let allowed_acls = if options.allowed_acls.is_empty() {
        vec![String::new()]
    } else {
        options.allowed_acls.clone()
    };
    let restricted_permissions = if options.restricted_permissions.is_empty() {
        vec![String::new()]
    } else {
        options.restricted_permissions.clone()
    };

    let profile = json!({
        "version-name": "2.0.0",
        "version-code": 2,
        "uuid": Uuid::new_v4().to_string(),
        "validity": {
            "not-before": not_before,
            "not-after": not_after
        },
        "type": "debug",
        "bundle-info": {
            "developer-id": "OpenHarmony",
            "development-certificate": app_certificate,
            "bundle-name": options.bundle_name,
            "apl": options.apl,
            "app-feature": options.app_feature
        },
        "acls": {
            "allowed-acls": allowed_acls
        },
        "permissions": {
            "restricted-permissions": restricted_permissions
        },
        "debug-info": {
            "device-ids": options.device_ids,
            "device-id-type": "udid"
        },
        "issuer": "pki_internal"
    });
    serde_json::to_vec(&profile).context("failed to serialize the provisioning profile")
}

fn create_cms(content: &[u8], key_der: &[u8], leaf_der: &[u8]) -> Result<Vec<u8>> {
    let secret =
        p256::SecretKey::from_pkcs8_der(key_der).context("invalid embedded signing key")?;
    let signer = SigningKey::from(secret);
    let leaf = Certificate::from_der(leaf_der).context("invalid embedded leaf certificate")?;
    let ca = Certificate::from_der(APP_CA).context("invalid embedded CA certificate")?;
    let root = Certificate::from_der(APP_ROOT).context("invalid embedded root certificate")?;

    let encapsulated = EncapsulatedContentInfo {
        econtent_type: const_oid::db::rfc5911::ID_DATA,
        // OpenHarmony's app verifier reads the digest message directly from
        // PKCS7 SignedData. The HAP signature is therefore attached, just like
        // the provisioning profile (developtools_hapsigner BcPkcs7Generator).
        econtent: Some(Any::new(Tag::OctetString, content.to_vec())?),
    };
    let digest_algorithm = AlgorithmIdentifierOwned {
        oid: const_oid::db::rfc5912::ID_SHA_256,
        parameters: None,
    };
    let signer_identifier = SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
        issuer: leaf.tbs_certificate.issuer.clone(),
        serial_number: leaf.tbs_certificate.serial_number.clone(),
    });
    let mut signer_info = SignerInfoBuilder::new(
        &signer,
        signer_identifier,
        digest_algorithm.clone(),
        &encapsulated,
        None,
    )
    .map_err(cms_error)?;
    // The device verifier uses this attribute when checking every certificate
    // in the chain, so it is required for OpenHarmony compatibility.
    signer_info
        .add_signed_attribute(create_signing_time_attribute().map_err(cms_error)?)
        .map_err(cms_error)?;

    let mut builder = SignedDataBuilder::new(&encapsulated);
    builder
        .add_digest_algorithm(digest_algorithm)
        .map_err(cms_error)?;
    builder
        .add_certificate(CertificateChoices::Certificate(leaf))
        .map_err(cms_error)?;
    builder
        .add_certificate(CertificateChoices::Certificate(ca))
        .map_err(cms_error)?;
    builder
        .add_certificate(CertificateChoices::Certificate(root))
        .map_err(cms_error)?;
    builder
        .add_signer_info::<SigningKey, DerSignature>(signer_info)
        .map_err(cms_error)?;
    let content_info = builder.build().map_err(cms_error)?;
    content_info
        .to_der()
        .context("failed to encode CMS SignedData")
}

fn cms_error(error: cms::builder::Error) -> anyhow::Error {
    anyhow!(error.to_string())
}

fn locate_zip_sections(input: &[u8]) -> Result<ZipSections> {
    let search_start = input.len().saturating_sub(65_557);
    let relative = input[search_start..]
        .windows(EOCD_MAGIC.len())
        .rposition(|window| window == EOCD_MAGIC)
        .context("ZIP end-of-central-directory record was not found")?;
    let eocd_start = search_start + relative;
    if eocd_start + 22 > input.len() {
        bail!("truncated ZIP end-of-central-directory record");
    }
    let comment_length = read_u16(input, eocd_start + 20)? as usize;
    if eocd_start + 22 + comment_length != input.len() {
        bail!("invalid ZIP end-of-central-directory comment length");
    }
    let central_directory_size = read_u32(input, eocd_start + 12)? as usize;
    let central_directory_start = read_u32(input, eocd_start + 16)? as usize;
    if central_directory_size == u32::MAX as usize || central_directory_start == u32::MAX as usize {
        bail!("ZIP64 HAP files are not supported");
    }
    if central_directory_start
        .checked_add(central_directory_size)
        .context("central-directory range overflow")?
        != eocd_start
    {
        bail!("invalid ZIP central-directory range");
    }

    let mut sign_start = central_directory_start;
    if central_directory_start >= 32
        && &input[central_directory_start - 20..central_directory_start - 4] == SIGNING_MAGIC_V3
    {
        let size = read_u64(input, central_directory_start - 28)? as usize;
        if size < 32 || size > central_directory_start {
            bail!("invalid HAP signing-block size");
        }
        sign_start = central_directory_start - size;
        let version = read_u32(input, central_directory_start - 4)?;
        if version != SIGNING_BLOCK_VERSION {
            bail!("unsupported HAP signing-block version {version}");
        }
    }
    Ok(ZipSections {
        sign_start,
        central_directory_start,
        eocd_start,
    })
}

fn chunk_digests(sections: &[&[u8]]) -> Vec<u8> {
    let chunk_count = sections
        .iter()
        .map(|section| section.len().div_ceil(CHUNK_SIZE))
        .sum::<usize>();
    let mut output = Vec::with_capacity(5 + chunk_count * 32);
    output.push(0x5a);
    output.extend_from_slice(&(chunk_count as u32).to_le_bytes());
    for section in sections {
        for chunk in section.chunks(CHUNK_SIZE) {
            let mut hasher = Sha256::new();
            hasher.update([0xa5]);
            hasher.update((chunk.len() as u32).to_le_bytes());
            hasher.update(chunk);
            output.extend_from_slice(&hasher.finalize());
        }
    }
    output
}

fn encode_digest_message(digest: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(20 + digest.len());
    output.extend_from_slice(&2u32.to_le_bytes());
    output.extend_from_slice(&1u32.to_le_bytes());
    // Length excludes its own four-byte field. See SignHap::
    // EncodeListOfPairsToByteArray and HapVerifyV2::GetDigestAndAlgorithm.
    output.extend_from_slice(&(8u32 + digest.len() as u32).to_le_bytes());
    output.extend_from_slice(&SIGNATURE_ALGORITHM_SHA256_ECDSA.to_le_bytes());
    output.extend_from_slice(&(digest.len() as u32).to_le_bytes());
    output.extend_from_slice(digest);
    output
}

fn create_signing_block(blocks: &[(u32, Vec<u8>)]) -> Result<Vec<u8>> {
    let header_size = blocks
        .len()
        .checked_mul(12)
        .context("too many signing sub-blocks")?;
    let values_size = blocks.iter().try_fold(0usize, |total, (_, value)| {
        total
            .checked_add(value.len())
            .context("signing block is too large")
    })?;
    let total_size = header_size
        .checked_add(values_size)
        .and_then(|size| size.checked_add(32))
        .context("signing block is too large")?;
    let mut output = Vec::with_capacity(total_size);
    let mut offset = header_size;
    for (block_type, value) in blocks {
        output.extend_from_slice(&block_type.to_le_bytes());
        output.extend_from_slice(
            &u32::try_from(value.len())
                .context("signing sub-block is too large")?
                .to_le_bytes(),
        );
        output.extend_from_slice(
            &u32::try_from(offset)
                .context("signing sub-block offset is too large")?
                .to_le_bytes(),
        );
        offset += value.len();
    }
    for (_, value) in blocks {
        output.extend_from_slice(value);
    }
    output.extend_from_slice(
        &u32::try_from(blocks.len())
            .context("too many signing sub-blocks")?
            .to_le_bytes(),
    );
    output.extend_from_slice(&(total_size as u64).to_le_bytes());
    output.extend_from_slice(SIGNING_MAGIC_V3);
    output.extend_from_slice(&SIGNING_BLOCK_VERSION.to_le_bytes());
    debug_assert_eq!(output.len(), total_size);
    Ok(output)
}

fn read_u16(input: &[u8], offset: usize) -> Result<u16> {
    let bytes = input
        .get(offset..offset + 2)
        .context("unexpected end of file")?;
    Ok(u16::from_le_bytes(
        bytes.try_into().expect("two-byte slice"),
    ))
}

fn read_u32(input: &[u8], offset: usize) -> Result<u32> {
    let bytes = input
        .get(offset..offset + 4)
        .context("unexpected end of file")?;
    Ok(u32::from_le_bytes(
        bytes.try_into().expect("four-byte slice"),
    ))
}

fn read_u64(input: &[u8], offset: usize) -> Result<u64> {
    let bytes = input
        .get(offset..offset + 8)
        .context("unexpected end of file")?;
    Ok(u64::from_le_bytes(
        bytes.try_into().expect("eight-byte slice"),
    ))
}

fn write_u32_at(output: &mut [u8], offset: usize, value: u32) -> Result<()> {
    let target = output
        .get_mut(offset..offset + 4)
        .context("unexpected end of file")?;
    target.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tiny_zip() -> Vec<u8> {
        let name = b"module.json";
        let content = b"{}";
        let crc = 0xa3a6_ba2d_u32;
        let mut zip = Vec::new();
        zip.extend_from_slice(b"PK\x03\x04");
        zip.extend_from_slice(&20u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&crc.to_le_bytes());
        zip.extend_from_slice(&(content.len() as u32).to_le_bytes());
        zip.extend_from_slice(&(content.len() as u32).to_le_bytes());
        zip.extend_from_slice(&(name.len() as u16).to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(name);
        zip.extend_from_slice(content);
        let cd_start = zip.len();
        zip.extend_from_slice(b"PK\x01\x02");
        zip.extend_from_slice(&20u16.to_le_bytes());
        zip.extend_from_slice(&20u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&crc.to_le_bytes());
        zip.extend_from_slice(&(content.len() as u32).to_le_bytes());
        zip.extend_from_slice(&(content.len() as u32).to_le_bytes());
        zip.extend_from_slice(&(name.len() as u16).to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u32.to_le_bytes());
        zip.extend_from_slice(&0u32.to_le_bytes());
        zip.extend_from_slice(name);
        let cd_size = zip.len() - cd_start;
        zip.extend_from_slice(EOCD_MAGIC);
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&1u16.to_le_bytes());
        zip.extend_from_slice(&1u16.to_le_bytes());
        zip.extend_from_slice(&(cd_size as u32).to_le_bytes());
        zip.extend_from_slice(&(cd_start as u32).to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip
    }

    #[test]
    fn signs_and_replaces_a_v3_block() {
        let options = SignOptions {
            bundle_name: "com.example.test".into(),
            ..Default::default()
        };
        let signed = sign_hap(&tiny_zip(), &options).unwrap();
        let info = signing_block_info(&signed).unwrap();
        assert_eq!(info.version, 3);
        assert_eq!(info.blocks.len(), 2);
        for (_, offset, length) in &info.blocks {
            let content_info = ContentInfo::from_der(&signed[*offset..*offset + *length]).unwrap();
            let signed_data =
                SignedData::from_der(&content_info.content.to_der().unwrap()).unwrap();
            assert!(signed_data.encap_content_info.econtent.is_some());
            let signer_info = signed_data.signer_infos.0.get(0).unwrap();
            assert!(signer_info
                .signed_attrs
                .as_ref()
                .unwrap()
                .iter()
                .any(|attribute| { attribute.oid == const_oid::db::rfc5911::ID_SIGNING_TIME }));
        }
        let profile = embedded_profile(&signed).unwrap();
        assert_eq!(profile["bundle-info"]["bundle-name"], "com.example.test");

        let resigned = sign_hap(&signed, &options).unwrap();
        assert_eq!(signing_block_info(&resigned).unwrap().blocks.len(), 2);
        assert!(resigned.len() < signed.len() + info.size);
    }

    #[test]
    fn rejects_invalid_profile_parameters() {
        let options = SignOptions::default();
        let error = sign_hap(&tiny_zip(), &options).unwrap_err();
        assert!(error.to_string().contains("bundle name"));
    }

    #[test]
    fn encodes_the_device_verifier_digest_message_layout() {
        let digest = [0x5a; 32];
        let message = encode_digest_message(&digest);
        assert_eq!(message.len(), 52);
        assert_eq!(read_u32(&message, 0).unwrap(), 2);
        assert_eq!(read_u32(&message, 4).unwrap(), 1);
        assert_eq!(read_u32(&message, 8).unwrap(), 40);
        assert_eq!(read_u32(&message, 12).unwrap(), 0x201);
        assert_eq!(read_u32(&message, 16).unwrap(), 32);
        assert_eq!(&message[20..], &digest);
    }
}
