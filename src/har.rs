//! HarmonyOS SDK directory signing (`sdk-sign-tool-full.jar sign-har`).
//!
//! Hvigor's `PackageSignHar` stages a task directory that contains `package/`
//! and asks the HarmonyOS SDK directory signer to add
//! `.CodeSignature/{profile,codeFileList,signature}` in place. This module
//! implements that protocol natively, so a package/sign pipeline does not
//! need a Java runtime.
//!
//! The format is observed from `sdk-dir-signer` 7.0.0.304
//! (`com.huawei.hmos.security.pki.sdk.sign.SdkSigner`):
//!
//! * `.CodeSignature` is deleted and recreated on every sign. The profile, when
//!   present, is copied to `.CodeSignature/profile` *before* the file list is
//!   produced, so the profile is itself a signed entry.
//! * Every regular file below the input directory is listed, including
//!   `.CodeSignature/profile` but excluding `codeFileList` and `signature`
//!   because those are written after the list is produced. Entries are sorted
//!   by file name (`File.getName()`), then by manifest path for determinism.
//! * `codeFileList` is compact Gson JSON with `version: 1.0`, digest algorithm
//!   `SHA-256`, and standard Base64 digests. Gson's default HTML escaping is
//!   applied (`<`, `>`, `&`, `=`, and `'` become `\u00xx`).
//! * `signature` is an attached CMS SignedData over the exact `codeFileList`
//!   bytes, with `contentType`, `signingTime`, and `messageDigest` signed
//!   attributes. Top-level `digestAlgorithm` identifiers omit the optional
//!   parameters, as do the HAP/profile generators; RSA-PSS parameters nest a
//!   digest identifier with an explicit NULL.
//!
//! This module only mutates the staged directory. Hvigor project discovery,
//! staging `package/`, and repacking the signed archive remain the caller's
//! responsibility.

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::time::SystemTime;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use sha2::{Digest, Sha256};

use crate::error::SignError;
use crate::keystore::SigningKey;
use crate::pkcs7;
use crate::remote::SigningIdentity;
use crate::SigningAlgorithm;

/// Directory that carries the HAR signature material.
pub const SIGNATURE_DIR: &str = ".CodeSignature";
/// File name of the signed manifest.
pub const CODE_FILE_LIST: &str = "codeFileList";
/// File name of the CMS signature.
pub const SIGNATURE_FILE: &str = "signature";
/// File name of the copied provisioning profile.
pub const PROFILE_FILE: &str = "profile";

const CODE_FILE_LIST_VERSION: &str = "1.0";
const FILE_DIGEST_ALG: &str = "SHA-256";

/// Caller-owned material for signing a staged HAR directory.
pub struct HarSigningMaterial<'a> {
    /// JKS or PKCS#12 keystore bytes. The format is detected from the header.
    pub keystore: &'a [u8],
    pub store_password: &'a str,
    pub key_alias: &'a str,
    pub key_password: &'a str,
    /// Certificate chain supplied as official `-signCertFile`.
    ///
    /// PEM or concatenated DER. The chain is sorted leaf-first and validated,
    /// matching `SdkSigner.getPublicCerts`.
    pub sign_certificate_chain: &'a [u8],
    /// Provisioning profile bytes copied to `.CodeSignature/profile`.
    pub profile: Option<&'a [u8]>,
    pub algorithm: SigningAlgorithm,
}

/// Signs a Hvigor `PackageSignHar` task directory.
pub struct HarSigner {
    identity: SigningIdentity,
    algorithm: SigningAlgorithm,
    profile: Option<Vec<u8>>,
}

impl HarSigner {
    /// Build a signer from an already loaded key and leaf-first certificate
    /// chain. The CMS certificate set is DER-sorted independently.
    pub fn new(signing_key: SigningKey, algorithm: SigningAlgorithm) -> Self {
        Self {
            identity: SigningIdentity::Local(signing_key),
            algorithm,
            profile: None,
        }
    }

    /// Load the private key from a keystore and the embedded certificate chain
    /// from official `-signCertFile` material.
    pub fn from_keystore(material: HarSigningMaterial<'_>) -> Result<Self, SignError> {
        let mut signing_key = SigningKey::from_keystore(
            material.keystore,
            material.store_password,
            material.key_alias,
            material.key_password,
        )?;
        signing_key.cert_chain =
            SigningKey::cert_chain_from_bytes(material.sign_certificate_chain)?;
        Ok(Self {
            identity: SigningIdentity::Local(signing_key),
            algorithm: material.algorithm,
            profile: material.profile.map(ToOwned::to_owned),
        })
    }

    /// Copy a provisioning profile into the signed directory.
    pub fn with_profile(mut self, profile: Vec<u8>) -> Self {
        self.profile = Some(profile);
        self
    }

    /// Add `.CodeSignature/{profile,codeFileList,signature}` to `directory`.
    ///
    /// Any existing `.CodeSignature` is replaced, matching `SdkSigner.signSdk`.
    pub fn sign_directory(&self, directory: &Path) -> Result<(), SignError> {
        let root = canonical_directory(directory)?;
        let signature_dir = directory.join(SIGNATURE_DIR);
        remove_path(&signature_dir)?;
        fs::create_dir(&signature_dir).map_err(|error| io_error(&signature_dir, error))?;

        if let Some(profile) = &self.profile {
            let profile_path = signature_dir.join(PROFILE_FILE);
            fs::write(&profile_path, profile).map_err(|error| io_error(&profile_path, error))?;
        }

        let entries = collect_file_entries(&root)?;
        if entries.is_empty() {
            return Err(SignError::Config(format!(
                "no files to sign below {}",
                root.display()
            )));
        }
        let mut manifest = Vec::with_capacity(entries.len());
        for entry in &entries {
            manifest.push((entry.relative.clone(), sha256_base64(&entry.canonical)?));
        }
        let code_file_list = render_code_file_list(&manifest);

        let code_file_list_path = signature_dir.join(CODE_FILE_LIST);
        fs::write(&code_file_list_path, &code_file_list)
            .map_err(|error| io_error(&code_file_list_path, error))?;

        let signature =
            pkcs7::build_har_cms_signed_data(&code_file_list, &self.identity, self.algorithm)?;
        let signature_path = signature_dir.join(SIGNATURE_FILE);
        fs::write(&signature_path, signature).map_err(|error| io_error(&signature_path, error))?;
        Ok(())
    }
}

/// Result of verifying a signed HAR directory.
#[derive(Debug)]
pub struct HarVerification {
    /// DER certificates carried by the CMS signature.
    pub certificates: Vec<Vec<u8>>,
    pub algorithm: SigningAlgorithm,
    pub signing_time: Option<SystemTime>,
    /// Bytes of `.CodeSignature/profile`, when the package carries one.
    pub profile: Option<Vec<u8>>,
    /// Number of files covered by the signed manifest.
    pub file_count: usize,
}

/// Verifies the `.CodeSignature` material of a staged HAR directory.
pub struct HarVerifier;

impl HarVerifier {
    /// Verify the CMS signature, the manifest bytes, and every file digest.
    ///
    /// This mirrors `SdkVerifier.verifySdkIntegrity`: the CMS signature is
    /// checked against the embedded certificate, the attached content must
    /// equal `codeFileList`, and the file set must match the manifest exactly.
    /// Trust anchoring against a source certificate list is a separate policy
    /// and is not applied here.
    pub fn verify_directory(directory: &Path) -> Result<HarVerification, SignError> {
        let root = canonical_directory(directory)?;
        let signature_dir = directory.join(SIGNATURE_DIR);
        let signature_path = signature_dir.join(SIGNATURE_FILE);
        let code_file_list_path = signature_dir.join(CODE_FILE_LIST);

        let signature = read_signature_material(&signature_path)?;
        let code_file_list = read_signature_material(&code_file_list_path)?;

        let verified = pkcs7::verify_cms_signed_data(&signature)?;
        if verified.content != code_file_list {
            return Err(SignError::VerificationFailed(
                "codeFileList does not match the CMS signed content".to_owned(),
            ));
        }
        let manifest = parse_code_file_list(&verified.content)?;

        let manifest_relative = format!("{SIGNATURE_DIR}/{CODE_FILE_LIST}");
        let signature_relative = format!("{SIGNATURE_DIR}/{SIGNATURE_FILE}");
        let mut files = collect_file_entries(&root)?;
        files.retain(|entry| {
            entry.relative != manifest_relative && entry.relative != signature_relative
        });
        if files.len() != manifest.len() {
            return Err(SignError::VerificationFailed(format!(
                "the directory contains {} files but the signature lists {}",
                files.len(),
                manifest.len()
            )));
        }

        let by_path = files
            .iter()
            .map(|entry| (entry.relative.as_str(), entry))
            .collect::<HashMap<_, _>>();
        let mut seen = HashSet::with_capacity(manifest.len());
        for (file_name, expected_digest) in &manifest {
            validate_manifest_path(file_name)?;
            let entry = by_path.get(file_name.as_str()).ok_or_else(|| {
                SignError::VerificationFailed(format!(
                    "'{file_name}' is not present in the directory"
                ))
            })?;
            if !seen.insert(file_name.as_str()) {
                return Err(SignError::VerificationFailed(format!(
                    "'{file_name}' is listed more than once"
                )));
            }
            let actual_digest = sha256_base64(&entry.canonical)?;
            if actual_digest != *expected_digest {
                return Err(SignError::VerificationFailed(format!(
                    "digest mismatch for '{file_name}'"
                )));
            }
        }
        for entry in &files {
            if !seen.contains(entry.relative.as_str()) {
                return Err(SignError::VerificationFailed(format!(
                    "'{}' is not covered by the signature",
                    entry.relative
                )));
            }
        }

        let profile_path = signature_dir.join(PROFILE_FILE);
        let profile = match fs::read(&profile_path) {
            Ok(bytes) => Some(bytes),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(io_error(&profile_path, error)),
        };

        Ok(HarVerification {
            certificates: verified.certificates,
            algorithm: verified.algorithm,
            signing_time: verified.signing_time,
            profile,
            file_count: manifest.len(),
        })
    }
}

struct FileEntry {
    canonical: PathBuf,
    /// Slash-separated path relative to the signing root.
    relative: String,
    /// `File.getName()` equivalent, used for the upstream sort order.
    name: String,
}

fn canonical_directory(directory: &Path) -> Result<PathBuf, SignError> {
    let metadata = fs::metadata(directory).map_err(|error| io_error(directory, error))?;
    if !metadata.is_dir() {
        return Err(SignError::Config(format!(
            "directory signing input is not a directory: {}",
            directory.display()
        )));
    }
    fs::canonicalize(directory).map_err(|error| io_error(directory, error))
}

fn remove_path(path: &Path) -> Result<(), SignError> {
    match fs::metadata(path) {
        Ok(metadata) if metadata.is_dir() => {
            fs::remove_dir_all(path).map_err(|error| io_error(path, error))
        }
        Ok(_) => fs::remove_file(path).map_err(|error| io_error(path, error)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io_error(path, error)),
    }
}

fn collect_file_entries(root: &Path) -> Result<Vec<FileEntry>, SignError> {
    let mut entries = Vec::new();
    let mut visited = HashSet::new();
    walk_files(root, root, &mut entries, &mut visited)?;
    entries.sort_by(|left, right| {
        utf16_cmp(&left.name, &right.name).then_with(|| utf16_cmp(&left.relative, &right.relative))
    });
    Ok(entries)
}

fn walk_files(
    directory: &Path,
    root: &Path,
    entries: &mut Vec<FileEntry>,
    visited: &mut HashSet<PathBuf>,
) -> Result<(), SignError> {
    let canonical_dir = fs::canonicalize(directory).map_err(|error| io_error(directory, error))?;
    // Java follows directory symlinks. Tracking canonical directories keeps a
    // symlink cycle from recursing forever.
    if !visited.insert(canonical_dir) {
        return Ok(());
    }
    let read_dir = fs::read_dir(directory).map_err(|error| io_error(directory, error))?;
    for dir_entry in read_dir {
        let dir_entry = dir_entry.map_err(|error| io_error(directory, error))?;
        let path = dir_entry.path();
        let metadata = match fs::metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(io_error(&path, error)),
        };
        if metadata.is_file() {
            let canonical = fs::canonicalize(&path).map_err(|error| io_error(&path, error))?;
            entries.push(FileEntry {
                relative: manifest_path(&canonical, root)?,
                canonical,
                name: dir_entry.file_name().to_string_lossy().into_owned(),
            });
        } else if metadata.is_dir() {
            walk_files(&path, root, entries, visited)?;
        }
    }
    Ok(())
}

fn manifest_path(file: &Path, root: &Path) -> Result<String, SignError> {
    let relative = file.strip_prefix(root).map_err(|_| {
        SignError::Config(format!(
            "file '{}' is outside the signing directory '{}'",
            file.display(),
            root.display()
        ))
    })?;
    let mut path = String::new();
    for component in relative.components() {
        let Component::Normal(part) = component else {
            return Err(SignError::Config(format!(
                "unexpected path component in '{}'",
                file.display()
            )));
        };
        let part = part.to_str().ok_or_else(|| {
            SignError::Config(format!(
                "file name is not valid UTF-8: '{}'",
                file.display()
            ))
        })?;
        if !path.is_empty() {
            path.push('/');
        }
        path.push_str(part);
    }
    if path.is_empty() {
        return Err(SignError::Config(format!(
            "cannot derive a manifest name for '{}'",
            file.display()
        )));
    }
    Ok(path)
}

/// Java sorts with `String.compareTo`, i.e. UTF-16 code units.
fn utf16_cmp(left: &str, right: &str) -> Ordering {
    left.encode_utf16().cmp(right.encode_utf16())
}

fn sha256_base64(path: &Path) -> Result<String, SignError> {
    let mut file = fs::File::open(path).map_err(|error| io_error(path, error))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 16 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| io_error(path, error))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(STANDARD.encode(hasher.finalize()))
}

fn render_code_file_list(entries: &[(String, String)]) -> Vec<u8> {
    let mut output = String::new();
    output.push_str("{\"version\":");
    output.push_str(CODE_FILE_LIST_VERSION);
    output.push_str(",\"fileInfo\":{\"digestAlg\":");
    push_json_string(&mut output, FILE_DIGEST_ALG);
    output.push_str(",\"fileList\":[");
    for (index, (file_name, digest)) in entries.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        output.push_str("{\"fileName\":");
        push_json_string(&mut output, file_name);
        output.push_str(",\"digest\":");
        push_json_string(&mut output, digest);
        output.push('}');
    }
    output.push_str("]}}");
    output.into_bytes()
}

/// Gson 2.11's default string encoding: HTML-safe escapes and no `\/`.
fn push_json_string(output: &mut String, value: &str) {
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{08}' => output.push_str("\\b"),
            '\u{0c}' => output.push_str("\\f"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            '<' | '>' | '&' | '=' | '\'' => {
                let _ = write!(output, "\\u{:04x}", character as u32);
            }
            '\u{2028}' => output.push_str("\\u2028"),
            '\u{2029}' => output.push_str("\\u2029"),
            character if (character as u32) < 0x20 => {
                let _ = write!(output, "\\u{:04x}", character as u32);
            }
            character => output.push(character),
        }
    }
    output.push('"');
}

fn parse_code_file_list(bytes: &[u8]) -> Result<Vec<(String, String)>, SignError> {
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|error| {
        SignError::VerificationFailed(format!("invalid codeFileList JSON: {error}"))
    })?;
    let file_info = value
        .get("fileInfo")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| {
            SignError::VerificationFailed("codeFileList has no fileInfo object".to_owned())
        })?;
    let digest_algorithm = file_info
        .get("digestAlg")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| SignError::VerificationFailed("codeFileList has no digestAlg".to_owned()))?;
    if !digest_algorithm.eq_ignore_ascii_case(FILE_DIGEST_ALG) {
        return Err(SignError::UnsupportedAlgorithm(format!(
            "codeFileList digest algorithm '{digest_algorithm}'"
        )));
    }
    let file_list = file_info
        .get("fileList")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            SignError::VerificationFailed("codeFileList has no fileList array".to_owned())
        })?;
    let mut entries = Vec::with_capacity(file_list.len());
    for entry in file_list {
        let entry = entry.as_object().ok_or_else(|| {
            SignError::VerificationFailed("codeFileList entry is not an object".to_owned())
        })?;
        let file_name = entry
            .get("fileName")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                SignError::VerificationFailed("codeFileList entry has no fileName".to_owned())
            })?;
        let digest = entry
            .get("digest")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                SignError::VerificationFailed("codeFileList entry has no digest".to_owned())
            })?;
        entries.push((file_name.to_owned(), digest.to_owned()));
    }
    Ok(entries)
}

/// Reject absolute paths and `..` escapes before joining them to the root.
fn validate_manifest_path(file_name: &str) -> Result<(), SignError> {
    if file_name.is_empty() {
        return Err(SignError::VerificationFailed(
            "codeFileList contains an empty file name".to_owned(),
        ));
    }
    let path = Path::new(file_name);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(SignError::VerificationFailed(format!(
            "codeFileList contains an unsafe path '{file_name}'"
        )));
    }
    Ok(())
}

fn read_signature_material(path: &Path) -> Result<Vec<u8>, SignError> {
    fs::read(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            SignError::VerificationFailed(format!(
                "missing HAR signature material: {}",
                path.display()
            ))
        } else {
            io_error(path, error)
        }
    })
}

fn io_error(path: &Path, source: std::io::Error) -> SignError {
    SignError::IoPath {
        path: path.to_path_buf(),
        source,
    }
}
