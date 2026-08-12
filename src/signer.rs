use std::io::{BufWriter, Write};
use std::path::Path;

use tempfile::NamedTempFile;

use crate::code_sign::CodeSignPropertyBuilder;
use crate::material::SigningMaterial;
use crate::zip::HapZip;
use crate::{application, pkcs7, signing_block, InputFormat, SignError};

/// Default compatible version used by OpenHarmony hapsigner when Hvigor does
/// not pass `-compatibleVersion`.
pub const DEFAULT_COMPATIBLE_VERSION: u32 = 9;

/// Format controls for HAP/HSP signing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignOptions {
    /// Selects V2 (`< 8`) or V3 (`>= 8`) signing-block framing.
    pub compatible_version: u32,
    /// Emit the property/code-sign block used for `.abc` and native libraries.
    pub code_signing: bool,
}

impl Default for SignOptions {
    fn default() -> Self {
        Self {
            compatible_version: DEFAULT_COMPATIBLE_VERSION,
            code_signing: true,
        }
    }
}

/// In-process OpenHarmony HAP/HSP signer.
///
/// All project discovery, password decryption, and material selection happen
/// before construction. The signer owns immutable loaded material and performs
/// deterministic archive preparation, digesting, CMS signing, and final write.
pub struct HapSigner {
    material: SigningMaterial,
    options: SignOptions,
}

impl HapSigner {
    pub fn new(material: SigningMaterial, options: SignOptions) -> Self {
        Self { material, options }
    }

    /// Sign an archive held in memory.
    pub fn sign(&self, unsigned_hap: &[u8]) -> Result<Vec<u8>, SignError> {
        self.sign_zip(HapZip::parse(unsigned_hap)?)
    }

    /// Sign an owned archive without copying its entry payloads.
    pub fn sign_owned(&self, unsigned_hap: Vec<u8>) -> Result<Vec<u8>, SignError> {
        self.sign_zip(HapZip::parse_owned(unsigned_hap)?)
    }

    /// Sign any input form accepted by official `sign-app -inForm`.
    pub fn sign_application(
        &self,
        unsigned: &[u8],
        format: InputFormat,
    ) -> Result<Vec<u8>, SignError> {
        match format {
            InputFormat::Zip => self.sign(unsigned),
            InputFormat::Elf => {
                application::ElfSigner::new(&self.material, &self.options).sign(unsigned)
            }
            InputFormat::Bin => application::BinarySigner::new(&self.material).sign(unsigned),
        }
    }

    fn sign_zip(&self, mut hap_zip: HapZip) -> Result<Vec<u8>, SignError> {
        self.material.validate_profile_for_application_signing()?;
        hap_zip.prepare_for_signing()?;
        let blocks = self.optional_blocks_for_zip(&hap_zip)?;
        let optional_values = blocks
            .iter()
            .map(|(_, value)| value.as_slice())
            .collect::<Vec<_>>();
        let content_digest = hap_zip.content_digest_for_signing_with_algorithm(
            &optional_values,
            self.material.algorithm.content_digest(),
        )?;
        let signing_block = self.signing_block_from_digest(blocks, &content_digest)?;
        hap_zip.with_signing_block(&signing_block)
    }

    /// Sign a file with bounded archive memory and atomically persist the
    /// completed output in its destination directory.
    pub fn sign_file(&self, input: &Path, output: &Path) -> Result<(), SignError> {
        self.material.validate_profile_for_application_signing()?;
        let parent = output.parent().unwrap_or_else(|| Path::new("."));
        fs_err::create_dir_all(parent).map_err(|source| SignError::IoPath {
            path: parent.to_path_buf(),
            source,
        })?;

        let mut hap_zip = HapZip::parse_file(input)?;
        hap_zip.prepare_for_signing()?;
        let blocks = self.optional_blocks_for_zip(&hap_zip)?;
        let optional_values = blocks
            .iter()
            .map(|(_, value)| value.as_slice())
            .collect::<Vec<_>>();

        let mut temporary = NamedTempFile::new_in(parent).map_err(|source| SignError::IoPath {
            path: parent.to_path_buf(),
            source,
        })?;
        {
            let mut writer = BufWriter::with_capacity(4 * 1024 * 1024, temporary.as_file_mut());
            let sections = hap_zip.write_entries_and_content_digest_with_algorithm(
                &mut writer,
                &optional_values,
                self.material.algorithm.content_digest(),
            )?;
            let signing_block = self.signing_block_from_digest(blocks, &sections.content_digest)?;
            hap_zip.write_signing_block_and_directory(&mut writer, &signing_block, sections)?;
            writer.flush()?;
        }
        temporary.as_file().sync_all()?;
        temporary
            .persist(output)
            .map_err(|error| SignError::IoPath {
                path: output.to_path_buf(),
                source: error.error,
            })?;
        Ok(())
    }

    /// Sign ZIP, ELF, or BIN input and atomically persist the result.
    pub fn sign_application_file(
        &self,
        input: &Path,
        output: &Path,
        format: InputFormat,
    ) -> Result<(), SignError> {
        if format == InputFormat::Zip {
            return self.sign_file(input, output);
        }
        let unsigned = fs_err::read(input).map_err(|source| SignError::IoPath {
            path: input.to_path_buf(),
            source,
        })?;
        let signed = self.sign_application(&unsigned, format)?;
        let parent = output.parent().unwrap_or_else(|| Path::new("."));
        fs_err::create_dir_all(parent).map_err(|source| SignError::IoPath {
            path: parent.to_path_buf(),
            source,
        })?;
        let mut temporary = NamedTempFile::new_in(parent).map_err(|source| SignError::IoPath {
            path: parent.to_path_buf(),
            source,
        })?;
        temporary.write_all(&signed)?;
        temporary.as_file().sync_all()?;
        temporary
            .persist(output)
            .map_err(|error| SignError::IoPath {
                path: output.to_path_buf(),
                source: error.error,
            })?;
        Ok(())
    }

    fn optional_blocks_for_zip(&self, hap_zip: &HapZip) -> Result<Vec<(u32, Vec<u8>)>, SignError> {
        let mut blocks = Vec::with_capacity(4);
        if let Some(property) = &self.material.property {
            blocks.push((signing_block::BLOCK_ID_PROPERTY, property.clone()));
        }
        blocks.push((
            signing_block::BLOCK_ID_PROFILE,
            self.material.signed_profile.clone(),
        ));
        if let Some(proof) = &self.material.proof_of_rotation {
            blocks.push((signing_block::BLOCK_ID_PROOF_OF_ROTATION, proof.clone()));
        }
        if self.options.code_signing {
            let code_sign_offset = self.code_sign_offset(hap_zip.entries_len(), blocks.len())?;
            let property = CodeSignPropertyBuilder::new(
                &self.material.signing_identity,
                self.material.algorithm.id(),
                &self.material.signed_profile,
                self.material.profile_signed,
            )?
            .build_property_block(hap_zip, code_sign_offset)?;
            blocks.insert(0, (signing_block::BLOCK_ID_PROPERTY, property));
        }
        Ok(blocks)
    }

    fn code_sign_offset(
        &self,
        central_directory_offset: usize,
        optional_block_count_before_code_sign: usize,
    ) -> Result<usize, SignError> {
        let offset = central_directory_offset
            .checked_add(12 * (optional_block_count_before_code_sign + 2))
            .and_then(|offset| offset.checked_add(12))
            .ok_or_else(|| SignError::SigningFailed("code-sign offset overflow".to_owned()))?;
        if offset > u32::MAX as usize {
            return Err(SignError::SigningFailed(
                "code-sign offset exceeds the OpenHarmony u32 field".to_owned(),
            ));
        }
        Ok(offset)
    }

    fn signing_block_from_digest(
        &self,
        mut blocks: Vec<(u32, Vec<u8>)>,
        content_digest: &[u8],
    ) -> Result<Vec<u8>, SignError> {
        let algorithm = self.material.algorithm.id();
        let digest_pairs = signing_block::encode_digest_pairs(&[(algorithm, content_digest)]);
        let cms = pkcs7::build_cms_signed_data_with_identity(
            &digest_pairs,
            &self.material.signing_identity,
            algorithm,
        )?;
        blocks.push((signing_block::BLOCK_ID_SIGNATURE_V1, cms));
        Ok(signing_block::build_signing_block(
            &blocks,
            self.options.compatible_version,
        ))
    }
}
