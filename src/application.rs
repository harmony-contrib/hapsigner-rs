use crate::code_sign::ElfCodeSignBuilder;
use crate::material::SigningMaterial;
use crate::{pkcs7, SignError, SignOptions};

const SIGN_HEAD_SIZE: usize = 32;
const BIN_BLOCK_HEAD_SIZE: usize = 8;
const ELF_BLOCK_HEAD_SIZE: usize = 12;
const BIN_CHUNK_SIZE: usize = 4096;

/// Input forms accepted by official `sign-app -inForm`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InputFormat {
    Zip,
    Elf,
    Bin,
}

pub(crate) struct BinarySigner<'a> {
    material: &'a SigningMaterial,
}

impl<'a> BinarySigner<'a> {
    pub(crate) fn new(material: &'a SigningMaterial) -> Self {
        Self { material }
    }

    pub(crate) fn sign(&self, input: &[u8]) -> Result<Vec<u8>, SignError> {
        self.material.validate_profile_for_application_signing()?;
        let profile_len = u16::try_from(self.material.signed_profile.len()).map_err(|_| {
            SignError::SigningFailed("BIN profile exceeds the official u16 length field".to_owned())
        })?;
        let profile_offset = input
            .len()
            .checked_add(BIN_BLOCK_HEAD_SIZE * 2)
            .ok_or_else(|| SignError::SigningFailed("BIN profile offset overflow".to_owned()))?;
        let signature_offset = profile_offset
            .checked_add(self.material.signed_profile.len())
            .ok_or_else(|| SignError::SigningFailed("BIN signature offset overflow".to_owned()))?;
        let profile_offset = u32::try_from(profile_offset)
            .map_err(|_| SignError::SigningFailed("BIN profile offset exceeds u32".to_owned()))?;
        let signature_offset = u32::try_from(signature_offset)
            .map_err(|_| SignError::SigningFailed("BIN signature offset exceeds u32".to_owned()))?;

        let profile_type = if self.material.profile_signed { 2 } else { 1 };
        let mut output = Vec::with_capacity(
            input.len() + BIN_BLOCK_HEAD_SIZE * 2 + self.material.signed_profile.len() + 4096,
        );
        output.extend_from_slice(input);
        self.write_block_head(&mut output, profile_type, profile_len, profile_offset);
        self.write_block_head(&mut output, 0, 0, signature_offset);
        output.extend_from_slice(&self.material.signed_profile);

        let digest = self.file_digest(&output)?;
        let content_info = self.sign_content_info(&digest)?;
        let cms = pkcs7::build_cms_signed_data_with_identity(
            &content_info,
            &self.material.signing_identity,
            self.material.algorithm.id(),
        )?;
        output.extend_from_slice(&cms);

        let signed_area_size = output
            .len()
            .checked_sub(input.len())
            .and_then(|size| size.checked_add(SIGN_HEAD_SIZE))
            .ok_or_else(|| SignError::SigningFailed("BIN signing-head size overflow".to_owned()))?;
        let signed_area_size = u32::try_from(signed_area_size).map_err(|_| {
            SignError::SigningFailed("BIN signing-head size exceeds u32".to_owned())
        })?;
        self.write_sign_head(&mut output, signed_area_size);
        Ok(output)
    }

    fn file_digest(&self, input: &[u8]) -> Result<Vec<u8>, SignError> {
        if input.is_empty() {
            return Err(SignError::DigestError(
                "official BIN digest rejects an empty input".to_owned(),
            ));
        }
        let algorithm = self.material.algorithm.content_digest();
        let mut chunk_digests =
            Vec::with_capacity(input.len().div_ceil(BIN_CHUNK_SIZE) * algorithm.output_size());
        for chunk in input.chunks(BIN_CHUNK_SIZE) {
            chunk_digests.extend_from_slice(&algorithm.digest(chunk));
        }
        Ok(algorithm.digest(&chunk_digests))
    }

    fn sign_content_info(&self, digest: &[u8]) -> Result<Vec<u8>, SignError> {
        let size = 16usize
            .checked_add(digest.len())
            .ok_or_else(|| SignError::SigningFailed("BIN content-info size overflow".to_owned()))?;
        let size = u16::try_from(size)
            .map_err(|_| SignError::SigningFailed("BIN content-info exceeds u16".to_owned()))?;
        let digest_algorithm_id: u16 = match self.material.algorithm.content_digest() {
            crate::ContentDigestAlgorithm::Sha256 => 6,
            crate::ContentDigestAlgorithm::Sha384 => 7,
            crate::ContentDigestAlgorithm::Sha512 => 8,
        };
        let mut output = Vec::with_capacity(size as usize);
        output.extend_from_slice(b"1000");
        output.extend_from_slice(&size.to_be_bytes());
        output.extend_from_slice(&1u16.to_be_bytes());
        output.push(0);
        output.push(0x88);
        output.extend_from_slice(&digest_algorithm_id.to_be_bytes());
        output.extend_from_slice(&(digest.len() as u32).to_be_bytes());
        output.extend_from_slice(digest);
        Ok(output)
    }

    fn write_block_head(&self, output: &mut Vec<u8>, block_type: u8, len: u16, offset: u32) {
        output.push(block_type);
        output.push(0);
        output.extend_from_slice(&len.to_be_bytes());
        output.extend_from_slice(&offset.to_be_bytes());
    }

    fn write_sign_head(&self, output: &mut Vec<u8>, signed_area_size: u32) {
        output.extend_from_slice(b"hw signed app   ");
        output.extend_from_slice(b"1000");
        output.extend_from_slice(&signed_area_size.to_be_bytes());
        output.extend_from_slice(&2u32.to_be_bytes());
        output.extend_from_slice(&0u32.to_be_bytes());
    }
}

pub(crate) struct ElfSigner<'a> {
    material: &'a SigningMaterial,
    options: &'a SignOptions,
}

impl<'a> ElfSigner<'a> {
    pub(crate) fn new(material: &'a SigningMaterial, options: &'a SignOptions) -> Self {
        Self { material, options }
    }

    pub(crate) fn sign(&self, input: &[u8]) -> Result<Vec<u8>, SignError> {
        if !self.material.profile_signed {
            return Err(SignError::Config(
                "official sign-app forbids profileSigned=0 for ELF input".to_owned(),
            ));
        }
        self.material.validate_optional_elf_profile()?;
        if self.material.signed_profile.len() > u16::MAX as usize {
            return Err(SignError::SigningFailed(
                "ELF profile exceeds the official u16 validation limit".to_owned(),
            ));
        }

        let padding = 4096 - input.len() % 4096;
        let mut aligned = Vec::with_capacity(input.len() + padding);
        aligned.extend_from_slice(input);
        aligned.resize(aligned.len() + padding, 0);

        let block_count = usize::from(self.options.code_signing)
            + usize::from(!self.material.signed_profile.is_empty());
        let mut blocks = Vec::with_capacity(block_count);
        if self.options.code_signing {
            let code_sign_offset = aligned
                .len()
                .checked_add(block_count * ELF_BLOCK_HEAD_SIZE)
                .ok_or_else(|| {
                    SignError::SigningFailed("ELF code-sign offset overflow".to_owned())
                })?;
            let code_sign = ElfCodeSignBuilder::new(
                &self.material.signing_identity,
                self.material.algorithm.id(),
                &self.material.signed_profile,
                self.material.profile_signed,
            )?
            .build(&aligned, code_sign_offset)?;
            blocks.push((3u16, code_sign));
        }
        if !self.material.signed_profile.is_empty() {
            blocks.push((2u16, self.material.signed_profile.clone()));
        }

        let mut output = aligned;
        let mut block_offset = blocks
            .len()
            .checked_mul(ELF_BLOCK_HEAD_SIZE)
            .ok_or_else(|| SignError::SigningFailed("ELF block offset overflow".to_owned()))?;
        for (block_type, bytes) in &blocks {
            let len = u32::try_from(bytes.len())
                .map_err(|_| SignError::SigningFailed("ELF block exceeds u32".to_owned()))?;
            let offset = u32::try_from(block_offset)
                .map_err(|_| SignError::SigningFailed("ELF block offset exceeds u32".to_owned()))?;
            output.extend_from_slice(&block_type.to_le_bytes());
            output.extend_from_slice(&0u16.to_le_bytes());
            output.extend_from_slice(&len.to_le_bytes());
            output.extend_from_slice(&offset.to_le_bytes());
            block_offset = block_offset
                .checked_add(bytes.len())
                .ok_or_else(|| SignError::SigningFailed("ELF block offset overflow".to_owned()))?;
        }
        for (_, bytes) in &blocks {
            output.extend_from_slice(bytes);
        }

        let signed_area_size = block_offset;
        let signed_area_size = u32::try_from(signed_area_size)
            .map_err(|_| SignError::SigningFailed("ELF signing area exceeds u32".to_owned()))?;
        output.extend_from_slice(b"elf sign block  ");
        output.extend_from_slice(b"1000");
        output.extend_from_slice(&signed_area_size.to_le_bytes());
        output.extend_from_slice(&(blocks.len() as u32).to_le_bytes());
        output.extend_from_slice(&0u32.to_le_bytes());
        Ok(output)
    }
}
