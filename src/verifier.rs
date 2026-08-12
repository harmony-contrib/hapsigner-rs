use crate::digest::HapDigestComputer;
use crate::profile_content::ProfileContent;
use crate::{
    signing_block, InputFormat, ProfileVerifier, SignError, SigningAlgorithm, SigningBlockInspector,
};

const EOCD_MAGIC: &[u8; 4] = b"PK\x05\x06";
const ELF_SIGN_MAGIC: &[u8; 16] = b"elf sign block  ";
const SIGN_VERSION: &[u8; 4] = b"1000";
const SIGN_HEAD_SIZE: usize = 32;
const ELF_BLOCK_HEAD_SIZE: usize = 12;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicationVerification {
    pub format: InputFormat,
    pub certificates: Vec<Vec<u8>>,
    pub profile: Option<Vec<u8>>,
    pub proof_of_rotation: Option<Vec<u8>>,
    pub properties: Vec<Vec<u8>>,
    pub algorithm: Option<SigningAlgorithm>,
    pub signing_block_version: Option<u32>,
}

/// Verifies the application forms handled by official `verify-app`.
pub struct ApplicationVerifier<'a> {
    input: &'a [u8],
}

impl<'a> ApplicationVerifier<'a> {
    pub fn new(input: &'a [u8]) -> Self {
        Self { input }
    }

    pub fn verify(&self, format: InputFormat) -> Result<ApplicationVerification, SignError> {
        match format {
            InputFormat::Zip => self.verify_zip(),
            InputFormat::Elf => self.verify_elf(),
            InputFormat::Bin => Err(SignError::UnsupportedOperation(
                "official verify-app routes BIN to VerifyElf and rejects its 'hw signed app' header"
                    .to_owned(),
            )),
        }
    }

    fn verify_zip(&self) -> Result<ApplicationVerification, SignError> {
        let info = SigningBlockInspector::new(self.input).inspect()?;
        let signature_blocks = info
            .blocks
            .iter()
            .filter(|entry| entry.block_type == signing_block::BLOCK_ID_SIGNATURE_V1)
            .collect::<Vec<_>>();
        let signature = match signature_blocks.as_slice() {
            [signature] => *signature,
            [] => {
                return Err(SignError::VerificationFailed(
                    "HAP signing block has no signature block".to_owned(),
                ));
            }
            _ => {
                return Err(SignError::VerificationFailed(
                    "HAP signing block has multiple signature blocks".to_owned(),
                ));
            }
        };
        let signature_bytes = self.block_value(signature.offset, signature.length)?;
        let verified_cms = crate::pkcs7::verify_cms_signed_data(signature_bytes)?;
        let signed_digest = HapDigestPair::parse(&verified_cms.content)?;
        if signed_digest.algorithm != verified_cms.algorithm {
            return Err(SignError::VerificationFailed(
                "HAP digest-pair algorithm does not match CMS algorithms".to_owned(),
            ));
        }

        let mut profile = None;
        let mut profile_content = None;
        let mut proof_of_rotation = None;
        let mut properties = Vec::new();
        let mut optional_values = Vec::new();
        for block in &info.blocks {
            let bytes = self.block_value(block.offset, block.length)?;
            match block.block_type {
                signing_block::BLOCK_ID_PROFILE => {
                    if profile.is_some() {
                        return Err(SignError::VerificationFailed(
                            "HAP signing block has multiple profile blocks".to_owned(),
                        ));
                    }
                    profile_content = Some(Self::verify_profile_or_json(bytes)?);
                    profile = Some(bytes.to_vec());
                    optional_values.push(bytes);
                }
                signing_block::BLOCK_ID_PROOF_OF_ROTATION => {
                    if proof_of_rotation.is_some() {
                        return Err(SignError::VerificationFailed(
                            "HAP signing block has multiple proof-of-rotation blocks".to_owned(),
                        ));
                    }
                    proof_of_rotation = Some(bytes.to_vec());
                    optional_values.push(bytes);
                }
                signing_block::BLOCK_ID_PROPERTY => {
                    properties.push(bytes.to_vec());
                    optional_values.push(bytes);
                }
                signing_block::BLOCK_ID_SIGNATURE_V1 => {}
                _ => {}
            }
        }
        let computed_digest =
            self.compute_zip_digest(&info, &optional_values, verified_cms.algorithm)?;
        if computed_digest != signed_digest.digest {
            return Err(SignError::VerificationFailed(
                "HAP content digest does not match the signed digest".to_owned(),
            ));
        }
        crate::code_sign::CodeSignVerifier::new(self.input, profile_content.as_ref())
            .verify_hap_properties(&info)?;

        Ok(ApplicationVerification {
            format: InputFormat::Zip,
            certificates: verified_cms.certificates,
            profile,
            proof_of_rotation,
            properties,
            algorithm: Some(verified_cms.algorithm),
            signing_block_version: Some(info.version),
        })
    }

    fn verify_elf(&self) -> Result<ApplicationVerification, SignError> {
        let head_start = self
            .input
            .len()
            .checked_sub(SIGN_HEAD_SIZE)
            .ok_or_else(|| {
                SignError::VerificationFailed("ELF sign head is truncated".to_owned())
            })?;
        let head = &self.input[head_start..];
        if &head[..16] != ELF_SIGN_MAGIC || &head[16..20] != SIGN_VERSION {
            return Err(SignError::VerificationFailed(
                "ELF sign head magic or version is invalid".to_owned(),
            ));
        }
        let signed_area_size = Self::read_u32_le(head, 20)? as usize;
        let block_count = Self::read_u32_le(head, 24)? as usize;
        let area_start = head_start.checked_sub(signed_area_size).ok_or_else(|| {
            SignError::VerificationFailed("ELF signed-area size exceeds input".to_owned())
        })?;
        let headers_size = block_count
            .checked_mul(ELF_BLOCK_HEAD_SIZE)
            .ok_or_else(|| {
                SignError::VerificationFailed("ELF signing block count overflow".to_owned())
            })?;
        if area_start
            .checked_add(headers_size)
            .is_none_or(|end| end > head_start)
        {
            return Err(SignError::VerificationFailed(
                "ELF signing block headers exceed the signed area".to_owned(),
            ));
        }

        let mut profile = None;
        let mut profile_content = None;
        let mut certificates = Vec::new();
        let mut algorithm = None;
        let mut code_sign_block = None;
        for index in 0..block_count {
            let header = area_start + index * ELF_BLOCK_HEAD_SIZE;
            let block_type = Self::read_u16_le(self.input, header)?;
            let length = Self::read_u32_le(self.input, header + 4)? as usize;
            let offset = Self::read_u32_le(self.input, header + 8)? as usize;
            let start = area_start.checked_add(offset).ok_or_else(|| {
                SignError::VerificationFailed("ELF signing block offset overflow".to_owned())
            })?;
            let bytes = self.block_value(start, length)?;
            if start + length > head_start {
                return Err(SignError::VerificationFailed(
                    "ELF signing sub-block exceeds signed area".to_owned(),
                ));
            }
            match block_type {
                1 => {
                    profile_content = Some(ProfileContent::from_json(bytes)?);
                    profile = Some(bytes.to_vec());
                }
                2 => {
                    let verified = ProfileVerifier::verify(bytes)?;
                    profile_content = Some(ProfileContent::from_json(&verified.content)?);
                    certificates = verified.certificates;
                    algorithm = Some(verified.algorithm);
                    profile = Some(bytes.to_vec());
                }
                3 => code_sign_block = Some((bytes, start)),
                _ => {}
            }
        }
        if let Some((bytes, start)) = code_sign_block {
            crate::code_sign::CodeSignVerifier::new(self.input, profile_content.as_ref())
                .verify_elf_block(&self.input[..area_start], bytes, start)?;
        }
        Ok(ApplicationVerification {
            format: InputFormat::Elf,
            certificates,
            profile,
            proof_of_rotation: None,
            properties: Vec::new(),
            algorithm,
            signing_block_version: None,
        })
    }

    fn compute_zip_digest(
        &self,
        info: &crate::SigningBlockInfo,
        optional_values: &[&[u8]],
        algorithm: SigningAlgorithm,
    ) -> Result<Vec<u8>, SignError> {
        let central_directory_start = info.start.checked_add(info.size).ok_or_else(|| {
            SignError::VerificationFailed("HAP signing-block size overflow".to_owned())
        })?;
        let eocd_start = self.eocd_start()?;
        if central_directory_start > eocd_start {
            return Err(SignError::VerificationFailed(
                "HAP central directory begins after EOCD".to_owned(),
            ));
        }
        let central_directory = &self.input[central_directory_start..eocd_start];
        let mut eocd = self.input[eocd_start..].to_vec();
        let signing_offset = u32::try_from(info.start).map_err(|_| {
            SignError::VerificationFailed("HAP signing offset exceeds ZIP u32".to_owned())
        })?;
        eocd[16..20].copy_from_slice(&signing_offset.to_le_bytes());
        let mut digest = HapDigestComputer::with_algorithm(
            &[info.start, 0, central_directory.len(), eocd.len()],
            algorithm.content_digest(),
        );
        digest.update_section(&self.input[..info.start]);
        digest.update_section(&[]);
        digest.update_section(central_directory);
        digest.update_section(&eocd);
        for value in optional_values {
            digest.update_optional_block(value);
        }
        Ok(digest.finalize())
    }

    fn verify_profile_or_json(profile: &[u8]) -> Result<ProfileContent, SignError> {
        match ProfileVerifier::verify(profile) {
            Ok(verified) => ProfileContent::from_json(&verified.content),
            Err(cms_error) => ProfileContent::from_json(profile).map_err(|_| cms_error),
        }
    }

    fn eocd_start(&self) -> Result<usize, SignError> {
        let search_start = self.input.len().saturating_sub(65_557);
        let relative = self.input[search_start..]
            .windows(EOCD_MAGIC.len())
            .rposition(|window| window == EOCD_MAGIC)
            .ok_or(SignError::InvalidZip("ZIP EOCD was not found"))?;
        let offset = search_start + relative;
        let comment_length = Self::read_u16_le(self.input, offset + 20)? as usize;
        if offset + 22 + comment_length != self.input.len() {
            return Err(SignError::InvalidZip("invalid ZIP EOCD comment length"));
        }
        Ok(offset)
    }

    fn block_value(&self, offset: usize, length: usize) -> Result<&'a [u8], SignError> {
        self.input
            .get(
                offset..offset.checked_add(length).ok_or_else(|| {
                    SignError::VerificationFailed("signing sub-block range overflow".to_owned())
                })?,
            )
            .ok_or_else(|| {
                SignError::VerificationFailed("signing sub-block exceeds input".to_owned())
            })
    }

    fn read_u16_le(bytes: &[u8], offset: usize) -> Result<u16, SignError> {
        bytes
            .get(offset..offset + 2)
            .map(|value| u16::from_le_bytes([value[0], value[1]]))
            .ok_or_else(|| SignError::VerificationFailed("truncated u16 field".to_owned()))
    }

    fn read_u32_le(bytes: &[u8], offset: usize) -> Result<u32, SignError> {
        bytes
            .get(offset..offset + 4)
            .map(|value| u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
            .ok_or_else(|| SignError::VerificationFailed("truncated u32 field".to_owned()))
    }
}

struct HapDigestPair {
    algorithm: SigningAlgorithm,
    digest: Vec<u8>,
}

impl HapDigestPair {
    fn parse(content: &[u8]) -> Result<Self, SignError> {
        if content.len() < 20
            || ApplicationVerifier::read_u32_le(content, 0)? != 2
            || ApplicationVerifier::read_u32_le(content, 4)? != 1
        {
            return Err(SignError::VerificationFailed(
                "HAP signed digest-pairs header is invalid".to_owned(),
            ));
        }
        let pair_length = ApplicationVerifier::read_u32_le(content, 8)? as usize;
        if pair_length.checked_add(12) != Some(content.len()) {
            return Err(SignError::VerificationFailed(
                "HAP signed digest-pair length is invalid".to_owned(),
            ));
        }
        let algorithm_id = ApplicationVerifier::read_u32_le(content, 12)?;
        let digest_length = ApplicationVerifier::read_u32_le(content, 16)? as usize;
        if digest_length.checked_add(20) != Some(content.len()) {
            return Err(SignError::VerificationFailed(
                "HAP signed digest length is invalid".to_owned(),
            ));
        }
        let algorithm = SigningAlgorithm::from_id(algorithm_id).ok_or_else(|| {
            SignError::UnsupportedAlgorithm(format!("HAP algorithm id 0x{algorithm_id:x}"))
        })?;
        if digest_length != algorithm.content_digest().output_size() {
            return Err(SignError::VerificationFailed(
                "HAP signed digest size does not match its algorithm".to_owned(),
            ));
        }
        Ok(Self {
            algorithm,
            digest: content[20..].to_vec(),
        })
    }
}
