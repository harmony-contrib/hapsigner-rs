use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use der::{Decode, Encode};
use serde_json::Value;

use crate::{signing_block, SignError};

const EOCD_MAGIC: &[u8; 4] = b"PK\x05\x06";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigningBlockEntry {
    pub block_type: u32,
    pub offset: usize,
    pub length: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SigningBlockType {
    Signature,
    ProofOfRotation,
    Profile,
    Property,
    Other(u32),
}

impl SigningBlockEntry {
    pub fn kind(&self) -> SigningBlockType {
        match self.block_type {
            signing_block::BLOCK_ID_SIGNATURE_V1 => SigningBlockType::Signature,
            signing_block::BLOCK_ID_PROOF_OF_ROTATION => SigningBlockType::ProofOfRotation,
            signing_block::BLOCK_ID_PROFILE => SigningBlockType::Profile,
            signing_block::BLOCK_ID_PROPERTY => SigningBlockType::Property,
            value => SigningBlockType::Other(value),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigningBlockInfo {
    pub start: usize,
    pub size: usize,
    pub version: u32,
    pub blocks: Vec<SigningBlockEntry>,
}

/// Read-only signing-block and provisioning-profile inspector.
pub struct SigningBlockInspector<'a> {
    hap: &'a [u8],
}

impl<'a> SigningBlockInspector<'a> {
    pub fn new(hap: &'a [u8]) -> Self {
        Self { hap }
    }

    pub fn inspect(&self) -> Result<SigningBlockInfo, SignError> {
        let sections = ZipSections::locate(self.hap)?;
        if sections.sign_start == sections.central_directory_start {
            return Err(SignError::InvalidZip("HAP has no signing block"));
        }
        let central_directory = sections.central_directory_start;
        let size = read_u64(self.hap, central_directory - 28)? as usize;
        let version = read_u32(self.hap, central_directory - 4)?;
        let count = read_u32(self.hap, central_directory - 32)? as usize;
        let header_size = count
            .checked_mul(12)
            .ok_or(SignError::InvalidZip("signing-block header overflow"))?;
        if sections.sign_start + header_size > central_directory - 32 {
            return Err(SignError::InvalidZip(
                "signing-block headers extend beyond payload",
            ));
        }

        let mut blocks = Vec::with_capacity(count);
        for index in 0..count {
            let entry = sections.sign_start + index * 12;
            let block_type = read_u32(self.hap, entry)?;
            let length = read_u32(self.hap, entry + 4)? as usize;
            let relative_offset = read_u32(self.hap, entry + 8)? as usize;
            let offset = sections
                .sign_start
                .checked_add(relative_offset)
                .ok_or(SignError::InvalidZip("signing-block offset overflow"))?;
            let end = offset
                .checked_add(length)
                .ok_or(SignError::InvalidZip("signing-block length overflow"))?;
            if end > central_directory - 32 {
                return Err(SignError::InvalidZip(
                    "signing sub-block extends beyond payload",
                ));
            }
            blocks.push(SigningBlockEntry {
                block_type,
                offset,
                length,
            });
        }
        Ok(SigningBlockInfo {
            start: sections.sign_start,
            size,
            version,
            blocks,
        })
    }

    pub fn embedded_profile(&self) -> Result<Value, SignError> {
        let info = self.inspect()?;
        let profile = info
            .blocks
            .iter()
            .find(|entry| entry.block_type == signing_block::BLOCK_ID_PROFILE)
            .ok_or_else(|| SignError::Config("HAP signing block has no profile".into()))?;
        let bytes = self
            .hap
            .get(profile.offset..profile.offset + profile.length)
            .ok_or(SignError::InvalidZip("profile block range is invalid"))?;
        let content_info = ContentInfo::from_der(bytes)
            .map_err(|error| SignError::DerError(format!("profile ContentInfo: {error}")))?;
        let signed_data = SignedData::from_der(
            &content_info
                .content
                .to_der()
                .map_err(|error| SignError::DerError(error.to_string()))?,
        )
        .map_err(|error| SignError::DerError(format!("profile SignedData: {error}")))?;
        let content = signed_data
            .encap_content_info
            .econtent
            .ok_or_else(|| SignError::Config("profile CMS has no embedded content".into()))?;
        serde_json::from_slice(content.value())
            .map_err(|error| SignError::Config(format!("profile JSON: {error}")))
    }
}

struct ZipSections {
    sign_start: usize,
    central_directory_start: usize,
}

impl ZipSections {
    fn locate(input: &[u8]) -> Result<Self, SignError> {
        let search_start = input.len().saturating_sub(65_557);
        let relative = input[search_start..]
            .windows(EOCD_MAGIC.len())
            .rposition(|window| window == EOCD_MAGIC)
            .ok_or(SignError::InvalidZip("ZIP EOCD was not found"))?;
        let eocd_start = search_start + relative;
        if eocd_start + 22 > input.len() {
            return Err(SignError::InvalidZip("truncated ZIP EOCD"));
        }
        let comment_length = read_u16(input, eocd_start + 20)? as usize;
        if eocd_start + 22 + comment_length != input.len() {
            return Err(SignError::InvalidZip("invalid ZIP EOCD comment length"));
        }
        let central_directory_size = read_u32(input, eocd_start + 12)? as usize;
        let central_directory_start = read_u32(input, eocd_start + 16)? as usize;
        if central_directory_start.checked_add(central_directory_size) != Some(eocd_start) {
            return Err(SignError::InvalidZip("invalid ZIP central-directory range"));
        }

        let mut sign_start = central_directory_start;
        if central_directory_start >= 32 {
            let magic = input
                .get(central_directory_start - 20..central_directory_start - 4)
                .ok_or(SignError::InvalidZip("truncated signing-block footer"))?;
            let version = read_u32(input, central_directory_start - 4)?;
            let recognized = (magic == signing_block::MAGIC_V2 && version == 2)
                || (magic == signing_block::MAGIC_V3 && version == 3);
            if recognized {
                let size = read_u64(input, central_directory_start - 28)? as usize;
                if size < 32 || size > central_directory_start {
                    return Err(SignError::InvalidZip("invalid signing-block size"));
                }
                sign_start = central_directory_start - size;
            }
        }
        Ok(Self {
            sign_start,
            central_directory_start,
        })
    }
}

fn read_u16(input: &[u8], offset: usize) -> Result<u16, SignError> {
    input
        .get(offset..offset + 2)
        .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
        .ok_or(SignError::InvalidZip("unexpected end of u16 field"))
}

fn read_u32(input: &[u8], offset: usize) -> Result<u32, SignError> {
    input
        .get(offset..offset + 4)
        .map(|bytes| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
        .ok_or(SignError::InvalidZip("unexpected end of u32 field"))
}

fn read_u64(input: &[u8], offset: usize) -> Result<u64, SignError> {
    input
        .get(offset..offset + 8)
        .map(|bytes| {
            u64::from_le_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ])
        })
        .ok_or(SignError::InvalidZip("unexpected end of u64 field"))
}
