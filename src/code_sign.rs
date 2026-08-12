use crate::profile_content::ProfileContent;
use crate::remote::SigningIdentity;
use crate::{pkcs7, signing_block, zip::HapZip, SignError, SigningBlockInfo};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const PAGE_SIZE: usize = 4096;
const DIGEST_SIZE: usize = 32;
const FS_VERITY_HASH_ALGORITHM_SHA256: u8 = 1;
const FS_VERITY_LOG2_BLOCK_SIZE: u8 = 12;
const FS_VERITY_DESCRIPTOR_SIZE: usize = 256;
const FS_VERITY_DESCRIPTOR_FLAG_STORE_MERKLE_TREE_OFFSET: u32 = 0x1;
const FS_VERITY_DIGEST_MAGIC: &[u8; 8] = b"FSVerity";

const CODE_SIGN_BLOCK_HEADER_SIZE: usize = 32;
const CODE_SIGN_BLOCK_MAGIC: u64 = 0xE046_C8C6_5389_FCCD;
const CODE_SIGN_BLOCK_VERSION: u32 = 1;
const CODE_SIGN_SEGMENT_HEADER_SIZE: usize = 12;
const CODE_SIGN_SEGMENT_COUNT: usize = 3;
const CODE_SIGN_FLAG_MERKLE_TREE_INLINED: u32 = 0x1;
const CODE_SIGN_FLAG_NATIVE_LIB_INCLUDED: u32 = 0x2;

const SEGMENT_FS_VERITY_INFO: u32 = 0x1;
const SEGMENT_HAP_INFO: u32 = 0x2;
const SEGMENT_NATIVE_LIB_INFO: u32 = 0x3;

const FS_VERITY_INFO_MAGIC: u32 = (0x1E38 << 16) + 0x31AB;
const HAP_INFO_MAGIC: u32 = (0xC1B5 << 16) + 0xCC66;
const NATIVE_LIB_INFO_MAGIC: u32 = (0x0ED2 << 16) + 0xE720;

const SIGN_INFO_FIXED_SIZE: usize = 60;
const SIGN_INFO_FLAG_MERKLE_TREE_INCLUDED: u32 = 0x1;
const EXTENSION_MERKLE_TREE_INLINED: u32 = 0x1;
const EXTENSION_MERKLE_TREE_SIZE: u32 = 80;

pub(crate) struct CodeSignPropertyBuilder<'a> {
    signing_identity: &'a SigningIdentity,
    alg_id: u32,
    profile: ProfileContent,
}

pub(crate) struct ElfCodeSignBuilder<'a> {
    signing_identity: &'a SigningIdentity,
    alg_id: u32,
    profile: Option<ProfileContent>,
}

impl<'a> ElfCodeSignBuilder<'a> {
    pub(crate) fn new(
        signing_identity: &'a SigningIdentity,
        alg_id: u32,
        profile_bytes: &[u8],
        profile_signed: bool,
    ) -> Result<Self, SignError> {
        Ok(Self {
            signing_identity,
            alg_id,
            profile: if profile_bytes.is_empty() {
                None
            } else {
                Some(ProfileContent::from_profile(profile_bytes, profile_signed)?)
            },
        })
    }

    pub(crate) fn build(&self, data: &[u8], code_sign_offset: usize) -> Result<Vec<u8>, SignError> {
        const INLINE_MERKLE_TREE_TYPE: u32 = 2;
        const FS_VERITY_DESCRIPTOR_TYPE: u32 = 1;

        let padding = (PAGE_SIZE - (code_sign_offset + 8) % PAGE_SIZE) % PAGE_SIZE;
        let tree_offset = code_sign_offset
            .checked_add(8 + padding)
            .ok_or_else(|| SignError::SigningFailed("ELF tree offset overflow".to_owned()))?;
        let fsverity = FsVerityGenerator::generate(data, tree_offset as u64)?;
        let signed_data_builder =
            pkcs7::CodeSignSignedDataBuilder::from_identity(self.signing_identity, self.alg_id)?;
        let owner_id = self
            .profile
            .as_ref()
            .map(ProfileContent::owner_id)
            .transpose()?
            .unwrap_or_else(|| Some("DEBUG_LIB_ID".to_owned()));
        let signature = signed_data_builder.build(&fsverity.digest, owner_id.as_deref(), None)?;
        let descriptor = FsVerityDescriptor {
            file_size: data.len() as u64,
            root_hash: fsverity.root_hash,
            flags: FS_VERITY_DESCRIPTOR_FLAG_STORE_MERKLE_TREE_OFFSET,
            merkle_tree_offset: tree_offset as u64,
        }
        .to_bytes(signature.len())?;

        let tree_length = padding
            .checked_add(fsverity.tree.len())
            .ok_or_else(|| SignError::SigningFailed("ELF tree length overflow".to_owned()))?;
        let descriptor_length = descriptor
            .len()
            .checked_add(signature.len())
            .ok_or_else(|| SignError::SigningFailed("ELF descriptor length overflow".to_owned()))?;
        let mut output = Vec::with_capacity(16 + tree_length + descriptor_length);
        output.extend_from_slice(&INLINE_MERKLE_TREE_TYPE.to_le_bytes());
        output.extend_from_slice(&(tree_length as u32).to_le_bytes());
        output.resize(output.len() + padding, 0);
        output.extend_from_slice(&fsverity.tree);
        output.extend_from_slice(&FS_VERITY_DESCRIPTOR_TYPE.to_le_bytes());
        output.extend_from_slice(&(descriptor_length as u32).to_le_bytes());
        output.extend_from_slice(&descriptor);
        output.extend_from_slice(&signature);
        Ok(output)
    }
}

impl<'a> CodeSignPropertyBuilder<'a> {
    pub(crate) fn new(
        signing_identity: &'a SigningIdentity,
        alg_id: u32,
        profile_bytes: &[u8],
        profile_signed: bool,
    ) -> Result<Self, SignError> {
        Ok(Self {
            signing_identity,
            alg_id,
            profile: ProfileContent::from_profile(profile_bytes, profile_signed)?,
        })
    }

    pub(crate) fn build_property_block(
        &self,
        hap_zip: &HapZip,
        code_sign_offset: usize,
    ) -> Result<Vec<u8>, SignError> {
        let owner_id = self.profile.owner_id()?;
        let public_hnp_owner_id = self.profile.public_hnp_owner_id()?;
        let plugin_id = self.plugin_id_if_needed(hap_zip)?;
        let code_sign_block = CodeSignBlockBuilder::new(
            hap_zip,
            self.signing_identity,
            self.alg_id,
            owner_id,
            public_hnp_owner_id,
            plugin_id,
            code_sign_offset,
        )
        .build()?;

        let mut value = Vec::with_capacity(12 + code_sign_block.len());
        value.extend_from_slice(&signing_block::BLOCK_ID_CODE_SIGN.to_le_bytes());
        value.extend_from_slice(&(code_sign_block.len() as u32).to_le_bytes());
        value.extend_from_slice(&(code_sign_offset as u32).to_le_bytes());
        value.extend_from_slice(&code_sign_block);
        Ok(value)
    }

    fn plugin_id_if_needed(&self, hap_zip: &HapZip) -> Result<Option<String>, SignError> {
        let Ok(module_json) = hap_zip.read_uncompressed_entry("module.json") else {
            return Ok(None);
        };
        let module_json = String::from_utf8(module_json)
            .map_err(|e| SignError::Config(format!("module.json is not UTF-8: {e}")))?;
        let value: serde_json::Value = serde_json::from_str(&module_json)
            .map_err(|e| SignError::Config(format!("module.json is not valid JSON: {e}")))?;
        let bundle_type = value
            .get("app")
            .and_then(|app| app.get("bundleType"))
            .and_then(serde_json::Value::as_str);
        if bundle_type == Some("appPlugin") {
            Ok(Some(self.profile.plugin_id()?))
        } else {
            Ok(None)
        }
    }
}

struct CodeSignBlockBuilder<'a> {
    hap_zip: &'a HapZip,
    signing_identity: &'a SigningIdentity,
    alg_id: u32,
    owner_id: Option<String>,
    public_hnp_owner_id: &'static str,
    plugin_id: Option<String>,
    code_sign_offset: usize,
}

impl<'a> CodeSignBlockBuilder<'a> {
    fn new(
        hap_zip: &'a HapZip,
        signing_identity: &'a SigningIdentity,
        alg_id: u32,
        owner_id: Option<String>,
        public_hnp_owner_id: &'static str,
        plugin_id: Option<String>,
        code_sign_offset: usize,
    ) -> Self {
        Self {
            hap_zip,
            signing_identity,
            alg_id,
            owner_id,
            public_hnp_owner_id,
            plugin_id,
            code_sign_offset,
        }
    }

    fn build(&self) -> Result<Vec<u8>, SignError> {
        let signed_data_builder =
            pkcs7::CodeSignSignedDataBuilder::from_identity(self.signing_identity, self.alg_id)?;

        let zero_padding_len = self.merkle_tree_padding_len();
        let fsv_tree_offset = self.code_sign_offset
            + CODE_SIGN_BLOCK_HEADER_SIZE
            + CODE_SIGN_SEGMENT_COUNT * CODE_SIGN_SEGMENT_HEADER_SIZE
            + zero_padding_len;

        let data_size = self.hap_zip.code_sign_data_size()?;
        let hap_fsverity =
            FsVerityGenerator::generate_pieces(data_size, fsv_tree_offset as u64, |push| {
                self.hap_zip
                    .try_for_each_entry_section_prefix_piece(data_size, push)
            })?;
        let hap_signature = self.sign_fsverity_digest(
            &signed_data_builder,
            &hap_fsverity.digest,
            self.owner_id.as_deref(),
        )?;
        let mut hap_sign_info = SignInfo::new(
            SIGN_INFO_FLAG_MERKLE_TREE_INCLUDED,
            data_size as u64,
            hap_signature,
        );
        hap_sign_info.add_extension(Extension::MerkleTree {
            size: hap_fsverity.tree.len() as u64,
            offset: fsv_tree_offset as u64,
            root_hash: hap_fsverity.root_hash,
        });

        let native_sign_infos = self.native_sign_infos(&signed_data_builder)?;
        let fs_verity_info_segment = FsVerityInfoSegment.to_bytes();
        let hap_info_segment = HapInfoSegment { hap_sign_info }.into_bytes();
        let native_lib_info_segment = NativeLibInfoSegment {
            entries: native_sign_infos,
        }
        .into_bytes();

        let segment_start = CODE_SIGN_BLOCK_HEADER_SIZE
            + CODE_SIGN_SEGMENT_COUNT * CODE_SIGN_SEGMENT_HEADER_SIZE
            + zero_padding_len
            + hap_fsverity.tree.len();
        let fs_verity_header = SegmentHeader {
            segment_type: SEGMENT_FS_VERITY_INFO,
            offset: segment_start,
            size: fs_verity_info_segment.len(),
        };
        let hap_header = SegmentHeader {
            segment_type: SEGMENT_HAP_INFO,
            offset: segment_start + fs_verity_info_segment.len(),
            size: hap_info_segment.len(),
        };
        let native_header = SegmentHeader {
            segment_type: SEGMENT_NATIVE_LIB_INFO,
            offset: segment_start + fs_verity_info_segment.len() + hap_info_segment.len(),
            size: native_lib_info_segment.len(),
        };

        let block_size = CODE_SIGN_BLOCK_HEADER_SIZE
            + CODE_SIGN_SEGMENT_COUNT * CODE_SIGN_SEGMENT_HEADER_SIZE
            + zero_padding_len
            + hap_fsverity.tree.len()
            + fs_verity_info_segment.len()
            + hap_info_segment.len()
            + native_lib_info_segment.len();
        let flags = CODE_SIGN_FLAG_MERKLE_TREE_INLINED
            | if native_header.size > 12 {
                CODE_SIGN_FLAG_NATIVE_LIB_INCLUDED
            } else {
                0
            };

        let mut output = Vec::with_capacity(block_size);
        CodeSignBlockHeader { block_size, flags }.write_to(&mut output);
        fs_verity_header.write_to(&mut output);
        hap_header.write_to(&mut output);
        native_header.write_to(&mut output);
        output.resize(output.len() + zero_padding_len, 0);
        output.extend_from_slice(&hap_fsverity.tree);
        output.extend_from_slice(&fs_verity_info_segment);
        output.extend_from_slice(&hap_info_segment);
        output.extend_from_slice(&native_lib_info_segment);
        Ok(output)
    }

    fn merkle_tree_padding_len(&self) -> usize {
        let size_without_merkle =
            CODE_SIGN_BLOCK_HEADER_SIZE + CODE_SIGN_SEGMENT_COUNT * CODE_SIGN_SEGMENT_HEADER_SIZE;
        let residual = (self.code_sign_offset + size_without_merkle) % PAGE_SIZE;
        if residual == 0 {
            0
        } else {
            PAGE_SIZE - residual
        }
    }

    fn native_sign_infos(
        &self,
        signed_data_builder: &pkcs7::CodeSignSignedDataBuilder,
    ) -> Result<Vec<(String, SignInfo)>, SignError> {
        let entries = self
            .hap_zip
            .native_entry_names()
            .into_iter()
            .map(|name| {
                let data_size = self.hap_zip.uncompressed_entry_size(&name)?;
                let fsverity = FsVerityGenerator::generate_pieces(data_size, 0, |push| {
                    self.hap_zip
                        .try_for_each_uncompressed_entry_piece(&name, push)
                })?;
                let signature = self.sign_fsverity_digest(
                    signed_data_builder,
                    &fsverity.digest,
                    self.owner_id.as_deref(),
                )?;
                Ok::<_, SignError>((name, SignInfo::new(0, data_size as u64, signature)))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut signed = entries;
        signed.extend(self.hnp_sign_infos(signed_data_builder)?);
        Ok(signed)
    }

    fn hnp_sign_infos(
        &self,
        signed_data_builder: &pkcs7::CodeSignSignedDataBuilder,
    ) -> Result<Vec<(String, SignInfo)>, SignError> {
        let packages = self.hnp_packages()?;
        let mut result = Vec::new();
        for entry in self.hap_zip.entries.iter().filter(|entry| {
            entry.name.starts_with("hnp/") && entry.name.to_ascii_lowercase().ends_with(".hnp")
        }) {
            let package_name = entry.name.split('/').skip(2).collect::<Vec<_>>().join("/");
            let package_type = packages
                .get(&package_name)
                .ok_or_else(|| SignError::HnpNotDeclared(entry.name.clone()))?;
            let owner_id = if package_type == "public" {
                Some(self.public_hnp_owner_id)
            } else {
                self.owner_id.as_deref()
            };
            let bytes = self.hap_zip.read_uncompressed_entry(&entry.name)?;
            let hnp = HapZip::parse_owned(bytes).map_err(|error| SignError::InvalidHnp {
                name: entry.name.clone(),
                message: error.to_string(),
            })?;
            let signed_entries = hnp
                .entries
                .iter()
                .map(|inner_entry| {
                    let data = hnp.read_uncompressed_entry(&inner_entry.name)?;
                    if !data.starts_with(b"\x7fELF") {
                        return Ok(None);
                    }
                    let fsverity = FsVerityGenerator::generate(&data, 0)?;
                    let signature =
                        self.sign_fsverity_digest(signed_data_builder, &fsverity.digest, owner_id)?;
                    Ok::<_, SignError>(Some((
                        format!("{}!/{}", entry.name, inner_entry.name),
                        SignInfo::new(0, data.len() as u64, signature),
                    )))
                })
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .flatten()
                .collect::<Vec<_>>();
            result.extend(signed_entries);
        }
        Ok(result)
    }

    fn hnp_packages(&self) -> Result<BTreeMap<String, String>, SignError> {
        let Ok(module_json) = self.hap_zip.read_uncompressed_entry("module.json") else {
            return Ok(BTreeMap::new());
        };
        let value: serde_json::Value = serde_json::from_slice(&module_json).map_err(|error| {
            SignError::Config(format!("module.json is not valid JSON: {error}"))
        })?;
        let packages = value
            .get("module")
            .and_then(|module| module.get("hnpPackages"))
            .and_then(serde_json::Value::as_array);
        let mut inventory = BTreeMap::new();
        for package in packages.into_iter().flatten() {
            let Some(name) = package.get("package").and_then(serde_json::Value::as_str) else {
                continue;
            };
            if name.is_empty() {
                continue;
            }
            let package_type = package
                .get("type")
                .and_then(serde_json::Value::as_str)
                .filter(|value| !value.is_empty())
                .unwrap_or("private");
            inventory.insert(name.to_owned(), package_type.to_owned());
        }
        Ok(inventory)
    }

    fn sign_fsverity_digest(
        &self,
        signed_data_builder: &pkcs7::CodeSignSignedDataBuilder,
        digest: &[u8],
        owner_id: Option<&str>,
    ) -> Result<Vec<u8>, SignError> {
        signed_data_builder.build(digest, owner_id, self.plugin_id.as_deref())
    }
}

struct FsVerityGenerator;

struct FsVerityOutput {
    digest: Vec<u8>,
    tree: Vec<u8>,
    root_hash: [u8; DIGEST_SIZE],
}

pub(crate) struct CodeSignVerifier<'a> {
    input: &'a [u8],
    profile: Option<&'a ProfileContent>,
}

struct ParsedSignInfo<'a> {
    data_size: usize,
    signature: &'a [u8],
    merkle_tree: Option<ParsedMerkleTree>,
}

struct ParsedMerkleTree {
    size: usize,
    offset: usize,
    root_hash: [u8; DIGEST_SIZE],
}

impl<'a> CodeSignVerifier<'a> {
    pub(crate) fn new(input: &'a [u8], profile: Option<&'a ProfileContent>) -> Self {
        Self { input, profile }
    }

    pub(crate) fn verify_hap_properties(
        &self,
        signing_block: &SigningBlockInfo,
    ) -> Result<(), SignError> {
        for entry in signing_block
            .blocks
            .iter()
            .filter(|entry| entry.block_type == signing_block::BLOCK_ID_PROPERTY)
        {
            let property = self.slice(entry.offset, entry.length, "HAP property block")?;
            if property.len() < 12
                || Self::read_u32(property, 0)? != signing_block::BLOCK_ID_CODE_SIGN
            {
                continue;
            }
            let length = Self::read_u32(property, 4)? as usize;
            let offset = Self::read_u32(property, 8)? as usize;
            if offset != entry.offset + 12 || length.checked_add(12) != Some(property.len()) {
                return Err(SignError::VerificationFailed(
                    "HAP code-sign property offset or length is invalid".to_owned(),
                ));
            }
            self.verify_hap_block(&property[12..], offset)?;
        }
        Ok(())
    }

    pub(crate) fn verify_elf_block(
        &self,
        signed_data: &[u8],
        block: &[u8],
        block_offset: usize,
    ) -> Result<(), SignError> {
        let tree_type = Self::read_u32(block, 0)?;
        let tree_length = Self::read_u32(block, 4)? as usize;
        if tree_type != 2 {
            return Err(SignError::VerificationFailed(
                "ELF code-sign block has no inline Merkle tree".to_owned(),
            ));
        }
        let descriptor_head = 8usize.checked_add(tree_length).ok_or_else(|| {
            SignError::VerificationFailed("ELF code-sign tree length overflow".to_owned())
        })?;
        if Self::read_u32(block, descriptor_head)? != 1 {
            return Err(SignError::VerificationFailed(
                "ELF code-sign block has no fs-verity descriptor".to_owned(),
            ));
        }
        let descriptor_length = Self::read_u32(block, descriptor_head + 4)? as usize;
        let descriptor_start = descriptor_head + 8;
        let descriptor_end = descriptor_start
            .checked_add(descriptor_length)
            .ok_or_else(|| {
                SignError::VerificationFailed("ELF descriptor length overflow".to_owned())
            })?;
        if descriptor_end != block.len() || descriptor_length < FS_VERITY_DESCRIPTOR_SIZE {
            return Err(SignError::VerificationFailed(
                "ELF fs-verity descriptor range is invalid".to_owned(),
            ));
        }
        let descriptor = &block[descriptor_start..descriptor_start + FS_VERITY_DESCRIPTOR_SIZE];
        let signature_length = Self::read_u32(descriptor, 4)? as usize;
        if FS_VERITY_DESCRIPTOR_SIZE.checked_add(signature_length) != Some(descriptor_length) {
            return Err(SignError::VerificationFailed(
                "ELF code-sign signature length is invalid".to_owned(),
            ));
        }
        let file_size = Self::read_u64(descriptor, 8)? as usize;
        if file_size != signed_data.len() {
            return Err(SignError::VerificationFailed(
                "ELF fs-verity file size does not match signed data".to_owned(),
            ));
        }
        let tree_offset = Self::read_u64(descriptor, 120)? as usize;
        let expected_tree_start = block_offset
            .checked_add(8)
            .ok_or_else(|| SignError::VerificationFailed("ELF tree offset overflow".to_owned()))?;
        if tree_offset < expected_tree_start || tree_offset > block_offset + descriptor_head {
            return Err(SignError::VerificationFailed(
                "ELF fs-verity tree offset is outside the tree block".to_owned(),
            ));
        }
        let padding = tree_offset - expected_tree_start;
        let fsverity = FsVerityGenerator::generate(signed_data, tree_offset as u64)?;
        if tree_length != padding + fsverity.tree.len()
            || block[8..8 + padding].iter().any(|byte| *byte != 0)
            || block[8 + padding..descriptor_head] != fsverity.tree
            || descriptor[16..48] != fsverity.root_hash
        {
            return Err(SignError::VerificationFailed(
                "ELF fs-verity Merkle tree or root hash is invalid".to_owned(),
            ));
        }
        let signature = &block[descriptor_start + FS_VERITY_DESCRIPTOR_SIZE..descriptor_end];
        let verified = pkcs7::verify_detached_cms_signed_data(signature, &fsverity.digest)?;
        self.verify_owner_id(&verified, false)?;
        Ok(())
    }

    fn verify_hap_block(&self, block: &[u8], block_offset: usize) -> Result<(), SignError> {
        if block.len() < CODE_SIGN_BLOCK_HEADER_SIZE
            || Self::read_u64(block, 0)? != CODE_SIGN_BLOCK_MAGIC
            || Self::read_u32(block, 8)? != CODE_SIGN_BLOCK_VERSION
            || Self::read_u32(block, 12)? as usize != block.len()
        {
            return Err(SignError::VerificationFailed(
                "HAP code-sign header is invalid".to_owned(),
            ));
        }
        let segment_count = Self::read_u32(block, 16)? as usize;
        let headers_end = CODE_SIGN_BLOCK_HEADER_SIZE
            .checked_add(
                segment_count
                    .checked_mul(CODE_SIGN_SEGMENT_HEADER_SIZE)
                    .ok_or_else(|| {
                        SignError::VerificationFailed("code-sign segment count overflow".to_owned())
                    })?,
            )
            .ok_or_else(|| {
                SignError::VerificationFailed("code-sign segment headers overflow".to_owned())
            })?;
        if headers_end > block.len() {
            return Err(SignError::VerificationFailed(
                "HAP code-sign segment headers are truncated".to_owned(),
            ));
        }
        let mut hap_segment = None;
        let mut native_segment = None;
        for index in 0..segment_count {
            let header = CODE_SIGN_BLOCK_HEADER_SIZE + index * CODE_SIGN_SEGMENT_HEADER_SIZE;
            let segment_type = Self::read_u32(block, header)?;
            let offset = Self::read_u32(block, header + 4)? as usize;
            let size = Self::read_u32(block, header + 8)? as usize;
            let segment = block
                .get(
                    offset..offset.checked_add(size).ok_or_else(|| {
                        SignError::VerificationFailed("code-sign segment range overflow".to_owned())
                    })?,
                )
                .ok_or_else(|| {
                    SignError::VerificationFailed("code-sign segment exceeds block".to_owned())
                })?;
            match segment_type {
                SEGMENT_HAP_INFO => hap_segment = Some(segment),
                SEGMENT_NATIVE_LIB_INFO => native_segment = Some(segment),
                _ => {}
            }
        }
        let hap_segment = hap_segment.ok_or_else(|| {
            SignError::VerificationFailed("HAP code-sign block has no HAP info segment".to_owned())
        })?;
        if Self::read_u32(hap_segment, 0)? != HAP_INFO_MAGIC {
            return Err(SignError::VerificationFailed(
                "HAP info segment magic is invalid".to_owned(),
            ));
        }
        let hap_sign_info = self.parse_sign_info(hap_segment, 4)?;
        let merkle_tree = hap_sign_info.merkle_tree.as_ref().ok_or_else(|| {
            SignError::VerificationFailed("HAP sign info has no Merkle-tree extension".to_owned())
        })?;
        let data = self.input.get(..hap_sign_info.data_size).ok_or_else(|| {
            SignError::VerificationFailed("HAP code-sign data size exceeds input".to_owned())
        })?;
        let fsverity = FsVerityGenerator::generate(data, merkle_tree.offset as u64)?;
        let relative_tree_offset =
            merkle_tree
                .offset
                .checked_sub(block_offset)
                .ok_or_else(|| {
                    SignError::VerificationFailed(
                        "HAP Merkle-tree offset precedes code-sign block".to_owned(),
                    )
                })?;
        let embedded_tree = block
            .get(
                relative_tree_offset
                    ..relative_tree_offset
                        .checked_add(merkle_tree.size)
                        .ok_or_else(|| {
                            SignError::VerificationFailed(
                                "HAP Merkle-tree range overflow".to_owned(),
                            )
                        })?,
            )
            .ok_or_else(|| {
                SignError::VerificationFailed("HAP Merkle tree exceeds code-sign block".to_owned())
            })?;
        if embedded_tree != fsverity.tree || merkle_tree.root_hash != fsverity.root_hash {
            return Err(SignError::VerificationFailed(
                "HAP fs-verity Merkle tree or root hash is invalid".to_owned(),
            ));
        }
        let verified =
            pkcs7::verify_detached_cms_signed_data(hap_sign_info.signature, &fsverity.digest)?;
        self.verify_owner_id(&verified, false)?;
        if let Some(native_segment) = native_segment {
            self.verify_native_segment(native_segment)?;
        }
        Ok(())
    }

    fn verify_native_segment(&self, segment: &[u8]) -> Result<(), SignError> {
        if Self::read_u32(segment, 0)? != NATIVE_LIB_INFO_MAGIC
            || Self::read_u32(segment, 4)? as usize != segment.len()
        {
            return Err(SignError::VerificationFailed(
                "native-library code-sign segment is invalid".to_owned(),
            ));
        }
        let count = Self::read_u32(segment, 8)? as usize;
        let records_end = 12usize
            .checked_add(count.checked_mul(16).ok_or_else(|| {
                SignError::VerificationFailed("native sign-info count overflow".to_owned())
            })?)
            .ok_or_else(|| {
                SignError::VerificationFailed("native sign-info table overflow".to_owned())
            })?;
        if records_end > segment.len() {
            return Err(SignError::VerificationFailed(
                "native sign-info table is truncated".to_owned(),
            ));
        }
        let hap = HapZip::parse(self.input)?;
        for index in 0..count {
            let record = 12 + index * 16;
            let name_offset = Self::read_u32(segment, record)? as usize;
            let name_length = Self::read_u32(segment, record + 4)? as usize;
            let sign_info_offset = Self::read_u32(segment, record + 8)? as usize;
            let sign_info_length = Self::read_u32(segment, record + 12)? as usize;
            let name = std::str::from_utf8(self.segment_slice(
                segment,
                name_offset,
                name_length,
                "native sign-info name",
            )?)
            .map_err(|error| {
                SignError::VerificationFailed(format!(
                    "native sign-info name is not UTF-8: {error}"
                ))
            })?;
            let sign_info_bytes = self.segment_slice(
                segment,
                sign_info_offset,
                sign_info_length,
                "native sign-info",
            )?;
            let sign_info = self.parse_sign_info(sign_info_bytes, 0)?;
            let data = self.native_entry_data(&hap, name)?;
            if data.len() != sign_info.data_size {
                return Err(SignError::VerificationFailed(format!(
                    "native code-sign data size differs for '{name}'"
                )));
            }
            let fsverity = FsVerityGenerator::generate(&data, 0)?;
            let verified =
                pkcs7::verify_detached_cms_signed_data(sign_info.signature, &fsverity.digest)?;
            self.verify_owner_id(&verified, self.is_public_hnp(&hap, name)?)?;
        }
        Ok(())
    }

    fn native_entry_data(&self, hap: &HapZip, name: &str) -> Result<Vec<u8>, SignError> {
        let Some((outer, inner)) = name.split_once("!/") else {
            return hap.read_uncompressed_entry(name);
        };
        let hnp_bytes = hap.read_uncompressed_entry(outer)?;
        let hnp = HapZip::parse_owned(hnp_bytes).map_err(|error| SignError::InvalidHnp {
            name: outer.to_owned(),
            message: error.to_string(),
        })?;
        hnp.read_uncompressed_entry(inner)
    }

    fn is_public_hnp(&self, hap: &HapZip, name: &str) -> Result<bool, SignError> {
        let Some((outer, _)) = name.split_once("!/") else {
            return Ok(false);
        };
        let package_name = outer.split('/').skip(2).collect::<Vec<_>>().join("/");
        let module_json = hap.read_uncompressed_entry("module.json")?;
        let value: serde_json::Value = serde_json::from_slice(&module_json).map_err(|error| {
            SignError::VerificationFailed(format!("module.json is not valid JSON: {error}"))
        })?;
        let packages = value
            .get("module")
            .and_then(|module| module.get("hnpPackages"))
            .and_then(serde_json::Value::as_array);
        let package_type = packages
            .into_iter()
            .flatten()
            .find(|package| {
                package.get("package").and_then(serde_json::Value::as_str)
                    == Some(package_name.as_str())
            })
            .ok_or_else(|| SignError::HnpNotDeclared(outer.to_owned()))?
            .get("type")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.is_empty())
            .unwrap_or("private");
        Ok(package_type == "public")
    }

    fn verify_owner_id(
        &self,
        verified: &pkcs7::VerifiedCms,
        public_hnp: bool,
    ) -> Result<(), SignError> {
        let Some(profile) = self.profile else {
            return Ok(());
        };
        let debug = profile.profile_type()?.eq_ignore_ascii_case("debug");
        let expected = if public_hnp {
            Some(profile.public_hnp_owner_id()?.to_owned())
        } else {
            profile.owner_id()?
        };
        match (&verified.owner_id, expected.as_deref()) {
            (None, _) if debug => Ok(()),
            (None, None) => Ok(()),
            (None, Some(_)) => Err(SignError::VerificationFailed(
                "app-identifier is not in the code signature".to_owned(),
            )),
            (Some(_), None) => Err(SignError::VerificationFailed(
                "app-identifier is present in the code signature but absent from the profile"
                    .to_owned(),
            )),
            (Some(actual), Some(expected)) if actual == expected => Ok(()),
            (Some(_), Some(_)) => Err(SignError::VerificationFailed(
                "app-identifier in the code signature does not match the profile".to_owned(),
            )),
        }
    }

    fn parse_sign_info<'b>(
        &self,
        bytes: &'b [u8],
        start: usize,
    ) -> Result<ParsedSignInfo<'b>, SignError> {
        let fixed = self.segment_slice(bytes, start, SIGN_INFO_FIXED_SIZE, "sign info")?;
        let signature_length = Self::read_u32(fixed, 4)? as usize;
        let data_size = usize::try_from(Self::read_u64(fixed, 12)?).map_err(|_| {
            SignError::VerificationFailed("code-sign data size exceeds usize".to_owned())
        })?;
        let extension_count = Self::read_u32(fixed, 52)? as usize;
        let extension_offset = Self::read_u32(fixed, 56)? as usize;
        let signature = self.segment_slice(
            bytes,
            start + SIGN_INFO_FIXED_SIZE,
            signature_length,
            "code-sign CMS signature",
        )?;
        let mut merkle_tree = None;
        let mut extension = start.checked_add(extension_offset).ok_or_else(|| {
            SignError::VerificationFailed("code-sign extension offset overflow".to_owned())
        })?;
        for _ in 0..extension_count {
            let extension_type = Self::read_u32(bytes, extension)?;
            let extension_size = Self::read_u32(bytes, extension + 4)? as usize;
            let extension_data =
                self.segment_slice(bytes, extension + 8, extension_size, "code-sign extension")?;
            if extension_type == EXTENSION_MERKLE_TREE_INLINED {
                if extension_size != EXTENSION_MERKLE_TREE_SIZE as usize {
                    return Err(SignError::VerificationFailed(
                        "Merkle-tree extension size is invalid".to_owned(),
                    ));
                }
                let mut root_hash = [0u8; DIGEST_SIZE];
                root_hash.copy_from_slice(&extension_data[16..16 + DIGEST_SIZE]);
                merkle_tree = Some(ParsedMerkleTree {
                    size: usize::try_from(Self::read_u64(extension_data, 0)?).map_err(|_| {
                        SignError::VerificationFailed("Merkle-tree size exceeds usize".to_owned())
                    })?,
                    offset: usize::try_from(Self::read_u64(extension_data, 8)?).map_err(|_| {
                        SignError::VerificationFailed("Merkle-tree offset exceeds usize".to_owned())
                    })?,
                    root_hash,
                });
            }
            extension = extension.checked_add(8 + extension_size).ok_or_else(|| {
                SignError::VerificationFailed("code-sign extension range overflow".to_owned())
            })?;
        }
        Ok(ParsedSignInfo {
            data_size,
            signature,
            merkle_tree,
        })
    }

    fn segment_slice<'b>(
        &self,
        bytes: &'b [u8],
        offset: usize,
        length: usize,
        label: &str,
    ) -> Result<&'b [u8], SignError> {
        bytes
            .get(
                offset..offset.checked_add(length).ok_or_else(|| {
                    SignError::VerificationFailed(format!("{label} range overflow"))
                })?,
            )
            .ok_or_else(|| SignError::VerificationFailed(format!("{label} is truncated")))
    }

    fn slice(&self, offset: usize, length: usize, label: &str) -> Result<&'a [u8], SignError> {
        self.segment_slice(self.input, offset, length, label)
    }

    fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, SignError> {
        bytes
            .get(offset..offset + 4)
            .map(|value| u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
            .ok_or_else(|| SignError::VerificationFailed("truncated code-sign u32".to_owned()))
    }

    fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, SignError> {
        bytes
            .get(offset..offset + 8)
            .map(|value| {
                u64::from_le_bytes([
                    value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7],
                ])
            })
            .ok_or_else(|| SignError::VerificationFailed("truncated code-sign u64".to_owned()))
    }
}

impl FsVerityGenerator {
    fn generate(data: &[u8], merkle_tree_offset: u64) -> Result<FsVerityOutput, SignError> {
        Self::generate_pieces(data.len(), merkle_tree_offset, |push| {
            push(data);
            Ok(())
        })
    }

    fn generate_pieces<F>(
        data_size: usize,
        merkle_tree_offset: u64,
        feed: F,
    ) -> Result<FsVerityOutput, SignError>
    where
        F: FnOnce(&mut dyn FnMut(&[u8])) -> Result<(), SignError>,
    {
        let merkle = MerkleTree::from_pieces(data_size, merkle_tree_offset != 0, feed)?;
        let flags = if merkle_tree_offset == 0 {
            0
        } else {
            FS_VERITY_DESCRIPTOR_FLAG_STORE_MERKLE_TREE_OFFSET
        };
        let descriptor = FsVerityDescriptor {
            file_size: data_size as u64,
            root_hash: merkle.root_hash,
            flags,
            merkle_tree_offset,
        }
        .digest_bytes();
        let digest = Sha256::digest(&descriptor);
        let mut fsverity_digest = Vec::with_capacity(12 + digest.len());
        fsverity_digest.extend_from_slice(FS_VERITY_DIGEST_MAGIC);
        fsverity_digest.extend_from_slice(&(FS_VERITY_HASH_ALGORITHM_SHA256 as u16).to_le_bytes());
        fsverity_digest.extend_from_slice(&(digest.len() as u16).to_le_bytes());
        fsverity_digest.extend_from_slice(&digest);
        Ok(FsVerityOutput {
            digest: fsverity_digest,
            tree: merkle.tree,
            root_hash: merkle.root_hash,
        })
    }
}

struct MerkleTree {
    tree: Vec<u8>,
    root_hash: [u8; DIGEST_SIZE],
}

impl MerkleTree {
    fn from_pieces<F>(data_size: usize, retain_tree: bool, feed: F) -> Result<Self, SignError>
    where
        F: FnOnce(&mut dyn FnMut(&[u8])) -> Result<(), SignError>,
    {
        let leaf_count = data_size.div_ceil(PAGE_SIZE);
        let leaf_len = (leaf_count * DIGEST_SIZE).div_ceil(PAGE_SIZE) * PAGE_SIZE;
        let mut leaf = Vec::with_capacity(leaf_len);
        let mut page = [0u8; PAGE_SIZE];
        let mut page_len = 0usize;
        let mut observed = 0usize;
        {
            let mut push = |mut piece: &[u8]| {
                observed += piece.len();
                while !piece.is_empty() {
                    let take = (PAGE_SIZE - page_len).min(piece.len());
                    page[page_len..page_len + take].copy_from_slice(&piece[..take]);
                    page_len += take;
                    piece = &piece[take..];
                    if page_len == PAGE_SIZE {
                        leaf.extend_from_slice(&Sha256::digest(page));
                        page.fill(0);
                        page_len = 0;
                    }
                }
            };
            feed(&mut push)?;
        }
        if observed != data_size {
            return Err(SignError::DigestError(format!(
                "fs-verity input length mismatch: expected {data_size}, observed {observed}"
            )));
        }
        if page_len != 0 {
            leaf.extend_from_slice(&Sha256::digest(page));
        }
        leaf.resize(leaf_len, 0);

        if data_size == 0 {
            return Ok(Self {
                tree: Vec::new(),
                root_hash: [0; DIGEST_SIZE],
            });
        }
        if data_size <= PAGE_SIZE {
            let mut root_hash = [0u8; DIGEST_SIZE];
            root_hash.copy_from_slice(&leaf[..DIGEST_SIZE]);
            return Ok(Self {
                tree: Vec::new(),
                root_hash,
            });
        }

        if !retain_tree {
            let mut level = leaf;
            while level.len() > PAGE_SIZE {
                level = Self::hash_level(&level);
            }
            let root_hash: [u8; DIGEST_SIZE] = Sha256::digest(&level[..PAGE_SIZE]).into();
            return Ok(Self {
                tree: Vec::new(),
                root_hash,
            });
        }

        let mut levels = vec![leaf];
        loop {
            let Some(level) = levels.last() else {
                break;
            };
            if level.len() <= PAGE_SIZE {
                break;
            }
            let parent = Self::hash_level(level);
            levels.push(parent);
        }
        levels.reverse();
        let tree = levels.concat();
        let root_hash: [u8; DIGEST_SIZE] = Sha256::digest(&tree[..PAGE_SIZE]).into();
        Ok(Self { tree, root_hash })
    }

    fn hash_level(data: &[u8]) -> Vec<u8> {
        let chunk_count = data.len().div_ceil(PAGE_SIZE);
        let digest_bytes_len = chunk_count * DIGEST_SIZE;
        let padded_len = digest_bytes_len.div_ceil(PAGE_SIZE) * PAGE_SIZE;
        let mut output = Vec::with_capacity(padded_len);
        for chunk_index in 0..chunk_count {
            let start = chunk_index * PAGE_SIZE;
            let end = (start + PAGE_SIZE).min(data.len());
            let mut page = [0u8; PAGE_SIZE];
            page[..end - start].copy_from_slice(&data[start..end]);
            output.extend_from_slice(&Sha256::digest(page));
        }
        output.resize(padded_len, 0);
        output
    }
}

struct FsVerityDescriptor {
    file_size: u64,
    root_hash: [u8; DIGEST_SIZE],
    flags: u32,
    merkle_tree_offset: u64,
}

impl FsVerityDescriptor {
    fn digest_bytes(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(FS_VERITY_DESCRIPTOR_SIZE);
        output.push(1);
        output.push(FS_VERITY_HASH_ALGORITHM_SHA256);
        output.push(FS_VERITY_LOG2_BLOCK_SIZE);
        output.push(0);
        output.extend_from_slice(&0u32.to_le_bytes());
        output.extend_from_slice(&self.file_size.to_le_bytes());
        output.extend_from_slice(&self.root_hash);
        output.resize(output.len() + (64 - DIGEST_SIZE), 0);
        output.resize(output.len() + 32, 0);
        output.extend_from_slice(&self.flags.to_le_bytes());
        output.extend_from_slice(&0u32.to_le_bytes());
        output.extend_from_slice(&self.merkle_tree_offset.to_le_bytes());
        output.resize(FS_VERITY_DESCRIPTOR_SIZE, 0);
        output
    }

    fn to_bytes(&self, signature_len: usize) -> Result<Vec<u8>, SignError> {
        let signature_len = u32::try_from(signature_len).map_err(|_| {
            SignError::SigningFailed("ELF code-sign signature is too large".to_owned())
        })?;
        let mut output = Vec::with_capacity(FS_VERITY_DESCRIPTOR_SIZE);
        output.push(1);
        output.push(FS_VERITY_HASH_ALGORITHM_SHA256);
        output.push(FS_VERITY_LOG2_BLOCK_SIZE);
        output.push(0);
        output.extend_from_slice(&signature_len.to_le_bytes());
        output.extend_from_slice(&self.file_size.to_le_bytes());
        output.extend_from_slice(&self.root_hash);
        output.resize(output.len() + (64 - DIGEST_SIZE), 0);
        output.resize(output.len() + 32, 0);
        output.extend_from_slice(&self.flags.to_le_bytes());
        output.extend_from_slice(&0u32.to_le_bytes());
        output.extend_from_slice(&self.merkle_tree_offset.to_le_bytes());
        output.extend_from_slice(&0u64.to_le_bytes());
        output.resize(FS_VERITY_DESCRIPTOR_SIZE - 1, 0);
        output.push(1);
        Ok(output)
    }
}

struct SignInfo {
    flags: u32,
    data_size: u64,
    signature: Vec<u8>,
    extensions: Vec<Extension>,
}

impl SignInfo {
    fn new(flags: u32, data_size: u64, signature: Vec<u8>) -> Self {
        Self {
            flags,
            data_size,
            signature,
            extensions: Vec::new(),
        }
    }

    fn add_extension(&mut self, extension: Extension) {
        self.extensions.push(extension);
    }

    fn to_bytes(&self) -> Vec<u8> {
        let zero_padding_len = (4 - self.signature.len() % 4) % 4;
        let extension_offset = SIGN_INFO_FIXED_SIZE + self.signature.len() + zero_padding_len;
        let extensions_len = self.extensions.iter().map(Extension::size).sum::<usize>();
        let mut output = Vec::with_capacity(extension_offset + extensions_len);
        output.extend_from_slice(&0u32.to_le_bytes());
        output.extend_from_slice(&(self.signature.len() as u32).to_le_bytes());
        output.extend_from_slice(&self.flags.to_le_bytes());
        output.extend_from_slice(&self.data_size.to_le_bytes());
        output.resize(output.len() + 32, 0);
        output.extend_from_slice(&(self.extensions.len() as u32).to_le_bytes());
        output.extend_from_slice(&(extension_offset as u32).to_le_bytes());
        output.extend_from_slice(&self.signature);
        output.resize(output.len() + zero_padding_len, 0);
        for extension in &self.extensions {
            extension.write_to(&mut output);
        }
        output
    }
}

enum Extension {
    MerkleTree {
        size: u64,
        offset: u64,
        root_hash: [u8; DIGEST_SIZE],
    },
}

impl Extension {
    fn size(&self) -> usize {
        match self {
            Self::MerkleTree { .. } => 8 + EXTENSION_MERKLE_TREE_SIZE as usize,
        }
    }

    fn write_to(&self, output: &mut Vec<u8>) {
        match self {
            Self::MerkleTree {
                size,
                offset,
                root_hash,
            } => {
                output.extend_from_slice(&EXTENSION_MERKLE_TREE_INLINED.to_le_bytes());
                output.extend_from_slice(&EXTENSION_MERKLE_TREE_SIZE.to_le_bytes());
                output.extend_from_slice(&size.to_le_bytes());
                output.extend_from_slice(&offset.to_le_bytes());
                output.extend_from_slice(root_hash);
                output.resize(output.len() + (64 - DIGEST_SIZE), 0);
            }
        }
    }
}

struct FsVerityInfoSegment;

impl FsVerityInfoSegment {
    fn to_bytes(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(64);
        output.extend_from_slice(&FS_VERITY_INFO_MAGIC.to_le_bytes());
        output.push(1);
        output.push(FS_VERITY_HASH_ALGORITHM_SHA256);
        output.push(FS_VERITY_LOG2_BLOCK_SIZE);
        output.resize(64, 0);
        output
    }
}

struct HapInfoSegment {
    hap_sign_info: SignInfo,
}

impl HapInfoSegment {
    fn into_bytes(self) -> Vec<u8> {
        let sign_info = self.hap_sign_info.to_bytes();
        let mut output = Vec::with_capacity(4 + sign_info.len());
        output.extend_from_slice(&HAP_INFO_MAGIC.to_le_bytes());
        output.extend_from_slice(&sign_info);
        output
    }
}

struct NativeLibInfoSegment {
    entries: Vec<(String, SignInfo)>,
}

impl NativeLibInfoSegment {
    fn into_bytes(self) -> Vec<u8> {
        let names = self
            .entries
            .iter()
            .map(|(name, _)| name.as_bytes())
            .collect::<Vec<_>>();
        let sign_infos = self
            .entries
            .iter()
            .map(|(_, sign_info)| sign_info.to_bytes())
            .collect::<Vec<_>>();
        let names_len = names.iter().map(|name| name.len()).sum::<usize>();
        let sign_infos_len = sign_infos.iter().map(Vec::len).sum::<usize>();
        let zero_padding_len = (4 - names_len % 4) % 4;
        let pos_table_len = self.entries.len() * 16;
        let name_base = 12 + pos_table_len;
        let sign_info_base = name_base + names_len + zero_padding_len;
        let segment_size = 12 + pos_table_len + names_len + zero_padding_len + sign_infos_len;

        let mut output = Vec::with_capacity(segment_size);
        output.extend_from_slice(&NATIVE_LIB_INFO_MAGIC.to_le_bytes());
        output.extend_from_slice(&(segment_size as u32).to_le_bytes());
        output.extend_from_slice(&(self.entries.len() as u32).to_le_bytes());

        let mut name_offset = 0usize;
        let mut sign_info_offset = 0usize;
        for (name, sign_info) in names.iter().zip(sign_infos.iter()) {
            output.extend_from_slice(&((name_base + name_offset) as u32).to_le_bytes());
            output.extend_from_slice(&(name.len() as u32).to_le_bytes());
            output.extend_from_slice(&((sign_info_base + sign_info_offset) as u32).to_le_bytes());
            output.extend_from_slice(&(sign_info.len() as u32).to_le_bytes());
            name_offset += name.len();
            sign_info_offset += sign_info.len();
        }

        for name in names {
            output.extend_from_slice(name);
        }
        output.resize(output.len() + zero_padding_len, 0);
        for sign_info in sign_infos {
            output.extend_from_slice(&sign_info);
        }
        output
    }
}

struct CodeSignBlockHeader {
    block_size: usize,
    flags: u32,
}

impl CodeSignBlockHeader {
    fn write_to(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(&CODE_SIGN_BLOCK_MAGIC.to_le_bytes());
        output.extend_from_slice(&CODE_SIGN_BLOCK_VERSION.to_le_bytes());
        output.extend_from_slice(&(self.block_size as u32).to_le_bytes());
        output.extend_from_slice(&(CODE_SIGN_SEGMENT_COUNT as u32).to_le_bytes());
        output.extend_from_slice(&self.flags.to_le_bytes());
        output.resize(output.len() + 8, 0);
    }
}

struct SegmentHeader {
    segment_type: u32,
    offset: usize,
    size: usize,
}

impl SegmentHeader {
    fn write_to(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.segment_type.to_le_bytes());
        output.extend_from_slice(&(self.offset as u32).to_le_bytes());
        output.extend_from_slice(&(self.size as u32).to_le_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::FsVerityGenerator;

    #[test]
    fn fragmented_fsverity_input_matches_contiguous_input() {
        let data = (0..12_345)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        let contiguous = FsVerityGenerator::generate(&data, 8192).expect("contiguous fs-verity");
        let fragmented = FsVerityGenerator::generate_pieces(data.len(), 8192, |push| {
            push(&data[..1]);
            push(&data[1..4097]);
            push(&data[4097..9000]);
            push(&data[9000..]);
            Ok(())
        })
        .expect("fragmented fs-verity");

        assert_eq!(fragmented.digest, contiguous.digest);
        assert_eq!(fragmented.tree, contiguous.tree);
        assert_eq!(fragmented.root_hash, contiguous.root_hash);
    }
}
