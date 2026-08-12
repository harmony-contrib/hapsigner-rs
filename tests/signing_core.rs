use std::str::FromStr;
use std::sync::Arc;

use hapsigner::{
    ApplicationVerifier, DevelopmentMaterialBuilder, DevelopmentProfileOptions, DevelopmentSigner,
    ExternalSigner, HapSigner, InputFormat, Pkcs12Material, ProfileSigner, ProfileVerifier,
    SignError, SignOptions, SigningAlgorithm, SigningBlockInspector, SigningBlockType, SigningKey,
    SigningMaterial,
};

#[test]
fn development_adapter_uses_core_v3_code_signing_pipeline() {
    let signer = DevelopmentSigner::new(
        development_profile("com.example.v3"),
        SignOptions::default(),
    )
    .expect("development signer");
    let signed = signer.sign(&tiny_zip()).expect("sign V3 HAP");
    let inspector = SigningBlockInspector::new(&signed);
    let info = inspector.inspect().expect("inspect V3 signing block");

    assert_eq!(info.version, 3);
    assert_eq!(
        info.blocks
            .iter()
            .map(|block| block.kind())
            .collect::<Vec<_>>(),
        [
            SigningBlockType::Property,
            SigningBlockType::Profile,
            SigningBlockType::Signature,
        ]
    );
    assert_eq!(
        inspector.embedded_profile().expect("embedded profile")["bundle-info"]["bundle-name"],
        "com.example.v3"
    );
}

#[test]
fn compatible_version_selects_v2_without_changing_injected_material_api() {
    let material = DevelopmentMaterialBuilder::new(development_profile("com.example.v2"))
        .build()
        .expect("development material");
    let signer = HapSigner::new(
        material,
        SignOptions {
            compatible_version: 7,
            code_signing: true,
        },
    );
    let signed = signer.sign_owned(tiny_zip()).expect("sign V2 HAP");
    let info = SigningBlockInspector::new(&signed)
        .inspect()
        .expect("inspect V2 signing block");

    assert_eq!(info.version, 2);
    assert_eq!(info.blocks[0].kind(), SigningBlockType::Property);
}

#[test]
fn pkcs12_rsa_material_is_injected_into_the_same_signer() {
    let fixture = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/test.p12"
    ))
    .expect("read RSA PKCS#12 fixture");
    let fixture_key =
        SigningKey::from_pkcs12(&fixture, "test123", "1", "test123").expect("load RSA fixture");
    let certificates = fixture_key.cert_chain.concat();
    let development_material =
        DevelopmentMaterialBuilder::new(development_profile("com.example.rsa"))
            .build()
            .expect("signed development profile");
    let material = SigningMaterial::from_pkcs12(Pkcs12Material {
        pkcs12: &fixture,
        store_password: "test123",
        key_alias: "1",
        key_password: "test123",
        app_certificate_chain: &certificates,
        signed_profile: development_material.signed_profile().to_vec(),
        algorithm: SigningAlgorithm::RsaPssSha256,
    })
    .expect("inject RSA signing material");
    let signed = HapSigner::new(
        material,
        SignOptions {
            compatible_version: 9,
            code_signing: true,
        },
    )
    .sign_owned(tiny_zip())
    .expect("RSA-PSS sign HAP");
    let info = SigningBlockInspector::new(&signed)
        .inspect()
        .expect("inspect RSA signed HAP");

    assert_eq!(info.version, 3);
    assert_eq!(
        info.blocks
            .iter()
            .map(|block| block.kind())
            .collect::<Vec<_>>(),
        [
            SigningBlockType::Property,
            SigningBlockType::Profile,
            SigningBlockType::Signature,
        ]
    );
}

#[test]
fn hvigor_algorithm_names_are_typed_and_unknown_values_are_rejected() {
    assert_eq!(
        SigningAlgorithm::from_str("SHA256withECDSA").expect("ECDSA name"),
        SigningAlgorithm::EcdsaSha256
    );
    assert_eq!(
        SigningAlgorithm::from_str("SHA256withRSA/PSS").expect("RSA name"),
        SigningAlgorithm::RsaPssSha256
    );
    assert_eq!(
        SigningAlgorithm::from_str("SHA384withECDSA").expect("SHA-384 ECDSA name"),
        SigningAlgorithm::EcdsaSha384
    );
    assert_eq!(
        SigningAlgorithm::from_str("SHA512withRSAandMGF1").expect("SHA-512 RSA alias"),
        SigningAlgorithm::RsaPssSha512
    );
    assert!(matches!(
        SigningAlgorithm::from_str("SHA1withRSA"),
        Err(SignError::UnsupportedAlgorithm(_))
    ));
}

#[test]
fn verify_app_checks_hap_digest_cms_profile_and_code_signatures() {
    let signer = DevelopmentSigner::new(
        development_profile("com.example.verify"),
        SignOptions::default(),
    )
    .expect("development signer");
    let signed = signer.sign(&tiny_zip()).expect("signed HAP");
    let verified = ApplicationVerifier::new(&signed)
        .verify(InputFormat::Zip)
        .expect("verify signed HAP");

    assert_eq!(verified.format, InputFormat::Zip);
    assert_eq!(verified.algorithm, Some(SigningAlgorithm::EcdsaSha256));
    assert_eq!(verified.signing_block_version, Some(3));
    assert!(verified.profile.is_some());
    assert!(!verified.certificates.is_empty());
}

#[test]
fn sha384_with_ecdsa_signs_and_verifies_all_hap_digest_layers() {
    let material = DevelopmentMaterialBuilder::new(development_profile("com.example.sha384"))
        .build()
        .expect("development material")
        .with_algorithm(SigningAlgorithm::EcdsaSha384);
    let signed = HapSigner::new(material, SignOptions::default())
        .sign(&tiny_zip())
        .expect("SHA-384 ECDSA HAP");
    let verified = ApplicationVerifier::new(&signed)
        .verify(InputFormat::Zip)
        .expect("verify SHA-384 ECDSA HAP");

    assert_eq!(verified.algorithm, Some(SigningAlgorithm::EcdsaSha384));
}

#[test]
fn sign_profile_and_verify_profile_use_attached_cms() {
    let fixture = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/test.p12"
    ))
    .expect("read RSA PKCS#12 fixture");
    let key = SigningKey::from_pkcs12(&fixture, "test123", "1", "test123")
        .expect("load profile signing key");
    let profile = br#"{"type":"debug","bundle-info":{"bundle-name":"com.example.profile"}}"#;
    let signed = ProfileSigner::new(key, SigningAlgorithm::RsaPssSha384)
        .sign(profile)
        .expect("sign profile");
    let verified = ProfileVerifier::verify(&signed).expect("verify profile");

    assert_eq!(verified.content, profile);
    assert_eq!(verified.algorithm, SigningAlgorithm::RsaPssSha384);
    assert!(!verified.certificates.is_empty());
}

#[test]
fn unsigned_profile_property_and_proof_blocks_follow_official_digest_order() {
    let fixture = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/test.p12"
    ))
    .expect("read RSA PKCS#12 fixture");
    let key =
        SigningKey::from_pkcs12(&fixture, "test123", "1", "test123").expect("load RSA fixture");
    let certificate_chain = key.cert_chain.concat();
    let signed_development_profile =
        DevelopmentMaterialBuilder::new(development_profile("com.example.raw"))
            .build()
            .expect("build profile with official required fields")
            .signed_profile()
            .to_vec();
    let raw_profile = ProfileVerifier::verify(&signed_development_profile)
        .expect("extract unsigned development profile")
        .content;
    let material = SigningMaterial::from_pkcs12(Pkcs12Material {
        pkcs12: &fixture,
        store_password: "test123",
        key_alias: "1",
        key_password: "test123",
        app_certificate_chain: &certificate_chain,
        signed_profile: raw_profile.clone(),
        algorithm: SigningAlgorithm::RsaPssSha256,
    })
    .expect("load raw-profile material")
    .with_unsigned_profile()
    .expect("mark profile unsigned")
    .with_property(b"upstream-property".to_vec())
    .expect("add property")
    .with_proof_of_rotation(b"upstream-proof".to_vec())
    .expect("add proof");
    let signed = HapSigner::new(
        material,
        SignOptions {
            compatible_version: 9,
            code_signing: false,
        },
    )
    .sign(&tiny_zip())
    .expect("sign raw-profile HAP");
    let verified = ApplicationVerifier::new(&signed)
        .verify(InputFormat::Zip)
        .expect("verify raw-profile HAP");

    assert_eq!(verified.profile.as_deref(), Some(raw_profile.as_slice()));
    assert_eq!(
        verified.proof_of_rotation.as_deref(),
        Some(b"upstream-proof".as_slice())
    );
    assert_eq!(verified.properties, [b"upstream-property".to_vec()]);
}

#[test]
fn external_signer_is_injected_across_hap_and_code_signing_cms_layers() {
    use rsa::pkcs8::DecodePrivateKey;

    let fixture = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/test.p12"
    ))
    .expect("read RSA PKCS#12 fixture");
    let source = SigningKey::from_pkcs12(&fixture, "test123", "1", "test123")
        .expect("load remote fixture key");
    let remote = Arc::new(TestExternalSigner {
        private_key: rsa::RsaPrivateKey::from_pkcs8_der(&source.private_key_der)
            .expect("parse remote RSA key"),
        certificates: source.cert_chain.clone(),
        signing: std::sync::atomic::AtomicBool::new(false),
    });
    let profile = DevelopmentMaterialBuilder::new(development_profile("com.example.remote"))
        .build()
        .expect("development profile")
        .signed_profile()
        .to_vec();
    let material =
        SigningMaterial::from_external(remote, profile, true, SigningAlgorithm::RsaPssSha256)
            .expect("external signing material");
    let first_elf = elf64_with_executable_segment(0x11);
    let second_elf = elf64_with_executable_segment(0x22);
    let signed = HapSigner::new(material, SignOptions::default())
        .sign(&stored_zip(&[
            ("module.json", b"{}"),
            ("libs/arm64-v8a/libfirst.so", &first_elf),
            ("libs/arm64-v8a/libsecond.so", &second_elf),
        ]))
        .expect("external sign HAP");
    let verified = ApplicationVerifier::new(&signed)
        .verify(InputFormat::Zip)
        .expect("verify externally signed HAP");

    assert_eq!(verified.algorithm, Some(SigningAlgorithm::RsaPssSha256));
}

#[test]
fn application_signing_rejects_a_profile_without_the_official_embedded_certificate() {
    let fixture = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/test.p12"
    ))
    .expect("read RSA PKCS#12 fixture");
    let key =
        SigningKey::from_pkcs12(&fixture, "test123", "1", "test123").expect("load RSA fixture");
    let material = SigningMaterial::from_pkcs12(Pkcs12Material {
        pkcs12: &fixture,
        store_password: "test123",
        key_alias: "1",
        key_password: "test123",
        app_certificate_chain: &key.cert_chain.concat(),
        signed_profile: br#"{"type":"debug","bundle-info":{}}"#.to_vec(),
        algorithm: SigningAlgorithm::RsaPssSha256,
    })
    .expect("construct unsigned profile material")
    .with_unsigned_profile()
    .expect("mark profile unsigned");

    assert!(matches!(
        HapSigner::new(
            material,
            SignOptions {
                compatible_version: 9,
                code_signing: false,
            },
        )
        .sign(&tiny_zip()),
        Err(SignError::Config(message)) if message.contains("development-certificate")
    ));
}

#[test]
fn elf_input_is_signed_and_verified_with_fsverity_code_signing() {
    let material = DevelopmentMaterialBuilder::new(development_profile("com.example.elf"))
        .build()
        .expect("development material");
    let signer = HapSigner::new(material, SignOptions::default());
    let unsigned = b"\x7fELF\x02\x01\x01\0fixture";
    let signed = signer
        .sign_application(unsigned, InputFormat::Elf)
        .expect("sign ELF");
    let verified = ApplicationVerifier::new(&signed)
        .verify(InputFormat::Elf)
        .expect("verify ELF");

    assert_eq!(verified.format, InputFormat::Elf);
    assert_eq!(verified.algorithm, Some(SigningAlgorithm::EcdsaSha256));
    assert!(verified.profile.is_some());
}

#[test]
fn elf_input_supports_the_official_profileless_code_signing_mode() {
    let fixture = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/test.p12"
    ))
    .expect("read RSA PKCS#12 fixture");
    let key = SigningKey::from_pkcs12(&fixture, "test123", "1", "test123")
        .expect("load profileless ELF key");
    let material = SigningMaterial::without_profile(key, SigningAlgorithm::RsaPssSha256);

    let signed = HapSigner::new(material, SignOptions::default())
        .sign_application(b"\x7fELF\x02\x01\x01\0profileless", InputFormat::Elf)
        .expect("sign profileless ELF");
    let verified = ApplicationVerifier::new(&signed)
        .verify(InputFormat::Elf)
        .expect("verify profileless ELF");

    assert!(verified.profile.is_none());
    assert!(verified.certificates.is_empty());
}

#[test]
fn bin_input_uses_official_big_endian_blocks_and_sign_head() {
    let material = DevelopmentMaterialBuilder::new(development_profile("com.example.bin"))
        .build()
        .expect("development material");
    let signer = HapSigner::new(material, SignOptions::default());
    let unsigned = b"binary-fixture";
    let signed = signer
        .sign_application(unsigned, InputFormat::Bin)
        .expect("sign BIN");

    assert_eq!(&signed[..unsigned.len()], unsigned);
    assert_eq!(
        &signed[signed.len() - 32..signed.len() - 16],
        b"hw signed app   "
    );
    assert_eq!(&signed[signed.len() - 16..signed.len() - 12], b"1000");
    assert_eq!(
        u32::from_be_bytes(
            signed[signed.len() - 8..signed.len() - 4]
                .try_into()
                .unwrap()
        ),
        2
    );
}

#[test]
fn verify_app_reports_the_official_bin_verifier_gap() {
    assert!(matches!(
        ApplicationVerifier::new(b"hw signed app   ").verify(InputFormat::Bin),
        Err(SignError::UnsupportedOperation(message)) if message.contains("VerifyElf")
    ));
}

#[test]
fn pkcs12_key_alias_is_enforced() {
    let fixture = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/test.p12"
    ))
    .expect("read RSA PKCS#12 fixture");

    assert!(matches!(
        SigningKey::from_pkcs12(&fixture, "test123", "missing", "test123"),
        Err(SignError::KeyAliasNotFound { alias, available })
            if alias == "missing" && available == ["1"]
    ));
}

#[test]
fn jks_private_key_entries_are_loaded_with_distinct_store_and_key_passwords() {
    let fixture = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/test.p12"
    ))
    .expect("read RSA PKCS#12 fixture");
    let source =
        SigningKey::from_pkcs12(&fixture, "test123", "1", "test123").expect("load source key");
    let mut store = jks::KeyStore::new();
    store
        .set_private_key_entry(
            "release",
            jks::PrivateKeyEntry {
                creation_time: std::time::SystemTime::UNIX_EPOCH,
                private_key: source.private_key_der.clone(),
                certificate_chain: source
                    .cert_chain
                    .iter()
                    .map(|certificate| jks::Certificate {
                        cert_type: "X509".to_owned(),
                        content: certificate.clone(),
                    })
                    .collect(),
            },
            b"key-password",
        )
        .expect("insert JKS private key");
    let mut jks_bytes = Vec::new();
    store
        .store(&mut jks_bytes, b"store-password")
        .expect("serialize JKS");

    let loaded = SigningKey::from_keystore(&jks_bytes, "store-password", "release", "key-password")
        .expect("auto-detect and load JKS");
    assert_eq!(loaded.private_key_der, source.private_key_der);
    assert_eq!(loaded.cert_chain, source.cert_chain);
}

#[test]
fn legacy_pkcs12_pbe_keystores_are_loaded_by_alias() {
    let fixture = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/test.p12"
    ))
    .expect("read source PKCS#12 fixture");
    let source =
        SigningKey::from_pkcs12(&fixture, "test123", "1", "test123").expect("load source key");
    let legacy = p12::PFX::new(
        &source.cert_chain[0],
        &source.private_key_der,
        None,
        "legacy-password",
        "legacy-alias",
    )
    .expect("construct legacy PKCS#12")
    .to_der();

    let loaded = SigningKey::from_pkcs12(
        &legacy,
        "legacy-password",
        "legacy-alias",
        "legacy-password",
    )
    .expect("load legacy PKCS#12");
    assert_eq!(loaded.private_key_der, source.private_key_der);
    assert_eq!(loaded.cert_chain, [source.cert_chain[0].clone()]);
}

#[test]
fn hnp_elf_entries_are_code_signed_with_official_archive_names() {
    let signer = DevelopmentSigner::new(
        development_profile("com.example.hnp"),
        SignOptions::default(),
    )
    .expect("development signer");
    let hnp = stored_zip(&[("bin/tool", b"\x7fELF\x02\x01\x01\0payload")]);
    let module = br#"{"module":{"hnpPackages":[{"package":"sample.hnp","type":"private"}]}}"#;
    let unsigned = stored_zip(&[("module.json", module), ("hnp/arm64-v8a/sample.hnp", &hnp)]);
    let signed = signer.sign(&unsigned).expect("sign HNP ELF entry");

    assert!(signed
        .windows(b"hnp/arm64-v8a/sample.hnp!/bin/tool".len())
        .any(|window| window == b"hnp/arm64-v8a/sample.hnp!/bin/tool"));
    ApplicationVerifier::new(&signed)
        .verify(InputFormat::Zip)
        .expect("verify HNP ELF code signature");
}

#[test]
fn undeclared_hnp_is_rejected_like_official_code_signing() {
    let signer = DevelopmentSigner::new(
        development_profile("com.example.hnp.missing"),
        SignOptions::default(),
    )
    .expect("development signer");
    let hnp = stored_zip(&[("bin/tool", b"\x7fELFpayload")]);
    let unsigned = stored_zip(&[
        ("module.json", br#"{"module":{}}"#),
        ("hnp/arm64-v8a/sample.hnp", &hnp),
    ]);

    assert!(matches!(
        signer.sign(&unsigned),
        Err(SignError::HnpNotDeclared(name)) if name == "hnp/arm64-v8a/sample.hnp"
    ));
}

#[test]
fn file_signing_is_streamed_and_supports_in_place_replacement() {
    let temp = tempfile::tempdir().expect("tempdir");
    let input = temp.path().join("entry-default-unsigned.hap");
    let output = temp.path().join("nested").join("entry-default-signed.hap");
    std::fs::write(&input, tiny_zip()).expect("write unsigned HAP");
    let signer = DevelopmentSigner::new(
        development_profile("com.example.file"),
        SignOptions::default(),
    )
    .expect("development signer");

    signer
        .sign_file(&input, &output)
        .expect("stream signed HAP");
    let signed = std::fs::read(&output).expect("read signed HAP");
    assert_eq!(
        SigningBlockInspector::new(&signed)
            .inspect()
            .expect("inspect file output")
            .version,
        3
    );
    signer
        .sign_file(&input, &input)
        .expect("official SignProvider supports overlapping input/output");
    let in_place = std::fs::read(&input).expect("read in-place signed HAP");
    SigningBlockInspector::new(&in_place)
        .inspect()
        .expect("inspect in-place signed output");
}

#[test]
fn file_code_signing_streams_a_multi_megabyte_abc_prefix() {
    let temp = tempfile::tempdir().expect("tempdir");
    let input = temp.path().join("large-unsigned.hap");
    let output = temp.path().join("large-signed.hap");
    let abc = vec![0xA5; 2 * 1024 * 1024 + 137];
    std::fs::write(
        &input,
        stored_zip(&[("ets/modules.abc", &abc), ("module.json", b"{}")]),
    )
    .expect("write large unsigned HAP");
    let signer = DevelopmentSigner::new(
        development_profile("com.example.large"),
        SignOptions::default(),
    )
    .expect("development signer");

    signer
        .sign_file(&input, &output)
        .expect("stream large ABC HAP");
    let signed = std::fs::read(output).expect("read large signed HAP");
    let info = SigningBlockInspector::new(&signed)
        .inspect()
        .expect("inspect large signed HAP");
    assert_eq!(info.blocks[0].kind(), SigningBlockType::Property);
}

fn development_profile(bundle_name: &str) -> DevelopmentProfileOptions {
    DevelopmentProfileOptions {
        bundle_name: bundle_name.to_owned(),
        ..DevelopmentProfileOptions::default()
    }
}

fn tiny_zip() -> Vec<u8> {
    tiny_zip_named("module.json", b"{}")
}

fn tiny_zip_named(name: &str, content: &[u8]) -> Vec<u8> {
    stored_zip(&[(name, content)])
}

fn elf64_with_executable_segment(fill: u8) -> Vec<u8> {
    let mut elf = vec![fill; 0x2100];
    elf[..64].fill(0);
    elf[0..4].copy_from_slice(b"\x7fELF");
    elf[4] = 2;
    elf[5] = 1;
    elf[6] = 1;
    elf[16..18].copy_from_slice(&3u16.to_le_bytes());
    elf[18..20].copy_from_slice(&183u16.to_le_bytes());
    elf[20..24].copy_from_slice(&1u32.to_le_bytes());
    elf[32..40].copy_from_slice(&64u64.to_le_bytes());
    elf[52..54].copy_from_slice(&64u16.to_le_bytes());
    elf[54..56].copy_from_slice(&56u16.to_le_bytes());
    elf[56..58].copy_from_slice(&1u16.to_le_bytes());

    let program_header = 64;
    elf[program_header..program_header + 4].copy_from_slice(&1u32.to_le_bytes());
    elf[program_header + 4..program_header + 8].copy_from_slice(&5u32.to_le_bytes());
    elf[program_header + 8..program_header + 16].copy_from_slice(&0x1000u64.to_le_bytes());
    elf[program_header + 16..program_header + 24].copy_from_slice(&0x1000u64.to_le_bytes());
    elf[program_header + 24..program_header + 32].copy_from_slice(&0x1000u64.to_le_bytes());
    elf[program_header + 32..program_header + 40].copy_from_slice(&0x1100u64.to_le_bytes());
    elf[program_header + 40..program_header + 48].copy_from_slice(&0x1100u64.to_le_bytes());
    elf[program_header + 48..program_header + 56].copy_from_slice(&0x1000u64.to_le_bytes());
    elf
}

fn stored_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut zip = Vec::new();
    let mut central_directory = Vec::new();
    for (name, content) in entries {
        let name = name.as_bytes();
        let crc = crc32fast::hash(content);
        let local_offset = zip.len() as u32;
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

        central_directory.extend_from_slice(b"PK\x01\x02");
        central_directory.extend_from_slice(&20u16.to_le_bytes());
        central_directory.extend_from_slice(&20u16.to_le_bytes());
        central_directory.extend_from_slice(&0u16.to_le_bytes());
        central_directory.extend_from_slice(&0u16.to_le_bytes());
        central_directory.extend_from_slice(&0u16.to_le_bytes());
        central_directory.extend_from_slice(&0u16.to_le_bytes());
        central_directory.extend_from_slice(&crc.to_le_bytes());
        central_directory.extend_from_slice(&(content.len() as u32).to_le_bytes());
        central_directory.extend_from_slice(&(content.len() as u32).to_le_bytes());
        central_directory.extend_from_slice(&(name.len() as u16).to_le_bytes());
        central_directory.extend_from_slice(&0u16.to_le_bytes());
        central_directory.extend_from_slice(&0u16.to_le_bytes());
        central_directory.extend_from_slice(&0u16.to_le_bytes());
        central_directory.extend_from_slice(&0u16.to_le_bytes());
        central_directory.extend_from_slice(&0u32.to_le_bytes());
        central_directory.extend_from_slice(&local_offset.to_le_bytes());
        central_directory.extend_from_slice(name);
    }
    let central_directory_start = zip.len();
    let central_directory_size = central_directory.len();
    zip.extend_from_slice(&central_directory);
    zip.extend_from_slice(b"PK\x05\x06");
    zip.extend_from_slice(&0u16.to_le_bytes());
    zip.extend_from_slice(&0u16.to_le_bytes());
    zip.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    zip.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    zip.extend_from_slice(&(central_directory_size as u32).to_le_bytes());
    zip.extend_from_slice(&(central_directory_start as u32).to_le_bytes());
    zip.extend_from_slice(&0u16.to_le_bytes());
    zip
}

struct TestExternalSigner {
    private_key: rsa::RsaPrivateKey,
    certificates: Vec<Vec<u8>>,
    signing: std::sync::atomic::AtomicBool,
}

impl ExternalSigner for TestExternalSigner {
    fn sign(
        &self,
        authenticated_attributes_der: &[u8],
        algorithm: SigningAlgorithm,
    ) -> Result<Vec<u8>, SignError> {
        use signature::{RandomizedSigner, SignatureEncoding};
        use std::sync::atomic::Ordering;

        if algorithm != SigningAlgorithm::RsaPssSha256 {
            return Err(SignError::UnsupportedAlgorithm(
                algorithm.hvigor_name().to_owned(),
            ));
        }
        if self.signing.swap(true, Ordering::AcqRel) {
            return Err(SignError::SigningFailed(
                "ExternalSigner was invoked concurrently".to_owned(),
            ));
        }
        for _ in 0..64 {
            std::thread::yield_now();
        }
        let signature = rsa::pss::SigningKey::<sha2::Sha256>::new(self.private_key.clone())
            .sign_with_rng(&mut rand::rngs::OsRng, authenticated_attributes_der)
            .to_vec();
        self.signing.store(false, Ordering::Release);
        Ok(signature)
    }

    fn certificates(&self) -> Result<Vec<Vec<u8>>, SignError> {
        Ok(self.certificates.clone())
    }
}
