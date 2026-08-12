use std::str::FromStr;

use hapsigner::{
    DevelopmentMaterialBuilder, DevelopmentProfileOptions, DevelopmentSigner, HapSigner,
    Pkcs12Material, SignError, SignOptions, SigningAlgorithm, SigningBlockInspector,
    SigningBlockType, SigningKey, SigningMaterial,
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
    assert!(matches!(
        SigningAlgorithm::from_str("SHA1withRSA"),
        Err(SignError::UnsupportedAlgorithm(_))
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
fn hnp_code_signing_is_rejected_instead_of_silently_omitted() {
    let signer = DevelopmentSigner::new(
        development_profile("com.example.hnp"),
        SignOptions::default(),
    )
    .expect("development signer");

    assert!(matches!(
        signer.sign(&tiny_zip_named("hnp/sample.hnp", b"hnp")),
        Err(SignError::UnsupportedHnpCodeSigning)
    ));
}

#[test]
fn file_signing_is_streamed_and_rejects_in_place_overwrite() {
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
    assert!(matches!(
        signer.sign_file(&input, &input),
        Err(SignError::InputOutputSame(path)) if path == input
    ));
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
