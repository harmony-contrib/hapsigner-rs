# hapsigner-rs

`hapsigner` is a Java-free OpenHarmony HAP/HSP signing library with a thin
`hap-sign` development CLI. The core accepts material selected by the caller;
it does not discover Hvigor projects, read `build-profile.json5`, decrypt
DevEco secrets, or assume an SDK/install path.

The signing pipeline implements HAP signing block V2/V3, CMS/PKCS#7,
`SHA256withECDSA`, `SHA256withRSA/PSS`, ZIP alignment, page-info generation,
and optional fs-verity code signing for ABC/native-library entries. File
signing streams archive payloads and fs-verity inputs, then atomically persists
the output.

## Library

Callers that already resolved build-profile values can inject the same inputs
Hvigor passes to `hap-sign-tool.jar`:

```rust,no_run
use std::{fs, path::Path};
use hapsigner::{
    HapSigner, Pkcs12Material, SignOptions, SigningAlgorithm, SigningMaterial,
};

fn sign() -> Result<(), Box<dyn std::error::Error>> {
    let keystore = fs::read("signing/debug.p12")?;
    let app_cert = fs::read("signing/debug-app-cert.pem")?;
    let signed_profile = fs::read("signing/debug-profile.p7b")?;
    let material = SigningMaterial::from_pkcs12(Pkcs12Material {
        pkcs12: &keystore,
        store_password: "store password",
        key_alias: "debugKey",
        key_password: "key password",
        app_certificate_chain: &app_cert,
        signed_profile,
        algorithm: SigningAlgorithm::EcdsaSha256,
    })?;

    HapSigner::new(material, SignOptions::default()).sign_file(
        Path::new("entry-default-unsigned.hap"),
        Path::new("entry-default-signed.hap"),
    )?;
    Ok(())
}
```

Use `SigningMaterial::from_der` when a build system or key provider already
owns PKCS#8 private-key DER and the DER certificate chain. Use
`FileSigningMaterial` only as a convenience after the caller has resolved all
paths and plaintext passwords. PKCS#12 aliases are matched against
`friendlyName`; unnamed keys receive the Java-compatible numeric aliases
`1`, `2`, and so on.

Library-only consumers can disable the CLI and compile the embedded development
identity out of their artifact:

```toml
hapsigner = { version = "0.1", default-features = false }
```

`compatible_version < 8` emits the V2 signing block; version 8 or newer emits
V3. `SignOptions::default()` uses compatible version 9 and enables code
signing.

## CLI

Install from source:

```bash
cargo install --git https://github.com/harmony-contrib/hapsigner-rs --locked
```

The existing command signs with the embedded public development identity:

```bash
hap-sign sign entry-default-unsigned.hap \
  --bundle-name com.example.application
```

For caller-provided local-sign material, passwords are supplied through the
environment so they do not appear in the process arguments:

```bash
export HAPSIGNER_STORE_PASSWORD='store password'
export HAPSIGNER_KEY_PASSWORD='key password'

hap-sign sign-with-material entry-default-unsigned.hap \
  --keystore signing/debug.p12 \
  --profile signing/debug-profile.p7b \
  --certificate signing/debug-app-cert.pem \
  --key-alias debugKey \
  --sign-alg SHA256withECDSA
```

Inspect signing-block metadata and the embedded profile with:

```bash
hap-sign inspect entry-default-signed.hap
```

> [!WARNING]
> The development adapter's embedded OpenHarmony credentials are public test
> keys. They are only for QEMU and local development, never production,
> AppGallery, or private release signing.

## Compatibility boundary

- Supported archives are ZIP32 HAP/HSP files. ZIP64 is rejected.
- Existing HAP signing blocks are replaced.
- ELF segment discovery decodes one native library at a time; it never retains
  the complete archive, while ABC/page-info and fs-verity hashing are streamed.
- HNP entries are rejected with `SignError::UnsupportedHnpCodeSigning` when
  code signing is enabled; the library does not pretend to sign them.
- HAR archives, remote signing, project configuration discovery, and DevEco
  password-store decryption are intentionally outside this crate.

The observed OpenHarmony/Hvigor format contract is documented in
[`docs/openharmony-format.md`](docs/openharmony-format.md). The project is MIT
licensed; upstream OpenHarmony notices and development-asset provenance are in
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
