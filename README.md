# hapsigner-rs

`hapsigner` is a Java-free OpenHarmony HAP/HSP signing library with a thin
`hap-sign` development CLI. The core accepts material selected by the caller;
it does not discover Hvigor projects, read `build-profile.json5`, decrypt
DevEco secrets, or assume an SDK/install path.

The signing pipeline implements HAP signing block V2/V3, CMS/PKCS#7, all
official SHA-256/384/512 ECDSA and RSA-PSS algorithm names, ZIP alignment,
page-info generation, and fs-verity code signing for ABC, native-library, HNP,
and standalone ELF inputs. It loads both JKS and modern or legacy PKCS#12
keystores. File signing streams archive payloads and fs-verity inputs, then
atomically replaces the destination, including when input and output are the
same path.

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
hapsigner = { version = "0.2", default-features = false }
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

hap-sign sign-app entry-default-unsigned.hap \
  --keystore signing/debug.p12 \
  --profile signing/debug-profile.p7b \
  --certificate signing/debug-app-cert.pem \
  --key-alias debugKey \
  --sign-alg SHA256withECDSA
```

`sign-app --in-form` accepts `zip`, `elf`, and `bin`; `--profile-signed 0`
embeds raw profile JSON for ZIP/BIN input. `--proof` and `--property` load the
official optional block bytes verbatim. The upstream tool does not generate a
Proof-of-Rotation structure, so neither does this crate.

The application and provisioning-profile verification/signing workflows are
available as first-class commands:

```bash
hap-sign verify-app entry-default-signed.hap \
  --out-cert-chain app-cert-chain.pem \
  --out-profile profile.p7b

hap-sign sign-profile profile.json \
  --output profile.p7b \
  --keystore signing/profile.jks \
  --certificate signing/profile-cert-chain.pem \
  --key-alias profileKey

hap-sign verify-profile profile.p7b --output profile-verification.json
```

Remote signing follows the official `ISigner` boundary: library consumers
inject an `ExternalSigner` which returns signatures, certificates, and optional
CRLs. Official hapsigner defines no network protocol, its default
`RemoteSigner` throws `Not implement yet`, and `remoteResign` is also
unimplemented. The CLI therefore reports those same unsupported boundaries
instead of inventing a transport; the library API provides the usable injected
signer path.

Inspect signing-block metadata and the embedded profile with:

```bash
hap-sign inspect entry-default-signed.hap
```

## Certificate and key generation

The six material-producing commands of the official tool are implemented here
too, so a complete signing identity can be bootstrapped without a Java
toolchain:

```bash
export HAPSIGNER_STORE_PASSWORD='123456'
export HAPSIGNER_KEY_PASSWORD='123456'

# A root CA. If the keystore does not exist, the key and the file are created.
hap-sign generate-ca \
  --key-alias root --key-alg ECC --key-size NIST-P-256 \
  --subject "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Root CA" \
  --keystore root.p12 --sign-alg SHA256withECDSA \
  --basic-constraints-path-len 1 --out-file root-ca.pem

# A subordinate CA, signed by the root.
hap-sign generate-keypair \
  --key-alias sub --key-alg ECC --key-size NIST-P-256 --keystore sub.p12

hap-sign generate-ca \
  --key-alias sub --key-alg ECC --key-size NIST-P-256 \
  --subject "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application CA" \
  --issuer "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Root CA" \
  --issuer-key-alias root --issuer-keystore root.p12 \
  --keystore sub.p12 --out-file sub-ca.pem

# An application certificate, emitted as the official leaf/sub-CA/root chain.
hap-sign generate-keypair \
  --key-alias app --key-alg ECC --key-size NIST-P-256 --keystore app.p12

hap-sign generate-app-cert \
  --key-alias app \
  --subject "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release" \
  --issuer "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application CA" \
  --issuer-key-alias sub --issuer-keystore sub.p12 \
  --keystore app.p12 --out-form certChain \
  --sub-ca-cert-file sub-ca.pem --root-ca-cert-file root-ca.pem \
  --out-file app-cert-chain.pem
```

`generate-profile-cert` takes the same options and stamps the profile signing
capability instead of the application one. `generate-cert` issues a certificate
with explicit `--key-usage`, `--ext-key-usage`, and `--basic-constraints-*`
control, and `generate-csr` emits the legacy
`-----BEGIN NEW CERTIFICATE REQUEST-----` PEM.

Every flag has the official camelCase spelling as a visible alias
(`--keyAlias`, `--keystoreFile`, `--outForm`), so a command copied from the
upstream documentation only needs a second leading dash.

Passwords are read from the flag first and from the environment second:
`HAPSIGNER_STORE_PASSWORD` and `HAPSIGNER_KEY_PASSWORD`, plus
`HAPSIGNER_ISSUER_STORE_PASSWORD` and `HAPSIGNER_ISSUER_KEY_PASSWORD` for a
separate `--issuer-keystore`. When the issuer keystore is the caller's own, both
fall back to the primary passwords, so a shared password is supplied once. An
absent key password means an empty one, matching the official tool.

The same capability is available as a library. `generate_key_pair`,
`parse_distinguished_name`, `build_certificate`, `write_keystore`, and the
`cert_tools` functions accept caller-resolved inputs and return bytes, with no
filesystem or environment access.

> [!WARNING]
> The development adapter's embedded OpenHarmony credentials are public test
> keys. They are only for QEMU and local development, never production,
> AppGallery, or private release signing.

## Compatibility boundary

- ZIP application input uses ZIP32; ZIP64 is rejected. Standalone ELF and BIN
  input use their official binary signing layouts.
- Existing HAP signing blocks are replaced.
- ELF segment discovery decodes one native library at a time; it never retains
  the complete archive, while ABC/page-info and fs-verity hashing are streamed.
- ELF files inside declared `module.hnpPackages` are code-signed with the
  official `outer.hnp!/inner.so` record name and debug/private/public owner-ID
  rules.
- `verify-app` deliberately reports a typed unsupported result for BIN because
  official 6.1.1.280 routes BIN verification through `VerifyElf` and rejects
  its own `hw signed app` header.
- `generate-*` never rewrites a populated keystore. The official tool merges a
  new entry into an existing file; this tool refuses to replace one without
  `--force`, because it does not merge entries. Run `generate-keypair` per
  alias instead. The same applies to `generate-ca`, which only creates a
  keystore when none exists yet.
- Passwords never have to appear in the process arguments; the official
  `-keystorePwd`/`-keyPwd` flags are accepted alongside `HAPSIGNER_*`.
- `generate-ca` rejects `--issuer` without `--issuer-key-alias`, and
  `generate-app-cert`/`generate-profile-cert` accept `.pem` as well as `.cer`
  for the CA certificate files. Both relax cases where the official tool would
  either emit a self-inconsistent self-signed certificate or reject a
  correctly-named file.
- HAR project orchestration, project configuration discovery, remote transport,
  and DevEco password-store decryption are intentionally outside this crate.

The observed OpenHarmony/Hvigor format contract is documented in
[`docs/openharmony-format.md`](docs/openharmony-format.md). The project is MIT
licensed; upstream OpenHarmony notices and development-asset provenance are in
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
