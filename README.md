# hapsigner-rs

`hap-sign` is a Java-free OpenHarmony HAP signer intended for local development and
the [`harmony-contrib/ohos-qemu`](https://github.com/harmony-contrib/ohos-qemu)
images. CMS/PKCS#7, X.509 parsing, ECDSA, and HAP chunk hashing are implemented
with pure Rust crates.

> [!WARNING]
> The embedded OpenHarmony development keys are public test keys. Packages signed
> by this tool are for OpenHarmony QEMU and local development only. Never use them
> for production, AppGallery, or private release signing.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/ohos-rs/hapsigner-rs/main/install.sh | bash
```

Or install from source:

```bash
cargo install --git https://github.com/ohos-rs/hapsigner-rs --locked
```

## Sign a HAP

```bash
hap-sign sign entry-default-unsigned.hap \
  --bundle-name com.example.application
```

The default output is `entry-default-unsigned-signed.hap`. To add ACLs required by
the application profile:

```bash
hap-sign sign entry-default-unsigned.hap \
  --bundle-name com.example.vpn \
  --acl ohos.permission.FILE_ACCESS_PERSIST \
  --output entry-default-signed.hap
```

Inspect the embedded profile:

```bash
hap-sign inspect entry-default-signed.hap
```

The default profile is for QEMU RD/developer images. For a non-QEMU debug
device, add its UDID with `--device-id <UDID>`; the option may be repeated.

The input must be a ZIP32 HAP produced by the OpenHarmony build tools. Signing an
already signed HAP replaces its HAP signing block.

## Why not rustls?

HAP signatures use CMS/PKCS#7 rather than TLS. `rustls` therefore is not directly
applicable. This project uses the corresponding pure Rust RustCrypto stack:
`cms`, `x509-cert`, `p256`, and `sha2`.

## License and signing assets

The project is MIT licensed. The embedded QEMU development certificates and
keys are derived from OpenHarmony's `developtools/hapsigner/dist/OpenHarmony.p12`
and certificate chains, which are distributed by OpenHarmony under Apache-2.0.
See `THIRD_PARTY_NOTICES.md`.

The format implementation is traced to specific OpenHarmony signer and verifier
sources in [`docs/openharmony-format.md`](docs/openharmony-format.md).
