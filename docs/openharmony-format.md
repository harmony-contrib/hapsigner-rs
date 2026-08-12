# OpenHarmony format alignment

The implementation follows both sides of OpenHarmony's HAP signature contract,
not only a sample signed file.

Source revisions used for the implementation and QEMU validation on 2026-08-09:

- `developtools_hapsigner` at `6e46665d418d0dfedd6ba460172271565020f212`
- `security_appverify` at `78d4b2c274ac33f211217d1cd4980d2faf469c64`

The corresponding upstream repositories are:

- <https://gitee.com/openharmony/developtools_hapsigner>
- <https://gitee.com/openharmony/security_appverify>

The caller-facing material model was also compared with DevEco Studio
6.1.1.280's readable Hvigor sources. In
`tasks/sign/command-builder-impl/hap-sign-command-builder.ts`,
`HapSignCommandBuilder.initCommandParams` invokes `sign-app -mode localSign`
and forwards `keystoreFile`, store password, `keyAlias`, key password,
`signAlg`, signed `profileFile`, `appCertFile`, input, and output. The tool path
comes from the selected SDK toolchains component's `hap-sign-tool.jar`, not a
fixed installation directory. `SigningMaterial` and `Pkcs12Material` model
those material inputs without copying Hvigor's project or SDK discovery into
the signing library.

## CMS/PKCS#7

`BcPkcs7Generator.generateSignedData` and the C++ `PKCS7Data::Pkcs7Sign`
produce attached SignedData. Both the provisioning profile and the HAP digest
message are stored in `encapContentInfo.eContent`. Each `SignerInfo` uses the
leaf certificate issuer and serial number and contains the PKCS#9
`contentType`, `signingTime`, and `messageDigest` signed attributes.

The device verifier's `HapVerifyOpensslUtils::ParsePkcs7Package` requires the
attached octet string, and `VerifyCertChain` uses `signingTime` when checking
the certificate chain validity period.

## Digest message

`SignHap::EncodeListOfPairsToByteArray` and
`HapVerifyV2::GetDigestAndAlgorithm` define this little-endian layout:

```text
u32 version = 2
u32 block_count = 1
u32 block_length = 8 + digest_length
u32 algorithm = 0x201  # SHA-256 with ECDSA
u32 digest_length = 32
u8  digest[32]
```

The `block_length` excludes its own four-byte field. The algorithm identifier
is `0x201` for ECDSA P-256/SHA-256 and `0x101` for RSA-PSS/SHA-256.

## HAP content digest

`HapSigningBlockUtils::ComputeDigestsForEachChunk` hashes the three ZIP
sections in 1 MiB chunks. Every chunk is prefixed by `0xa5` and its little-endian
length. The list starts with `0x5a` and the chunk count. The final SHA-256 input
is that list followed by each optional block value in signing-block order. A
QEMU development signature contains the attached signed profile as its optional
block.

## Signing block

The signing block contains 12-byte little-endian type/length/offset entries,
their values, the block count, total size, magic, and version. Compatible
versions below 8 select V2 (`HAP Sig Block 42`, version 2); version 8 and newer
select V3 (`<hap sign block>`, version 3).

With code signing enabled, the block order is property `0x20000003`, profile
`0x20000002`, then main signature `0x20000000`. The property contains the
`0x30000001` code-sign block. With code signing disabled, only profile and main
signature are emitted.

## Archive preparation and code signing

Normal stored entries are aligned to 4 bytes; runnable `.abc` and `.so`
entries are aligned to 4096 bytes. The generated `.pages.info` bitmap and
fs-verity Merkle/sign-info structures follow the hapsigner layout. Native
library code-sign records are computed in parallel but restored to archive
order before serialization, keeping output deterministic.

File-backed ABC/page-info and fs-verity inputs are fed incrementally. Merkle
levels are retained only when the HAP code-sign block must serialize them;
native-library root calculation keeps only the active levels. ELF segment
discovery decodes one native library at a time because the object parser needs
random access to that entry.

HNP code signing is a separate upstream path and is not implemented here.
Archives containing `hnp/*.hnp` fail with a typed error when code signing is
requested.

The implementation is regression-tested against these layouts and the
development-signing adapter was accepted by the `v20260809` QEMU image
(`OpenHarmony 7.0.0.32`) for both a normal HAP and a HAP declaring a VPN
extension. PKCS#12 ECDSA/RSA material injection, V2/V3 selection, streaming
file output, and typed unsupported boundaries have dedicated regression tests.
