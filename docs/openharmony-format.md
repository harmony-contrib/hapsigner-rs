# OpenHarmony format alignment

The implementation follows both sides of OpenHarmony's HAP signature contract,
not only a sample signed file.

Source revisions used for implementation, differential verification, and QEMU
validation:

- `developtools_hapsigner` at `9da724ff3ab21ff210085e8386fba62fec167368`
- `security_appverify` at `78d4b2c274ac33f211217d1cd4980d2faf469c64`

The corresponding upstream repositories are:

- <https://gitee.com/openharmony/developtools_hapsigner>
- <https://gitee.com/openharmony/security_appverify>

The caller-facing material model was also compared with DevEco Studio
6.1.1.280's readable Hvigor sources. In
`tasks/sign/command-builder-impl/hap-sign-command-builder.ts`,
`HapSignCommandBuilder.initCommandParams` invokes `sign-app -mode localSign`
and forwards `keystoreFile`, store password, `keyAlias`, key password,
`signAlg`, `profileFile`, `profileSigned`, `appCertFile`, input, and output. The
tool path comes from the selected SDK toolchains component's
`hap-sign-tool.jar`, not a fixed installation directory. `SigningMaterial` and
`KeystoreMaterial` model those material inputs without copying Hvigor's
project or SDK discovery into the signing library.

`SignProvider.VALID_SIGN_ALG_NAME` accepts SHA-256/384/512 with ECDSA and
RSA-PSS (`RSA/PSS` and `RSAandMGF1` aliases). `KeyStoreHelper` accepts JKS and
PKCS#12. The Rust implementation covers that matrix, including JKS store/key
password separation and legacy PKCS#12 PBE used by the official fixtures.

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

The `block_length` excludes its own four-byte field. Algorithm identifiers are
`0x201`/`0x202`/`0x203` for ECDSA SHA-256/384/512 and
`0x101`/`0x102`/`0x103` for RSA-PSS SHA-256/384/512.

## HAP content digest

`HapSigningBlockUtils::ComputeDigestsForEachChunk` hashes the three ZIP
sections in 1 MiB chunks. Every chunk is prefixed by `0xa5` and its
little-endian length. The list starts with `0x5a` and the chunk count. The final
algorithm-specific input is that list followed by each optional block value in
signing-block order. Property, profile, and Proof-of-Rotation files are loaded
verbatim. `profileSigned=0` stores raw JSON; the official tool has no operation
that synthesizes a Proof-of-Rotation block.

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
library and HNP code-sign records are emitted in archive order. Signing
callbacks are deliberately sequential because the official `ISigner` provider
is allowed to be stateful; parallel callback invocation would not preserve its
observable behavior.

File-backed ABC/page-info and fs-verity inputs are fed incrementally. Merkle
levels are retained only when the HAP code-sign block must serialize them;
native-library root calculation keeps only the active levels. ELF segment
discovery decodes one native library at a time because the object parser needs
random access to that entry.

For HNP code signing, `module.json#module.hnpPackages` declares package names
and public/private type. Only nested ELF entries are signed. Records use the
official `hnp/<abi>/<package>.hnp!/<entry>` name. Debug packages use
`DEBUG_LIB_ID`; public release HNPs use `SHARED_LIB_ID`; private release HNPs
use the profile app identifier.

Standalone ELF signing appends the little-endian `elf sign block` layout and
fs-verity code signature. A signed profile is optional for ELF, but an unsigned
profile is explicitly rejected. BIN signing appends the big-endian
`hw signed app` layout. Official `verify-app` currently routes BIN to
`VerifyElf` and rejects that header, so the Rust verifier exposes the same gap
as a typed unsupported result rather than claiming successful verification.

Application verification checks CMS signatures, digest pairs, ZIP/ELF
fs-verity data, profile JSON/CMS, and code-sign owner IDs. Profile verification
also validates the certificate chain at the CMS signing time. App signing
requires the same debug/release embedded certificate and non-empty CN fields as
`SignProvider.checkProfileValid`; it does not introduce ACL-level policy.

Remote signing follows `ISigner`: an injected provider signs authenticated
attributes and returns its certificate chain and optional CRLs. Upstream does
not define a transport, its default `RemoteSigner` throws `Not implement yet`,
and `remoteResign` returns an unimplemented result. These remain explicit typed
boundaries rather than a made-up protocol.

The implementation is regression-tested against these layouts and the
development-signing adapter was accepted by the `v20260809` QEMU image
(`OpenHarmony 7.0.0.32`) for both a normal HAP and a HAP declaring a VPN
extension. JKS/PKCS#12 ECDSA/RSA material injection, V2/V3 selection, streaming
and in-place file output, HNP/ELF/BIN layouts, external signing, profile
workflows, and typed upstream-unimplemented boundaries have dedicated
regression tests.

The SHA-384 ECDSA differential suite signs HAP, ELF, BIN, and profile artifacts
with Rust and official `hap-sign-tool.jar`, then verifies the Rust HAP/ELF and
profile with the official tool and the official HAP/ELF with Rust. The binary
headers, block structure, digest algorithm, exported profile, and code-sign
verification results match; signature bytes and signing time remain naturally
non-deterministic.
