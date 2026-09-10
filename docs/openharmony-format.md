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

## Certificate construction

The `generate-*` commands reproduce `CertBuilder`, `CertTools`, and
`SignToolServiceImpl` rather than textbook PKI, so their output is
interchangeable with the official tool. Extensions are emitted in the order
`CertBuilder` adds them, which is the order the official certificates carry:

| Position | Extension | Criticality |
| --- | --- | --- |
| 1 | `subjectKeyIdentifier` | never (added in the `CertBuilder` constructor) |
| 2 | `authorityKeyIdentifier` | never; **only** for a subordinate CA |
| 3 | `basicConstraints` | per level (see below) |
| 4 | `keyUsage` | per command |
| 5 | `extendedKeyUsage` | per command; omitted entirely by `generate-ca` |
| 6 | signing capability `1.3.6.1.4.1.2011.2.376.1.3` | never; `generate-app-cert` and `generate-profile-cert` only |

`withAuthorityKeyIdentifier` is a no-op for every `CertLevel` except `SUB_CA`,
so root CA certificates, `generate-cert` output, and end-entity certificates
carry no authority key identifier at all; the key identifier is the SHA-1 of
the subject public key bits (RFC 5280 method 1), and a sub CA's is taken from
the *issuer*.

The signing-capability extension value is the raw DER
`30 06 02 01 01 0A 01 00` for application certificates and
`30 06 02 01 01 0A 01 01` for profile certificates.

`basicConstraints` follows `BasicConstraints(int pathLenConstraint)`, which sets
`CA:TRUE` implicitly, and `LocalizationAdapter` never produces a null path
length because it boxes a primitive `int`. The observable consequences are:

- a root or subordinate CA, and `generate-cert`, always report `CA:TRUE`;
- `generate-cert` reports `pathLenConstraint` `0` unless
  `-basicConstraintsPathLen` is given, so `-basicConstraintsCa false` has no
  effect;
- end-entity certificates carry a bare, non-critical sequence, which reads back
  as `CA:FALSE` with no path length.

Validity defaults are 3650 days for `generate-ca` and 1095 days for
`generate-cert`, `generate-app-cert`, and `generate-profile-cert`. Serial
numbers are positive 32-bit integers drawn from the platform CSPRNG.

Distinguished names use `CertUtils.buildDN`'s `X=xx,XX=xxx` grammar. Components
keep the order they were written in, because BouncyCastle's `X500Name(String)`
does not apply RFC 4514's most-specific-first convention. Attribute values are
`PrintableString` for `C` and `serialNumber`, `IA5String` for `DC`, and
`UTF8String` otherwise. The `CertReqInfo` this produces is byte-identical to
the official tool's for the same input.

PEM output uses 64-character lines and LF endings. Certification requests carry
the legacy `NEW CERTIFICATE REQUEST` label that `CertUtils.toCsrTemplate`
emits, not the modern `CERTIFICATE REQUEST` one.

## Keystore format

The container is chosen from the file extension, as
`KeyStoreHelper.createKeyStoreAccordingFileType` and `FileUtils.validFileType`
do: `.jks` selects JKS, `.p12` (and `.pfx`) select PKCS#12. JKS private keys use
Oracle's proprietary `KeyProtector` scheme with a 20-byte salt drawn from the
platform CSPRNG; the Rust `jks` dependency's `rand` feature is required for
this and is why it is enabled. Java's six-character minimum applies to the
store password only, so a short or empty key password is allowed.

PKCS#12 output is a PFX with a single unencrypted `AuthenticatedSafe` holding a
shrouded key bag and one certificate bag per chain entry. Each bag carries
`friendlyName` and `localKeyId` attributes so Java tooling can associate the
key with its chain. The key is protected with PBES2 using PBKDF2-HMAC-SHA256
and AES-256-CBC, and the archive integrity check is an HMAC-SHA256 `MacData`
over the `AuthenticatedSafe` octets, with 10000 iterations.

The MAC's `digestAlgorithm` is the plain `sha256` OID `2.16.840.1.101.3.4.2.1`
with an explicit NULL, which is what the JDK writes for `HmacPBESHA256`.
Using the parallel `hmacWithSHA256` OID `1.2.840.113549.2.9` instead makes
`keytool` reject the file with `Algorithm HmacPBEHMACSHA256 not available`.

Both formats and the generated certificates are verified against JDK 17: the
official `hap-sign-tool.jar` reads the Rust keystores, issues certificates
using them, and verifies a HAP signed with a certificate chain produced here.

## Generation divergences

Three behaviours differ from the official tool deliberately:

- **A keystore file is never merged.** The official `KeyStoreHelper.store`
  opens an existing keystore, adds the entry, and writes it back without a
  temporary file. This crate refuses to replace an existing keystore without
  `--force`, because merging into a populated PKCS#12 archive is not
  implemented. `generate-ca`, which auto-creates its key, therefore only
  creates a keystore when the file does not exist yet.
- **`generate-ca` rejects `--issuer` without `--issuer-key-alias`.** Upstream
  takes the root-CA path in that case and signs a certificate whose issuer name
  differs from its own subject with the same key, producing an identity that
  cannot validate.
- **CA certificate files may use `.pem` or `.crt`.** Upstream accepts `.cer`
  only, which rejects correctly encoded chains for no benefit.
