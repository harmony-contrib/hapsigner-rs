# OpenHarmony format alignment

The implementation follows both sides of OpenHarmony's HAP signature contract,
not only a sample signed file.

Source revisions used for the implementation and QEMU validation on 2026-08-09:

- `developtools_hapsigner` at `6e46665d418d0dfedd6ba460172271565020f212`
- `security_appverify` at `78d4b2c274ac33f211217d1cd4980d2faf469c64`

The corresponding upstream repositories are:

- <https://gitee.com/openharmony/developtools_hapsigner>
- <https://gitee.com/openharmony/security_appverify>

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

The `block_length` excludes its own four-byte field.

## HAP content digest

`HapSigningBlockUtils::ComputeDigestsForEachChunk` hashes the three ZIP
sections in 1 MiB chunks. Every chunk is prefixed by `0xa5` and its little-endian
length. The list starts with `0x5a` and the chunk count. The final SHA-256 input
is that list followed by each optional block value in signing-block order. A
QEMU development signature contains the attached signed profile as its optional
block.

## Signing block

The v3 block contains 12-byte little-endian type/length/offset entries, their
values, the block count, total size, `<hap sign block>`, and version `3`. This
tool emits profile block `0x20000002` followed by main signature block
`0x20000000`.

The implementation is regression-tested against these layouts and was accepted
by the `v20260809` QEMU image (`OpenHarmony 7.0.0.32`) for both a normal HAP and
a HAP declaring a VPN extension.
