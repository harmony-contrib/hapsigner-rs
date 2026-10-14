# Native code-sign sequential reference

`native-code-sign-stored.bin` and `native-code-sign-deflated.bin` are property
blocks captured from the published hapsigner 0.2.0 (`ec531c0`) sequential
`native_sign_infos` / `hnp_sign_infos` implementation, before parallelization.
`native_code_sign_layout_matches_sequential_fixture_with_one_and_four_workers`
constructs the corresponding HAP inputs and verifies signed outputs, both
file-backed and memory-backed, with one and four Rayon workers.

The HAP has three distinct native libraries plus an HNP with three ELF files
and one non-ELF entry. Inner archive order deliberately differs from name order.
The test uses the existing RSA test key for fixed signature sizes. Normalization
zeros only CMS signature octets and fixes CMS signingTime to 2026-01-01 UTC;
all other bytes (including CMS messageDigest, certificates, owner IDs, SignInfo
offsets/sizes, Merkle data and segment layout) are compared verbatim. ELF load
segments are read-only so `.pages.info` generation cannot introduce a current
ZIP timestamp into the fixture's HAP Merkle tree. Existing executable-page
bitmap tests continue to cover that separate behavior.
