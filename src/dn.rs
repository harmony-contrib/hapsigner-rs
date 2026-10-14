//! Distinguished-name parsing.
//!
//! The accepted grammar is the `X=xx,XX=xxx` form used by official
//! `CertUtils.buildDN`, including its `checkDN` validation rules.

use std::str::FromStr;

use x509_cert::attr::AttributeTypeAndValue;
use x509_cert::name::{Name, RdnSequence, RelativeDistinguishedName};

use crate::error::SignError;

/// Parse an `X=xx,XX=xxx` distinguished name into an X.509 [`Name`].
///
/// Official `CertUtils.buildDN` validates the string and then delegates to
/// BouncyCastle's `X500Name(String)` parser. That parser trims the attribute
/// name on either side of the separator even though it leaves the value alone,
/// which `x509-cert`'s parser does not do at all; whitespace around the `=` and
/// after each `,` is therefore normalised here before handing the string over.
pub fn parse_distinguished_name(input: &str) -> Result<Name, SignError> {
    if input.trim().is_empty() {
        return Err(SignError::InvalidDistinguishedName(input.to_owned()));
    }
    let mut normalized = String::with_capacity(input.len());
    for (index, pair) in input.split(',').enumerate() {
        let Some((name, value)) = pair.split_once('=') else {
            return Err(SignError::InvalidDistinguishedName(input.to_owned()));
        };
        // `checkDN` splits each pair on "=" and requires exactly two parts.
        if value.contains('=') {
            return Err(SignError::InvalidDistinguishedName(input.to_owned()));
        }
        let (name, value) = (name.trim(), value.trim());
        if name.is_empty() || value.is_empty() {
            return Err(SignError::InvalidDistinguishedName(input.to_owned()));
        }
        if index > 0 {
            normalized.push(',');
        }
        normalized.push_str(name);
        normalized.push('=');
        normalized.push_str(value);
    }
    // Each pair is a single-valued RDN: `checkDN` requires exactly one `=` per
    // pair and never accepts the `+` separator.
    //
    // `RdnSequence::from_str` would reverse the components, because RFC 4514
    // writes a name most-specific-first while DER stores it root-first.
    // BouncyCastle's `X500Name(String)` instead keeps the components in the
    // order they were written, and that ordering is what the official tool
    // signs, so it is reproduced here.
    let mut components = Vec::new();
    for pair in normalized.split(',') {
        let attribute = AttributeTypeAndValue::from_str(pair)
            .map_err(|_| SignError::InvalidDistinguishedName(input.to_owned()))?;
        let rdn = RelativeDistinguishedName::try_from(vec![attribute])
            .map_err(|_| SignError::InvalidDistinguishedName(input.to_owned()))?;
        components.push(rdn);
    }
    Ok(RdnSequence(components))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_official_subject_shape() {
        let name =
            parse_distinguished_name("C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release")
                .expect("official example subject");
        assert_eq!(
            attribute_names(&name),
            ["C", "O", "OU", "CN"],
            "components must keep the order they were written in"
        );
    }

    /// Short names of each component, in DER order.
    fn attribute_names(name: &Name) -> Vec<String> {
        name.0
            .iter()
            .map(|rdn| {
                assert_eq!(rdn.0.len(), 1, "every RDN holds exactly one attribute");
                let oid = rdn.0.iter().next().expect("attribute").oid;
                const_oid::db::DB
                    .by_oid(&oid)
                    .unwrap_or_else(|| panic!("unknown attribute {oid}"))
                    .to_ascii_uppercase()
            })
            .collect()
    }

    #[test]
    fn tolerates_whitespace_around_separators() {
        let spaced = parse_distinguished_name(
            "C=CN, O=OpenHarmony, OU=OpenHarmony Community, CN=App1 Release",
        )
        .expect("spaced subject");
        let compact =
            parse_distinguished_name("C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release")
                .expect("compact subject");
        assert_eq!(spaced, compact);
        assert_eq!(attribute_names(&spaced), ["C", "O", "OU", "CN"]);
    }

    #[test]
    fn rejects_malformed_names() {
        for input in [
            "",
            "   ",
            "C=CN,O=OpenHarmony,NoSeparator",
            "C=CN,=OpenHarmony",
            "C=CN,O=",
            "C=CN,O=",
        ] {
            assert!(
                matches!(
                    parse_distinguished_name(input),
                    Err(SignError::InvalidDistinguishedName(_))
                ),
                "{input:?} must be rejected"
            );
        }
    }

    #[test]
    fn rejects_a_second_equals_sign() {
        assert!(matches!(
            parse_distinguished_name("C=CN,O=OpenHarmony,CN=a=b"),
            Err(SignError::InvalidDistinguishedName(_))
        ));
    }

    #[test]
    fn rejects_unknown_attribute_types() {
        assert!(matches!(
            parse_distinguished_name("NOTANATTRIBUTE=value"),
            Err(SignError::InvalidDistinguishedName(_))
        ));
    }
}
