use base64::Engine;
use der::{Decode, DecodePem};
use x509_cert::Certificate;

use crate::SignError;

pub(crate) struct ProfileContent {
    value: serde_json::Value,
}

impl ProfileContent {
    pub(crate) fn from_profile(profile: &[u8], signed: bool) -> Result<Self, SignError> {
        if signed {
            Self::from_signed_profile(profile)
        } else {
            Self::from_json(profile)
        }
    }

    pub(crate) fn from_signed_profile(profile: &[u8]) -> Result<Self, SignError> {
        let verified = crate::pkcs7::verify_cms_signed_data(profile)?;
        Self::from_json(&verified.content)
    }

    pub(crate) fn from_json(profile: &[u8]) -> Result<Self, SignError> {
        let json = String::from_utf8(profile.to_vec()).map_err(|error| {
            SignError::Config(format!("profile content is not UTF-8 JSON: {error}"))
        })?;
        let value = serde_json::from_str::<serde_json::Value>(&json).map_err(|error| {
            SignError::Config(format!("profile content is not valid JSON: {error}"))
        })?;
        Ok(Self { value })
    }

    /// Mirrors `SignProvider.checkProfileValid`: application signing requires
    /// a debug or release profile whose corresponding embedded application
    /// certificate has a non-empty common name. ACLs are intentionally not
    /// evaluated; the official development-signing path does not impose an ACL
    /// policy.
    pub(crate) fn validate_for_application_signing(&self) -> Result<(), SignError> {
        let profile_type = self
            .value
            .get("type")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| SignError::Config("profile type is missing".to_owned()))?;
        let certificate_field = if profile_type.eq_ignore_ascii_case("debug") {
            "development-certificate"
        } else if profile_type.eq_ignore_ascii_case("release") {
            "distribution-certificate"
        } else {
            return Err(SignError::Config(format!(
                "unsupported profile type: {profile_type}"
            )));
        };
        let encoded_certificate = self
            .value
            .get("bundle-info")
            .and_then(|bundle_info| bundle_info.get(certificate_field))
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| SignError::Config(format!("profile {certificate_field} is missing")))?;
        let certificate = Self::decode_profile_certificate(encoded_certificate)?;
        let has_common_name = certificate
            .tbs_certificate
            .subject
            .0
            .iter()
            .flat_map(|rdn| rdn.0.iter())
            .find(|attribute| attribute.oid == const_oid::db::rfc4519::COMMON_NAME)
            .map(|attribute| attribute.value.value())
            .is_some_and(|value| !value.is_empty());
        if !has_common_name {
            return Err(SignError::Config(
                "profile application certificate common name is empty".to_owned(),
            ));
        }
        Ok(())
    }

    pub(crate) fn owner_id(&self) -> Result<Option<String>, SignError> {
        let profile_type = self
            .value
            .get("type")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| SignError::Config("profile type is missing".to_string()))?;
        if profile_type.eq_ignore_ascii_case("debug") {
            return Ok(Some("DEBUG_LIB_ID".to_owned()));
        }
        if !profile_type.eq_ignore_ascii_case("release") {
            return Err(SignError::Config(format!(
                "unsupported profile type for code signing: {profile_type}"
            )));
        }
        let owner_id = self
            .value
            .get("bundle-info")
            .and_then(|bundle_info| bundle_info.get("app-identifier"))
            .and_then(serde_json::Value::as_str);
        if let Some(owner_id) = owner_id {
            if owner_id.is_empty() || owner_id.len() > 32 {
                return Err(SignError::Config(
                    "profile app-identifier length is invalid".to_string(),
                ));
            }
            Ok(Some(owner_id.to_owned()))
        } else {
            Ok(None)
        }
    }

    pub(crate) fn plugin_id(&self) -> Result<String, SignError> {
        let plugin_id = self
            .value
            .get("app-services-capabilities")
            .and_then(|capabilities| capabilities.get("ohos.permission.kernel.SUPPORT_PLUGIN"))
            .and_then(|permission| permission.get("pluginDistributionIDs"))
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                SignError::Config("profile pluginDistributionIDs is missing".to_string())
            })?;
        if plugin_id.is_empty() {
            return Err(SignError::Config(
                "profile pluginDistributionIDs is empty".to_string(),
            ));
        }
        Ok(plugin_id.to_string())
    }

    pub(crate) fn public_hnp_owner_id(&self) -> Result<&'static str, SignError> {
        let profile_type = self.profile_type()?;
        if profile_type.eq_ignore_ascii_case("debug") {
            Ok("DEBUG_LIB_ID")
        } else if profile_type.eq_ignore_ascii_case("release") {
            Ok("SHARED_LIB_ID")
        } else {
            Err(SignError::Config(format!(
                "unsupported profile type for public HNP: {profile_type}"
            )))
        }
    }

    pub(crate) fn profile_type(&self) -> Result<&str, SignError> {
        self.value
            .get("type")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| SignError::Config("profile type is missing".to_owned()))
    }

    fn decode_profile_certificate(encoded: &str) -> Result<Certificate, SignError> {
        if let Ok(certificate) = Certificate::from_pem(encoded) {
            return Ok(certificate);
        }
        let compact = encoded.split_ascii_whitespace().collect::<String>();
        let der = base64::engine::general_purpose::STANDARD
            .decode(compact)
            .map_err(|error| {
                SignError::Config(format!(
                    "profile application certificate is not Base64: {error}"
                ))
            })?;
        Certificate::from_der(&der).map_err(|error| {
            SignError::Config(format!(
                "profile application certificate is invalid: {error}"
            ))
        })
    }
}
