use core::fmt;

/// A parsed QASP Access Rights Model (ARM) resource URI.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ArmUri {
    pub provider: String,
    pub segments: Vec<String>,
}

impl fmt::Display for ArmUri {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "qasp://{}", self.provider)?;
        for segment in &self.segments {
            write!(formatter, "/{}", segment)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ArmUriError {
    message: String,
}

impl ArmUriError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for ArmUriError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ArmUriError {}

fn valid_provider(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.'))
}

fn valid_segment(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'*'))
}

pub fn parse_uri(uri: &str) -> Result<ArmUri, ArmUriError> {
    if uri.is_empty() {
        return Err(ArmUriError::new("ARM URI must not be empty"));
    }
    let body = uri
        .strip_prefix("qasp://")
        .ok_or_else(|| ArmUriError::new(format!("invalid ARM URI: {uri:?}")))?;

    let mut parts = body.split('/');
    let provider = parts.next().unwrap_or_default();
    if !valid_provider(provider) {
        return Err(ArmUriError::new(format!("invalid ARM URI: {uri:?}")));
    }

    let segments: Vec<String> = parts
        .map(|segment| {
            if valid_segment(segment) {
                Ok(segment.to_string())
            } else {
                Err(ArmUriError::new(format!("invalid ARM URI: {uri:?}")))
            }
        })
        .collect::<Result<_, _>>()?;

    for (index, segment) in segments.iter().enumerate() {
        if segment == "*" && index + 1 != segments.len() {
            return Err(ArmUriError::new(format!(
                "wildcard '*' may only appear as the last segment: {uri:?}"
            )));
        }
    }

    Ok(ArmUri {
        provider: provider.to_string(),
        segments,
    })
}

pub fn uri_matches(pattern: &str, target: &str) -> Result<bool, ArmUriError> {
    let pattern = parse_uri(pattern)?;
    let target = parse_uri(target)?;

    if pattern.provider != target.provider {
        return Ok(false);
    }
    if pattern.segments == target.segments {
        return Ok(true);
    }

    if pattern.segments.last().map(String::as_str) == Some("*") {
        let prefix = &pattern.segments[..pattern.segments.len() - 1];
        return Ok(
            target.segments.len() == prefix.len() + 1 && target.segments[..prefix.len()] == *prefix
        );
    }

    Ok(pattern.segments.len() < target.segments.len()
        && target.segments[..pattern.segments.len()] == pattern.segments)
}

pub fn is_attenuation(parent_uri: &str, child_uri: &str) -> Result<bool, ArmUriError> {
    uri_matches(parent_uri, child_uri)
}

pub fn intersect_uris(uri_a: &str, uri_b: &str) -> Result<Option<String>, ArmUriError> {
    let a = parse_uri(uri_a)?;
    let b = parse_uri(uri_b)?;

    if a.provider != b.provider {
        return Ok(None);
    }
    if uri_matches(uri_a, uri_b)? {
        return Ok(Some(uri_b.to_string()));
    }
    if uri_matches(uri_b, uri_a)? {
        return Ok(Some(uri_a.to_string()));
    }

    let a_concrete = without_trailing_wildcard(&a.segments);
    let b_concrete = without_trailing_wildcard(&b.segments);
    let common_len = a_concrete
        .iter()
        .zip(b_concrete.iter())
        .take_while(|(left, right)| left == right)
        .count();

    if common_len == 0 || (common_len < a_concrete.len() && common_len < b_concrete.len()) {
        return Ok(None);
    }

    if a_concrete.len() >= b_concrete.len() {
        Ok(Some(a.to_string()))
    } else {
        Ok(Some(b.to_string()))
    }
}

fn without_trailing_wildcard(segments: &[String]) -> &[String] {
    if segments.last().map(String::as_str) == Some("*") {
        &segments[..segments.len() - 1]
    } else {
        segments
    }
}

#[cfg(test)]
mod tests {
    use super::{intersect_uris, is_attenuation, parse_uri, uri_matches};

    #[test]
    fn parses_and_formats_uri() {
        let uri = parse_uri("qasp://cloud.acme.com/gpu-v2/model_a100.v3").unwrap();
        assert_eq!(uri.provider, "cloud.acme.com");
        assert_eq!(uri.segments, vec!["gpu-v2", "model_a100.v3"]);
        assert_eq!(
            uri.to_string(),
            "qasp://cloud.acme.com/gpu-v2/model_a100.v3"
        );
    }

    #[test]
    fn rejects_invalid_uri_forms() {
        assert!(parse_uri("").is_err());
        assert!(parse_uri("https://acme/gpu").is_err());
        assert!(parse_uri("qasp:///gpu").is_err());
        assert!(parse_uri("qasp://acme/gpu/").is_err());
        assert!(parse_uri("qasp://acme/*/gpu").is_err());
    }

    #[test]
    fn matches_exact_prefix_and_one_segment_wildcard_scopes() {
        assert!(uri_matches("qasp://acme/gpu/a100", "qasp://acme/gpu/a100").unwrap());
        assert!(uri_matches("qasp://acme/gpu", "qasp://acme/gpu/a100/mem").unwrap());
        assert!(uri_matches("qasp://acme/gpu/*", "qasp://acme/gpu/a100").unwrap());
        assert!(!uri_matches("qasp://acme/gpu/*", "qasp://acme/gpu/a100/mem").unwrap());
        assert!(!uri_matches("qasp://acme/gpu", "qasp://other/gpu").unwrap());
    }

    #[test]
    fn recognizes_narrowing_and_rejects_escalation() {
        assert!(is_attenuation("qasp://acme/gpu/*", "qasp://acme/gpu/a100").unwrap());
        assert!(is_attenuation("qasp://acme", "qasp://acme/gpu").unwrap());
        assert!(!is_attenuation("qasp://acme/gpu/a100", "qasp://acme/gpu/*").unwrap());
        assert!(!is_attenuation("qasp://acme/gpu/a100", "qasp://acme/gpu").unwrap());
    }

    #[test]
    fn intersects_to_most_specific_scope() {
        assert_eq!(
            intersect_uris("qasp://acme/gpu", "qasp://acme/gpu/a100").unwrap(),
            Some("qasp://acme/gpu/a100".to_string())
        );
        assert_eq!(
            intersect_uris("qasp://acme/gpu/*", "qasp://acme/gpu/a100").unwrap(),
            Some("qasp://acme/gpu/a100".to_string())
        );
        assert_eq!(
            intersect_uris("qasp://acme/gpu/a100", "qasp://acme/cpu/x86").unwrap(),
            None
        );
        assert_eq!(
            intersect_uris("qasp://acme/gpu", "qasp://other/gpu").unwrap(),
            None
        );
    }

    #[test]
    fn attenuation_and_matching_are_reflexive() {
        for uri in [
            "qasp://acme",
            "qasp://acme/gpu",
            "qasp://acme/gpu/a100",
            "qasp://acme/gpu/*",
        ] {
            assert!(uri_matches(uri, uri).unwrap());
            assert!(is_attenuation(uri, uri).unwrap());
        }
    }
}
