//! `otpauth://` provisioning URI builder (Google Authenticator Key URI format).

use percent_encoding::{percent_decode_str, utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};

use crate::error::{Error, Result};
use crate::otp::TotpParams;
use crate::secret::Secret;

const UNRESERVED: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

const MAX_LABEL_LEN: usize = 128;

fn check_label(field: &'static str, value: &str, allow_colon: bool) -> Result<()> {
    if value.trim().is_empty() {
        return Err(Error::InvalidLabel {
            field,
            reason: "must not be empty",
        });
    }
    if value.chars().count() > MAX_LABEL_LEN {
        return Err(Error::InvalidLabel {
            field,
            reason: "must be at most 128 characters",
        });
    }
    if value.chars().any(char::is_control) {
        return Err(Error::InvalidLabel {
            field,
            reason: "must not contain control characters",
        });
    }
    if !allow_colon && value.contains(':') {
        return Err(Error::InvalidLabel {
            field,
            reason: "must not contain ':'",
        });
    }
    Ok(())
}

fn enc(value: &str) -> String {
    utf8_percent_encode(value, UNRESERVED).to_string()
}

/// Builds an `otpauth://totp/...` URI.
pub fn totp_uri(
    secret: &Secret,
    account: &str,
    issuer: Option<&str>,
    params: &TotpParams,
) -> Result<String> {
    params.validate()?;
    let account = account.trim();
    check_label("account", account, true)?;
    let issuer = match issuer.map(str::trim) {
        Some(i) => {
            check_label("issuer", i, false)?;
            Some(i)
        }
        None => None,
    };
    let mut uri = String::from("otpauth://totp/");
    if let Some(i) = issuer {
        uri.push_str(&enc(i));
        uri.push(':');
    }
    uri.push_str(&enc(account));
    uri.push_str("?secret=");
    uri.push_str(&secret.to_base32());
    if let Some(i) = issuer {
        uri.push_str("&issuer=");
        uri.push_str(&enc(i));
    }
    uri.push_str(&format!(
        "&algorithm={}&digits={}&period={}",
        params.algorithm, params.digits, params.period
    ));
    Ok(uri)
}

/// Result of parsing an `otpauth://totp/...` URI.
#[derive(Debug)]
pub struct ParsedUri {
    /// Shared secret.
    pub secret: Secret,
    /// Issuer, from the `issuer` parameter or the label prefix.
    pub issuer: Option<String>,
    /// Account part of the label, if any.
    pub account: Option<String>,
    /// Algorithm, digits and period (defaults applied).
    pub params: TotpParams,
}

fn decode(value: &str) -> Result<String> {
    percent_decode_str(value)
        .decode_utf8()
        .map(|c| c.into_owned())
        .map_err(|_| Error::InvalidUri("not valid UTF-8"))
}

/// Parses an `otpauth://totp/...` URI as found inside provisioning QR codes.
pub fn parse_totp_uri(input: &str) -> Result<ParsedUri> {
    const SCHEME: &str = "otpauth://";
    let input = input.trim();
    let rest = input
        .get(..SCHEME.len())
        .filter(|p| p.eq_ignore_ascii_case(SCHEME))
        .map(|_| &input[SCHEME.len()..])
        .ok_or(Error::InvalidUri("must start with otpauth://"))?;
    let (kind, rest) = rest
        .split_once('/')
        .ok_or(Error::InvalidUri("missing type or label"))?;
    if kind.eq_ignore_ascii_case("hotp") {
        return Err(Error::InvalidUri(
            "HOTP (counter-based) URIs are not supported",
        ));
    }
    if !kind.eq_ignore_ascii_case("totp") {
        return Err(Error::InvalidUri("type must be totp"));
    }
    let (label, query) = rest.split_once('?').unwrap_or((rest, ""));
    let label = decode(label)?;
    let (label_issuer, account) = match label.split_once(':') {
        Some((i, a)) => (Some(i.trim().to_owned()), a.trim().to_owned()),
        None => (None, label.trim().to_owned()),
    };

    let mut secret = None;
    let mut issuer = None;
    let mut algorithm = None;
    let mut digits = None;
    let mut period = None;
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let value = decode(value)?;
        match key.to_ascii_lowercase().as_str() {
            "secret" => secret = Some(Secret::from_base32(&value)?),
            "issuer" => issuer = Some(value),
            "algorithm" => algorithm = Some(value.parse()?),
            "digits" => {
                digits = Some(
                    value
                        .parse::<u32>()
                        .map_err(|_| Error::InvalidUri("digits is not a number"))?,
                );
            }
            "period" => {
                period = Some(
                    value
                        .parse::<u64>()
                        .map_err(|_| Error::InvalidUri("period is not a number"))?,
                );
            }
            _ => {}
        }
    }
    let secret = secret.ok_or(Error::InvalidUri("missing secret parameter"))?;
    let params = TotpParams::new(
        algorithm.unwrap_or_default(),
        digits.unwrap_or(crate::otp::DEFAULT_DIGITS),
        period.unwrap_or(crate::otp::DEFAULT_PERIOD),
    )?;
    Ok(ParsedUri {
        secret,
        issuer: issuer.or(label_issuer).filter(|s| !s.is_empty()),
        account: Some(account).filter(|s| !s.is_empty()),
        params,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret() -> Secret {
        Secret::from_base32("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap()
    }

    #[test]
    fn full_uri() {
        let uri = totp_uri(
            &secret(),
            "alice@example.com",
            Some("ACME Co"),
            &TotpParams::default(),
        )
        .unwrap();
        assert_eq!(
            uri,
            "otpauth://totp/ACME%20Co:alice%40example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30"
        );
    }

    #[test]
    fn uri_without_issuer() {
        let uri = totp_uri(&secret(), "bob", None, &TotpParams::default()).unwrap();
        assert!(uri.starts_with("otpauth://totp/bob?secret="));
        assert!(!uri.contains("issuer"));
    }

    #[test]
    fn unicode_is_encoded() {
        let uri = totp_uri(&secret(), "müller", Some("Tëst"), &TotpParams::default()).unwrap();
        assert!(uri.contains("m%C3%BCller"));
        assert!(uri.contains("T%C3%ABst"));
    }

    #[test]
    fn rejects_bad_labels() {
        let p = TotpParams::default();
        assert!(totp_uri(&secret(), "  ", None, &p).is_err());
        assert!(totp_uri(&secret(), "a", Some("x:y"), &p).is_err());
        assert!(totp_uri(&secret(), "a\nb", None, &p).is_err());
        assert!(totp_uri(&secret(), &"a".repeat(129), None, &p).is_err());
    }

    #[test]
    fn parse_roundtrip() {
        let params = TotpParams::new(crate::otp::Algorithm::Sha256, 8, 60).unwrap();
        let uri = totp_uri(&secret(), "alice@example.com", Some("ACME Co"), &params).unwrap();
        let parsed = parse_totp_uri(&uri).unwrap();
        assert_eq!(parsed.secret, secret());
        assert_eq!(parsed.issuer.as_deref(), Some("ACME Co"));
        assert_eq!(parsed.account.as_deref(), Some("alice@example.com"));
        assert_eq!(parsed.params, params);
    }

    #[test]
    fn parse_variants() {
        let p = parse_totp_uri(
            "OTPAUTH://TOTP/PyPI%3Auser?secret=gezd gnbv gy3t qojq gezd gnbv gy3t qojq",
        );
        assert!(p.is_err() || p.unwrap().issuer.as_deref() == Some("PyPI"));
        let p = parse_totp_uri(
            "otpauth://totp/PyPI:user?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&foo=bar",
        )
        .unwrap();
        assert_eq!(p.issuer.as_deref(), Some("PyPI"));
        assert_eq!(p.params, TotpParams::default());
        let p = parse_totp_uri("otpauth://totp/?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap();
        assert!(p.account.is_none() && p.issuer.is_none());
    }

    #[test]
    fn parse_rejects_bad_input() {
        assert!(parse_totp_uri("https://example.com").is_err());
        assert!(parse_totp_uri("otpauth://hotp/a?secret=GEZDGNBVGY3TQOJQ&counter=1").is_err());
        assert!(parse_totp_uri("otpauth://totp/a").is_err());
        assert!(parse_totp_uri("otpauth://totp/a?secret=GEZDGNBVGY3TQOJQ&digits=x").is_err());
        assert!(parse_totp_uri("otpauth://totp/a?secret=GEZDGNBVGY3TQOJQ&digits=12").is_err());
    }
}
