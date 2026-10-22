use std::fmt;

use thiserror::Error;

pub const MAX_BATCH: usize = 100;
const MAX_LEN: usize = 20;

#[derive(Debug, Error, PartialEq, Eq)]
#[error("invalid CVE id {0:?}: expected CVE-YYYY-NNNN with at least four digits")]
pub struct CveIdError(pub String);

/// A validated, upper-cased CVE identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CveId(String);

impl CveId {
    pub fn parse(raw: &str) -> Result<Self, CveIdError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.len() > MAX_LEN {
            return Err(CveIdError(truncate(raw)));
        }
        let upper = trimmed.to_ascii_uppercase();
        let mut parts = upper.splitn(3, '-');
        let ok = matches!(
            (parts.next(), parts.next(), parts.next()),
            (Some("CVE"), Some(year), Some(seq))
                if year.len() == 4 && all_digits(year) && seq.len() >= 4 && all_digits(seq)
        );
        if ok {
            Ok(CveId(upper))
        } else {
            Err(CveIdError(truncate(raw)))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Parses a batch, collecting every invalid entry instead of stopping at the first.
    pub fn parse_batch(raw: &[String]) -> Result<Vec<CveId>, BatchError> {
        if raw.is_empty() {
            return Err(BatchError::Empty);
        }
        if raw.len() > MAX_BATCH {
            return Err(BatchError::TooMany(raw.len()));
        }
        let mut ids = Vec::with_capacity(raw.len());
        let mut invalid = Vec::new();
        for r in raw {
            match CveId::parse(r) {
                Ok(id) => {
                    if !ids.contains(&id) {
                        ids.push(id);
                    }
                }
                Err(e) => invalid.push(e.0),
            }
        }
        if invalid.is_empty() {
            Ok(ids)
        } else {
            Err(BatchError::Invalid(invalid))
        }
    }
}

impl fmt::Display for CveId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BatchError {
    #[error("cve_ids must contain at least one id")]
    Empty,
    #[error("cve_ids holds {0} ids; the maximum per call is {MAX_BATCH}")]
    TooMany(usize),
    #[error("invalid CVE ids: {}", .0.join(", "))]
    Invalid(Vec<String>),
}

fn all_digits(s: &str) -> bool {
    s.bytes().all(|b| b.is_ascii_digit())
}

fn truncate(s: &str) -> String {
    s.chars().take(MAX_LEN).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_canonical_and_lowercase_ids() {
        assert_eq!(
            CveId::parse("CVE-2023-38606").unwrap().as_str(),
            "CVE-2023-38606"
        );
        assert_eq!(
            CveId::parse("cve-2021-44228").unwrap().as_str(),
            "CVE-2021-44228"
        );
        assert_eq!(
            CveId::parse("  CVE-2024-1234567 ").unwrap().as_str(),
            "CVE-2024-1234567"
        );
    }

    #[test]
    fn rejects_malformed_ids() {
        for bad in [
            "",
            "CVE-2023",
            "CVE-23-38606",
            "CVE-2023-123",
            "CVE-2023-38606-x",
            "CVE 2023 38606",
            "CVE-2023-38606&apiKey=x",
            "../CVE-2023-38606",
            "CVE-2023-3860612345678901",
        ] {
            assert!(CveId::parse(bad).is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn error_message_is_bounded() {
        let long = "x".repeat(500);
        let err = CveId::parse(&long).unwrap_err();
        assert_eq!(err.0.len(), MAX_LEN);
    }

    #[test]
    fn batch_dedups_and_collects_invalid() {
        let raw = vec![
            "CVE-2023-38606".into(),
            "cve-2023-38606".into(),
            "CVE-2021-44228".into(),
        ];
        let ids = CveId::parse_batch(&raw).unwrap();
        assert_eq!(ids.len(), 2);

        let raw = vec!["CVE-2023-38606".into(), "nope".into(), "CVE-1".into()];
        assert_eq!(
            CveId::parse_batch(&raw).unwrap_err(),
            BatchError::Invalid(vec!["nope".into(), "CVE-1".into()])
        );
        assert_eq!(CveId::parse_batch(&[]).unwrap_err(), BatchError::Empty);
        let many: Vec<String> = (0..=MAX_BATCH)
            .map(|i| format!("CVE-2024-{i:04}"))
            .collect();
        assert_eq!(
            CveId::parse_batch(&many).unwrap_err(),
            BatchError::TooMany(MAX_BATCH + 1)
        );
    }
}
