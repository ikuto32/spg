//! Errors. The variants follow the spec's vocabulary (§2.4): a *rejected* file is not used
//! at all; *corrupt* data is a block or record that must not be used; *invalid* data is a
//! logical model that a conforming writer must not write.

use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// The file (or the whole file set of a manifest) must not be used (§2.4.3).
    Rejected(String),
    /// A block, section or record failed a check (§2.4.4).
    Corrupt { section: Option<[u8; 4]>, detail: String },
    /// A `.spgt` syntax error (§9.2), with the 1-based line number.
    Syntax { line: usize, detail: String },
    /// Data that violates a writer requirement of the spec.
    Invalid(String),
    /// Something this implementation does not support.
    Unsupported(String),
    /// A resource limit was exceeded.
    Limit(String),
    Io(String),
}

impl Error {
    pub fn rejected(m: impl Into<String>) -> Self {
        Error::Rejected(m.into())
    }

    pub fn corrupt(m: impl Into<String>) -> Self {
        Error::Corrupt { section: None, detail: m.into() }
    }

    pub fn corrupt_in(tag: [u8; 4], m: impl Into<String>) -> Self {
        Error::Corrupt { section: Some(tag), detail: m.into() }
    }

    pub fn invalid(m: impl Into<String>) -> Self {
        Error::Invalid(m.into())
    }

    pub fn syntax(line: usize, m: impl Into<String>) -> Self {
        Error::Syntax { line, detail: m.into() }
    }

    /// Attach a section tag to a corruption error that has none.
    pub fn in_section(self, tag: [u8; 4]) -> Self {
        match self {
            Error::Corrupt { section: None, detail } => Error::Corrupt { section: Some(tag), detail },
            other => other,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Rejected(m) => write!(f, "rejected: {m}"),
            Error::Corrupt { section: Some(t), detail } => write!(f, "corrupt {}: {detail}", String::from_utf8_lossy(t)),
            Error::Corrupt { section: None, detail } => write!(f, "corrupt: {detail}"),
            Error::Syntax { line, detail } => write!(f, "line {line}: {detail}"),
            Error::Invalid(m) => write!(f, "invalid SPG data: {m}"),
            Error::Unsupported(m) => write!(f, "unsupported: {m}"),
            Error::Limit(m) => write!(f, "limit exceeded: {m}"),
            Error::Io(m) => write!(f, "I/O error: {m}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
