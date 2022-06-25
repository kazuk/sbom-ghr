mod file_system;
mod git;
mod tar;
mod zip;

use std::path::StripPrefixError;

use ::zip::result::ZipError;

use crate::analyzers::SpdxFileAnalyzeError;

#[derive(Debug, thiserror::Error)]
pub enum PackageAnalyzeError {
    #[error("file io failed {0}")]
    Io(#[from] std::io::Error),
    #[error("file analyze failed {0}")]
    FileAnalyze(#[from] SpdxFileAnalyzeError),
    #[error("ZipError")]
    Zip(#[from] ZipError),
    #[error("{0}")]
    Context(String, Box<PackageAnalyzeError>),
    #[error("{0}")]
    PathStripFailed(#[from] StripPrefixError),
}

impl PackageAnalyzeError {
    pub fn with_context(message: &str, inner: PackageAnalyzeError) -> Self {
        Self::Context(message.to_string(), Box::new(inner))
    }
}

pub use self::tar::TarPackage;
pub use self::zip::ZipPackage;
pub use file_system::PathPackage;
pub use git::GitPackage;
