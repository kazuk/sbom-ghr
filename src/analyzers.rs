use spdx_rs::models::{Checksum, FileInformation, SimpleExpression, SpdxExpressionError};

mod license;
mod sha1;

pub trait FileAnalyzer: std::io::Write {
    type Output;

    fn finish(self) -> Self::Output;
}

pub struct SpdxFileAnalyzer {
    license_analyzer: license::SourceLicenceAnalyzer,
    sha1_analyzer: sha1::Sha1Writer,
}
pub struct SpdxFileAnalyzeSuccess {
    license_information_in_file: Option<SimpleExpression>,
    sha1_checksum: Checksum,
}

#[derive(thiserror::Error, Debug)]
pub enum SpdxFileAnalyzeError {
    #[error("parse license failed: {0}")]
    LicenseParseError(#[from] SpdxExpressionError),
    #[error("file io error {0}")]
    IoError(#[from] std::io::Error),
}

impl SpdxFileAnalyzer {
    pub fn new() -> Self {
        Self {
            license_analyzer: license::SourceLicenceAnalyzer::new(),
            sha1_analyzer: sha1::Sha1Writer::new(),
        }
    }
}

impl std::io::Write for SpdxFileAnalyzer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.license_analyzer.write(buf)?;
        self.sha1_analyzer.write(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.license_analyzer.flush()?;
        self.sha1_analyzer.flush()?;
        Ok(())
    }
}

impl FileAnalyzer for SpdxFileAnalyzer {
    type Output = Result<SpdxFileAnalyzeSuccess, SpdxFileAnalyzeError>;

    fn finish(self) -> Self::Output {
        let license_information_in_file = self.license_analyzer.finish()?;
        let sha1_checksum = self.sha1_analyzer.finish();

        Ok(SpdxFileAnalyzeSuccess {
            license_information_in_file,
            sha1_checksum,
        })
    }
}

impl SpdxFileAnalyzeSuccess {
    pub fn apply_to_file_info(
        self,
        file_info: &mut FileInformation,
    ) -> Result<(), SpdxFileAnalyzeError> {
        if let Some(license_expression) = self.license_information_in_file {
            file_info
                .license_information_in_file
                .push(license_expression);
        }
        file_info.file_checksum.push(self.sha1_checksum);
        Ok(())
    }

    pub fn sha1_checksum(&self) -> &Checksum {
        &self.sha1_checksum
    }

    pub fn license_information_in_file(&self) -> &Option<SimpleExpression> {
        &self.license_information_in_file
    }
}
