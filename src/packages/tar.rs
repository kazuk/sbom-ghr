use std::collections::HashMap;

use ::tar::Archive as Tar;
use anyhow::Result;
use flate2::read::GzDecoder;

use crate::{
    analyzers::{FileAnalyzer, SpdxFileAnalyzeSuccess, SpdxFileAnalyzer},
    packages::PackageAnalyzeError,
};

pub struct TarPackage<R: std::io::Read> {
    tar: Tar<GzDecoder<R>>,
}

impl<R: std::io::Read> TarPackage<R> {
    pub fn from_read(file: R) -> Self {
        let gzdec = GzDecoder::new(file);
        let tar = Tar::new(gzdec);
        Self { tar }
    }

    pub fn analyze_files(
        mut self,
    ) -> Result<HashMap<String, SpdxFileAnalyzeSuccess>, PackageAnalyzeError> {
        let mut files = HashMap::new();
        for entry in self.tar.entries()? {
            let mut file = entry?;
            let mut file_analyzer = SpdxFileAnalyzer::new();
            std::io::copy(&mut file, &mut file_analyzer)?;
            let analyze_result = file_analyzer.finish()?;
            files.insert(file.path()?.to_str().unwrap().to_owned(), analyze_result);
        }
        Ok(files)
    }
}
