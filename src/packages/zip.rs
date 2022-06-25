use std::collections::HashMap;

use ::zip::ZipArchive;

use crate::{
    analyzers::{FileAnalyzer, SpdxFileAnalyzeSuccess, SpdxFileAnalyzer},
    packages::PackageAnalyzeError,
};

pub struct ZipPackage<R: std::io::Read + std::io::Seek> {
    zip: ZipArchive<R>,
}

impl<R: std::io::Read + std::io::Seek> ZipPackage<R> {
    pub fn from_read(file: R) -> Result<Self, PackageAnalyzeError> {
        Ok(Self {
            zip: ZipArchive::new(file)?,
        })
    }

    pub fn analyze_files(
        mut self,
    ) -> Result<HashMap<String, SpdxFileAnalyzeSuccess>, PackageAnalyzeError> {
        let mut files = HashMap::new();
        for index in 0..self.zip.len() {
            let mut file = self.zip.by_index(index)?;
            let mut file_analyzer = SpdxFileAnalyzer::new();
            std::io::copy(&mut file, &mut file_analyzer)?;
            let analyze_result = file_analyzer.finish()?;
            files.insert(
                file.mangled_name().to_str().unwrap().to_owned(),
                analyze_result,
            );
        }
        Ok(files)
    }
}
