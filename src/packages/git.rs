use std::{collections::HashMap, fs};

use git2::build::RepoBuilder;
use tempfile::TempDir;
use url::Url;

use crate::{
    analyzers::SpdxFileAnalyzeSuccess,
    packages::{file_system::PathPackage, PackageAnalyzeError},
};

pub struct GitPackage {
    checkout_dir: TempDir,
}

impl GitPackage {
    pub fn checkout(clone_url: &Url, tag: &str) -> Result<Self, PackageAnalyzeError> {
        let tempdir = TempDir::new()?;
        let builder = RepoBuilder::new()
            .branch(tag)
            .clone(clone_url.as_str(), tempdir.path());
        Ok(GitPackage {
            checkout_dir: tempdir,
        })
    }

    pub fn analyze_files(
        mut self,
    ) -> Result<HashMap<String, SpdxFileAnalyzeSuccess>, PackageAnalyzeError> {
        PathPackage::new(self.checkout_dir.path()).analyze_files()
    }
}
