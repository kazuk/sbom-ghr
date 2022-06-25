use std::{
    collections::HashMap,
    fs::read_dir,
    path::{Path, PathBuf},
};

use crate::{
    analyzers::{FileAnalyzer, SpdxFileAnalyzeSuccess, SpdxFileAnalyzer},
    packages::PackageAnalyzeError,
};

pub struct PathPackage {
    path: PathBuf,
    ignores: Vec<String>,
}

impl PathPackage {
    pub fn new(path: &Path) -> Self {
        Self {
            path: PathBuf::from(path),
            ignores: Vec::new(),
        }
    }

    pub fn append_ignore(&mut self, path: &Path) {
        self.ignores.push(path.to_str().unwrap().to_owned())
    }

    fn is_ignore(&self, path: &Path) -> bool {
        self.ignores.contains(&path.to_str().unwrap().to_owned())
    }

    pub fn analyze_files(
        mut self,
    ) -> Result<HashMap<String, SpdxFileAnalyzeSuccess>, PackageAnalyzeError> {
        let mut files = HashMap::new();
        let mut stack = Vec::new();
        let path_prefix = &self.path;
        stack.push(self.path.clone());

        while !stack.is_empty() {
            let dir = read_dir(stack.pop().unwrap())?;
            for entry in dir {
                let entry = entry?;
                let file_path = entry.path().strip_prefix(&path_prefix)?.to_owned();
                if !self.is_ignore(file_path.as_path()) {
                    if entry.metadata()?.is_dir() {
                        stack.push(entry.path().as_path().to_owned());
                        continue;
                    } else {
                        let mut file_analyzer = SpdxFileAnalyzer::new();
                        let mut file = std::fs::File::open(entry.path())?;
                        std::io::copy(&mut file, &mut file_analyzer)?;
                        let analyze_result = file_analyzer.finish().map_err(|e| {
                            PackageAnalyzeError::with_context(
                                &format!("analyzing file {:?}", file_path),
                                PackageAnalyzeError::from(e),
                            )
                        })?;
                        files.insert(
                            format!("./{}", file_path.to_string_lossy().into_owned()),
                            analyze_result,
                        );
                    }
                }
            }
        }

        Ok(files)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        env,
        path::{Path, PathBuf},
    };

    use crate::packages::{PackageAnalyzeError, PathPackage};

    #[test]
    fn test_analyze_self() -> Result<(), PackageAnalyzeError> {
        let mut path_pkg = PathPackage::new(Path::new(&env::var("CARGO_MANIFEST_DIR").unwrap()));
        path_pkg.append_ignore(&PathBuf::from("target").as_path());
        path_pkg.append_ignore(&PathBuf::from("vendor").as_path());
        path_pkg.append_ignore(&PathBuf::from(".git").as_path());
        path_pkg.append_ignore(&PathBuf::from("Cargo.lock").as_path());

        let files = path_pkg.analyze_files()?;
        assert!(files.get("./Cargo.toml").is_some());
        assert!(files.get("./src/packages/file_system.rs").is_some());
        assert!(files.get("./Cargo.lock").is_none()); // check works ignore

        let license_rs = files.get("./src/analyzers/license.rs");
        let license_rs = license_rs.unwrap();
        let exp = license_rs.license_information_in_file().as_ref().unwrap();
        assert_eq!(exp.identifier, "MIT");

        Ok(())
    }
}
