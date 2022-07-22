use spdx_rs::models::{FileInformation, PackageInformation, Relationship, RelationshipType, SPDX};

mod tv_writer;

pub trait WriteTagValue<W: std::io::Write> {
    fn write_tag_value( &self, write: &mut W) -> Result<(), std::io::Error>;
}

pub struct SpdxDocument {
    spdx_id: i32,
    document: SPDX,
}

impl SpdxDocument {
    pub fn new(name: &str) -> Self {
        Self {
            spdx_id: 0,
            document: SPDX::new(name),
        }
    }

    pub fn new_package(&mut self, name: &str) -> PackageInformation {
        PackageInformation::new(name, &mut self.spdx_id)
    }

    pub fn push_package(&mut self, package: PackageInformation) {
        self.document.package_information.push(package);
    }

    pub fn new_file(&mut self, name: &str) -> FileInformation {
        FileInformation::new(name, &mut self.spdx_id)
    }

    pub fn push_file(&mut self, file: FileInformation) {
        self.document.file_information.push(file);
    }

    pub fn push_contains(&mut self, package_id: &str, file_id: &str) {
        let relation = Relationship::new(package_id, &file_id, RelationshipType::Contains, None);
        self.document.relationships.push(relation);
    }
}
