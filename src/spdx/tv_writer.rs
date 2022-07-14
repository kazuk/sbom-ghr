//! write tag-value for SPDX

use std::fmt::Display;

use chrono::SecondsFormat;
use spdx_rs::models::{SPDX, DocumentCreationInformation, CreationInfo};

use super::WriteTagValue;
   
impl<W: std::io::Write> WriteTagValue<W> for SPDX {

    fn write_tag_value( &self, write: &mut W) -> Result<(), std::io::Error> {
        self.document_creation_information.write_tag_value(write)?;
        self.package_information.write_tag_value(write)?;
        self.file_information.write_tag_value(write)?;
        Ok(())
    }
}

impl<W: std::io::Write> WriteTagValue<W> for DocumentCreationInformation {
    fn write_tag_value( &self, write: &mut W) -> Result<(), std::io::Error> {
        writeln!(write, "SPDXVersion: {}", self.spdx_version)?;
        writeln!(write, "DataLicense: {}", self.data_license)?;
        writeln!(write, "SPDXID: {}", self.spdx_identifier)?;
        writeln!(write, "DocumentName: {}", self.document_name)?;
        writeln!(write, "DocumentNamespace: {}", self.spdx_document_namespace)?;
        for item in self.external_document_references {
            item.write_tag_value(write)?;
        }
        self.creation_info.write_tag_value(write)?;
        Ok(())
    }
}

fn write_tag_value_opt<W: std::io::Write, S: Display>( write: &mut W, tag_name: &str, tag_value: &Option<S> ) -> Result<(), std::io::Error> {
    if let Some(v) = tag_value {
        writeln!( write, "{}: {}", tag_name, v)?;
    }
    Ok(())
}

fn write_tag_value_vec<W: std::io::Write, S: Display>( write: &mut W, tag_name: &str, values: &Vec<S>) -> Result<(), std::io::Error> {
    for value in values {
        writeln!( write, "{}: {}", tag_name, value)?;
    }
    Ok(())
}


impl<W: std::io::Write> WriteTagValue<W> for CreationInfo {
    fn write_tag_value( &self, write: &mut W) -> Result<(), std::io::Error> {
        write_tag_value_opt(write, "LicenseListVersion", &self.license_list_version)?;
        write_tag_value_vec(write, "Creator", &self.creators)?;
        write!(write, "Created: {}", self.created.to_rfc3339_opts(SecondsFormat::Secs, true))?;
        Ok(())
    }
}
