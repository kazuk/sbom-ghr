//! write tag-value for SPDX

use std::fmt::Display;

use chrono::SecondsFormat;
use spdx_rs::models::{
    Algorithm, Annotation, Checksum, CreationInfo, DocumentCreationInformation,
    ExternalDocumentReference, ExternalPackageReference, ExternalPackageReferenceCategory,
    FileInformation, FileType, OtherLicensingInformationDetected, PackageInformation,
    PackageVerificationCode, Relationship, Snippet, SPDX,
};

use super::WriteTagValue;

fn write_tag_value_normal<W: std::io::Write, S: Display>(
    write: &mut W,
    tag_name: &str,
    tag_value: &S,
) -> Result<(), std::io::Error> {
    writeln!(write, "{}: {}", tag_name, tag_value)
}

fn write_tag_value_opt<W: std::io::Write, S: Display>(
    write: &mut W,
    tag_name: &str,
    tag_value: &Option<S>,
) -> Result<(), std::io::Error> {
    if let Some(v) = tag_value {
        write_tag_value_normal(write, tag_name, v)?;
    }
    Ok(())
}

fn write_tag_value_vec<W: std::io::Write, S: Display>(
    write: &mut W,
    tag_name: &str,
    values: &Vec<S>,
) -> Result<(), std::io::Error> {
    for value in values {
        write_tag_value_normal(write, tag_name, value)?;
    }
    Ok(())
}

fn wrap_text<S: Display>(wrapping: &S) -> String {
    format!("<text>{}</text>", wrapping)
}

fn write_tag_value_vec_text<W: std::io::Write, S: Display>(
    write: &mut W,
    tag_name: &str,
    values: &Vec<S>,
) -> Result<(), std::io::Error> {
    for value in values {
        write_tag_value_normal(write, tag_name, &wrap_text(value))?;
    }
    Ok(())
}

fn wrap_text_opt<S: Display>(wrapping: &Option<S>) -> Option<String> {
    wrapping.as_ref().map(|s| wrap_text(&s))
}

fn format_checksum(checksum: &Checksum) -> String {
    let algorithm_name = match checksum.algorithm {
        Algorithm::SHA1 => "SHA1",
        Algorithm::SHA224 => "SHA224",
        Algorithm::SHA256 => "SHA256",
        Algorithm::SHA384 => "SHA384",
        Algorithm::SHA512 => "SHA512",
        Algorithm::MD2 => "MD2",
        Algorithm::MD4 => "MD4",
        Algorithm::MD5 => "MD5",
        Algorithm::MD6 => "MD6",
    };
    format!("{}: {}", algorithm_name, checksum.value)
}

impl<W: std::io::Write> WriteTagValue<W> for SPDX {
    fn write_tag_value(&self, write: &mut W) -> Result<(), std::io::Error> {
        self.document_creation_information.write_tag_value(write)?;
        for package in &self.package_information {
            package.write_tag_value(write)?;
        }
        for file in &self.file_information {
            file.write_tag_value(write)?;
        }
        for snippet in &self.snippet_information {
            snippet.write_tag_value(write)?;
        }
        for other_licensing in &self.other_licensing_information_detected {
            other_licensing.write_tag_value(write)?;
        }
        for rel in &self.relationships {
            rel.write_tag_value(write)?;
        }
        for ann in &self.annotations {
            ann.write_tag_value(write)?;
        }

        Ok(())
    }
}

impl<W: std::io::Write> WriteTagValue<W> for DocumentCreationInformation {
    fn write_tag_value(&self, write: &mut W) -> Result<(), std::io::Error> {
        write_tag_value_normal(write, "SPDXVersion", &self.spdx_version)?;
        write_tag_value_normal(write, "DataLicense", &self.data_license)?;
        write_tag_value_normal(write, "SPDXID", &self.spdx_identifier)?;
        write_tag_value_normal(write, "DocumentName", &self.document_name)?;
        write_tag_value_normal(write, "DocumentNamespace", &self.spdx_document_namespace)?;
        for item in &self.external_document_references {
            item.write_tag_value(write)?;
        }
        self.creation_info.write_tag_value(write)?;
        Ok(())
    }
}

impl<W: std::io::Write> WriteTagValue<W> for CreationInfo {
    fn write_tag_value(&self, write: &mut W) -> Result<(), std::io::Error> {
        write_tag_value_opt(write, "LicenseListVersion", &self.license_list_version)?;
        write_tag_value_vec(write, "Creator", &self.creators)?;
        write_tag_value_normal(
            write,
            "Created",
            &self.created.to_rfc3339_opts(SecondsFormat::Secs, true),
        )?;
        Ok(())
    }
}

impl<W: std::io::Write> WriteTagValue<W> for ExternalDocumentReference {
    fn write_tag_value(&self, write: &mut W) -> Result<(), std::io::Error> {
        let tag_value = format!(
            "{} {} {}",
            self.id_string,
            self.spdx_document_uri,
            format_checksum(&self.checksum)
        );
        write_tag_value_normal(write, "ExternalDocumentRef", &tag_value)?;
        Ok(())
    }
}

impl<W: std::io::Write> WriteTagValue<W> for PackageInformation {
    /// https://spdx.github.io/spdx-spec/package-information/
    fn write_tag_value(&self, write: &mut W) -> Result<(), std::io::Error> {
        write_tag_value_normal(write, "PackageName", &self.package_name)?;
        write_tag_value_normal(write, "SPDXID", &self.package_spdx_identifier)?;
        write_tag_value_opt(write, "PackageVersion", &self.package_version)?;
        write_tag_value_opt(write, "PackageFileName", &self.package_file_name)?;
        write_tag_value_opt(write, "PackageSupplier", &self.package_supplier)?;
        write_tag_value_opt(write, "PackageOriginator", &self.package_originator)?;
        write_tag_value_normal(
            write,
            "PackageDownloadLocation",
            &self.package_download_location,
        )?;
        write_tag_value_opt(write, "FilesAnalyzed", &self.files_analyzed)?;
        if let Some(package_verification_code) = &self.package_verification_code {
            package_verification_code.write_tag_value(write)?;
        }
        write_tag_value_vec(
            write,
            "PackageChecksum",
            &self.package_checksum.iter().map(format_checksum).collect(),
        )?;

        write_tag_value_opt(write, "PackageHomePage", &self.package_home_page)?;
        write_tag_value_opt(
            write,
            "PackageSourceInfo",
            &wrap_text_opt(&self.source_information),
        )?;
        write_tag_value_normal(write, "PackageLicenseConcluded", &self.concluded_license)?;
        write_tag_value_vec(
            write,
            "PackageLicenseInfoFromFiles",
            &self.all_licenses_information_from_files,
        )?;
        write_tag_value_normal(write, "PackageLicenseDeclared", &self.declared_license)?;
        write_tag_value_opt(
            write,
            "PackageLicenseComments",
            &wrap_text_opt(&self.comments_on_license),
        )?;
        write_tag_value_normal(
            write,
            "PackageCopyrightText",
            &wrap_text(&self.copyright_text),
        )?;
        write_tag_value_opt(
            write,
            "PackageSummary",
            &wrap_text_opt(&self.package_summary_description),
        )?;
        write_tag_value_opt(
            write,
            "PackageDescription",
            &wrap_text_opt(&self.package_detailed_description),
        )?;
        write_tag_value_opt(
            write,
            "PackageComment",
            &wrap_text_opt(&self.package_comment),
        )?;
        for extref in &self.external_reference {
            extref.write_tag_value(write)?;
        }
        write_tag_value_vec_text(
            write,
            "PackageAttributionText",
            &self.package_attribution_text,
        )?;

        Ok(())
    }
}

impl<W: std::io::Write> WriteTagValue<W> for PackageVerificationCode {
    fn write_tag_value(&self, write: &mut W) -> Result<(), std::io::Error> {
        let value = if self.excludes.len() == 0 {
            format!("{}", self.value)
        } else {
            format!("{} (excludes: {})", self.value, self.excludes.join(" "))
        };
        write_tag_value_normal(write, "PackageVerificationCode", &value)?;
        Ok(())
    }
}

impl<W: std::io::Write> WriteTagValue<W> for ExternalPackageReference {
    fn write_tag_value(&self, write: &mut W) -> Result<(), std::io::Error> {
        let category = match self.reference_category {
            ExternalPackageReferenceCategory::Security => "SECURITY",
            ExternalPackageReferenceCategory::PackageManager => "PACKAGE-MANAGER",
            ExternalPackageReferenceCategory::PersistentID => "PERSISTENT-ID",
            ExternalPackageReferenceCategory::Other => "OTHER",
        };

        write_tag_value_normal(
            write,
            "ExternalRef",
            &format!(
                "{} {} {}",
                category, self.reference_type, self.reference_locator
            ),
        )?;
        write_tag_value_opt(write, "ExternalComment", &self.reference_comment)?;
        Ok(())
    }
}

fn file_type_name(file_type: &FileType) -> &'static str {
    match file_type {
        FileType::Source => "SOURCE",
        FileType::Binary => "BINARY",
        FileType::Archive => "ARCHIVE",
        FileType::Application => "APPLICATION",
        FileType::Audio => "AUDIO",
        FileType::Image => "IMAGE",
        FileType::Text => "TEXT",
        FileType::Video => "VIDEO",
        FileType::Documentation => "DOCUMENTATION",
        FileType::SPDX => "SPDX",
        FileType::Other => "OTHER",
    }
}

impl<W: std::io::Write> WriteTagValue<W> for FileInformation {
    /// https://spdx.github.io/spdx-spec/file-information/
    fn write_tag_value(&self, write: &mut W) -> Result<(), std::io::Error> {
        write_tag_value_normal(write, "FileName", &self.file_name)?;
        write_tag_value_normal(write, "SPDXID", &self.file_spdx_identifier)?;
        write_tag_value_vec(
            write,
            "FileType",
            &self.file_type.iter().map(file_type_name).collect(),
        )?;
        write_tag_value_vec(
            write,
            "FileChecksum",
            &self.file_checksum.iter().map(format_checksum).collect(),
        )?;
        write_tag_value_normal(write, "LicenseConcluded", &self.concluded_license)?;
        write_tag_value_vec(
            write,
            "LicenseInfoInFile",
            &self.license_information_in_file,
        )?;
        write_tag_value_opt(write, "LicenseComments", &self.comments_on_license)?;
        write_tag_value_normal(write, "FileCopyrightText", &self.copyright_text)?;
        write_tag_value_opt(write, "FileComment", &wrap_text_opt(&self.file_comment))?;
        write_tag_value_opt(write, "FileNotice", &wrap_text_opt(&self.file_notice))?;
        write_tag_value_vec(write, "FileContributor", &self.file_contributor)?;
        if let Some(attribution) = &self.file_attribution_text {
            write_tag_value_vec_text(write, "FileAttributionText", &attribution)?;
        }
        Ok(())
    }
}

impl<W: std::io::Write> WriteTagValue<W> for Snippet {
    fn write_tag_value(&self, write: &mut W) -> Result<(), std::io::Error> {
        todo!()
    }
}

impl<W: std::io::Write> WriteTagValue<W> for OtherLicensingInformationDetected {
    fn write_tag_value(&self, write: &mut W) -> Result<(), std::io::Error> {
        todo!()
    }
}

impl<W: std::io::Write> WriteTagValue<W> for Relationship {
    fn write_tag_value(&self, write: &mut W) -> Result<(), std::io::Error> {
        todo!()
    }
}

impl<W: std::io::Write> WriteTagValue<W> for Annotation {
    fn write_tag_value(&self, write: &mut W) -> Result<(), std::io::Error> {
        todo!()
    }
}
