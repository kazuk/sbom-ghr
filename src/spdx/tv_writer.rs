//! write tag-value for SPDX

use std::{fmt::Display, io::ErrorKind};

use chrono::SecondsFormat;
use spdx_rs::models::{
    Algorithm, Annotation, Checksum, CreationInfo, DocumentCreationInformation,
    ExternalDocumentReference, ExternalPackageReference, ExternalPackageReferenceCategory,
    FileInformation, FileType, OtherLicensingInformationDetected, PackageInformation,
    PackageVerificationCode, Pointer, Range, Relationship, Snippet, SPDX,
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

fn validate_id_string(id_string: &str) -> Result<(), std::io::Error> {
    fn valid_id_string_char(ch: char) -> bool {
        ch.is_ascii_alphanumeric() || ch == '.' || ch == '-' || ch == '+'
    }

    if id_string.chars().all(valid_id_string_char) {
        Ok(())
    } else {
        Err(std::io::Error::new(
            ErrorKind::InvalidData,
            "invalid charctor in id_string",
        ))
    }
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
        validate_id_string(&self.spdx_identifier)?;

        write_tag_value_normal(write, "SPDXVersion", &self.spdx_version)?;
        write_tag_value_normal(write, "DataLicense", &self.data_license)?;
        write_tag_value_normal(write, "SPDXID", &self.spdx_identifier)?;
        write_tag_value_normal(write, "DocumentName", &self.document_name)?;
        write_tag_value_normal(write, "DocumentNamespace", &self.spdx_document_namespace)?;
        for item in &self.external_document_references {
            item.write_tag_value(write)?;
        }
        write_tag_value_opt(
            write,
            "DocumentComment",
            &wrap_text_opt(&self.document_comment),
        )?;

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
        validate_id_string(&self.id_string)?;

        let tag_value = format!(
            "DocumentRef-{} {} {}",
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

/// https://spdx.github.io/spdx-spec/snippet-information/
impl<W: std::io::Write> WriteTagValue<W> for Snippet {
    fn write_tag_value(&self, write: &mut W) -> Result<(), std::io::Error> {
        write_tag_value_normal(write, "SnippetSPDXID", &self.snippet_spdx_identifier)?;
        write_tag_value_normal(
            write,
            "SnippetFromFileSPDXID",
            &self.snippet_from_file_spdx_identifier,
        )?;
        for range in &self.ranges {
            range.write_tag_value(write)?;
        }
        write_tag_value_normal(
            write,
            "SnippetLicenseConcluded",
            &self.snippet_concluded_license,
        )?;
        write_tag_value_vec(
            write,
            "LicenseInfoInSnippet",
            &self.license_information_in_snippet,
        )?;
        write_tag_value_opt(
            write,
            "SnippetLicenseComments",
            &wrap_text_opt(&self.snippet_comments_on_license),
        )?;
        write_tag_value_normal(
            write,
            "SnippetCopyrightText",
            &wrap_text(&self.snippet_copyright_text),
        )?;
        write_tag_value_opt(
            write,
            "SnippetComment",
            &wrap_text_opt(&self.snippet_comment),
        )?;
        write_tag_value_opt(write, "SnippetName", &self.snippet_name)?;
        write_tag_value_opt(
            write,
            "SnippetAttributionText",
            &wrap_text_opt(&self.snippet_attribution_text),
        )?;

        Ok(())
    }
}

impl<W: std::io::Write> WriteTagValue<W> for Range {
    fn write_tag_value(&self, write: &mut W) -> Result<(), std::io::Error> {
        match self.start_pointer {
            Pointer::Byte {
                offset: start_offset,
                ..
            } => match self.end_pointer {
                Pointer::Byte {
                    offset: end_offset, ..
                } => write_tag_value_normal(
                    write,
                    "SnippetByteRange",
                    &format!("{}:{}", start_offset, end_offset),
                )?,
                Pointer::Line { .. } => panic!("range combines byte and line"),
            },
            Pointer::Line {
                line_number: start_line,
                ..
            } => match self.end_pointer {
                Pointer::Byte { .. } => panic!("range combines line and byte"),
                Pointer::Line {
                    line_number: end_line,
                    ..
                } => write_tag_value_normal(
                    write,
                    "SnippetLineRange",
                    &format!("{}:{}", start_line, end_line),
                )?,
            },
        }
        Ok(())
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

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use spdx_rs::{
        models::{Algorithm, Checksum, ExternalDocumentReference, SPDX},
        parsers::spdx_from_tag_value,
    };

    use crate::spdx::WriteTagValue;

    fn write_and_parse(source_spdx: &SPDX) -> SPDX {
        let mut buffer = Vec::new();
        let mut write = Cursor::new(&mut buffer);
        source_spdx.write_tag_value(&mut write).unwrap();
        let spdx_document = std::str::from_utf8(&buffer).unwrap();
        eprintln!("SPDX-DOCUMENT \n\n{}", spdx_document);
        spdx_from_tag_value(spdx_document).unwrap()
    }

    #[test]
    fn write_parse_simpl_spdxdoc() {
        let result_spdx = write_and_parse(&SPDX::new("this is spdx file"));
        assert_eq!(
            result_spdx.document_creation_information.document_name,
            "this is spdx file"
        );
    }

    #[test]
    fn write_parse_doc_creation_information() {
        let mut source_spdx = SPDX::new("this is spdx file");
        source_spdx.document_creation_information.spdx_version = "5.0.0-snapshot".to_string();
        source_spdx.document_creation_information.data_license = "this is data license".to_string();
        source_spdx.document_creation_information.spdx_identifier = "SPDXRef-ROOT".to_string();
        source_spdx
            .document_creation_information
            .spdx_document_namespace = "NAMESPACE".to_string();
        let external_document_reference = ExternalDocumentReference::new(
            "EXTERNAL-ID-STRING".to_string(),
            "http://spdx.org/spdxdocs/spdx-tools-v1.2-3F2504E0-4F89-41D3-9A0C-0305E82C3301"
                .to_string(),
            Checksum::new(Algorithm::SHA1, "12345"),
        );
        source_spdx
            .document_creation_information
            .external_document_references
            .push(external_document_reference);
        let external_document_reference = ExternalDocumentReference::new(
            "EXTERNAL-ID-STRING2".to_string(),
            "http://spdx.org/spdxdocs/spdx-tools-v1.2-3F2504E0-4F89-41D3-9A0C-0305E82C3301"
                .to_string(),
            Checksum::new(Algorithm::MD5, "12345"),
        );
        source_spdx
            .document_creation_information
            .external_document_references
            .push(external_document_reference);
        source_spdx.document_creation_information.document_comment =
            Some("document comment! \n multi line!".to_string());

        let result_spdx = write_and_parse(&source_spdx);

        assert_eq!(
            result_spdx.document_creation_information.document_name,
            "this is spdx file"
        );

        assert_eq!(
            result_spdx.document_creation_information.spdx_version,
            "5.0.0-snapshot"
        );
        assert_eq!(
            result_spdx.document_creation_information.data_license,
            "this is data license"
        );
        assert_eq!(
            result_spdx.document_creation_information.spdx_identifier,
            "SPDXRef-ROOT"
        );
        assert_eq!(
            result_spdx
                .document_creation_information
                .spdx_document_namespace,
            "NAMESPACE"
        );
        assert_eq!(
            result_spdx
                .document_creation_information
                .external_document_references
                .len(),
            2
        );
        assert_eq!(
            result_spdx
                .document_creation_information
                .external_document_references[0]
                .id_string,
            "EXTERNAL-ID-STRING"
        );
        assert_eq!(
            result_spdx.document_creation_information.document_comment,
            Some("document comment! \n multi line!".to_string())
        );
    }
}
