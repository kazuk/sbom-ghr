// SPDX-License-Identifier: MIT

use spdx_rs::models::SimpleExpression;
use std::io::{BufRead, BufReader, Cursor};

use crate::analyzers::{FileAnalyzer, SpdxFileAnalyzeError};

pub struct SourceLicenceAnalyzer {
    buffer: Cursor<Vec<u8>>,
}

impl SourceLicenceAnalyzer {
    pub fn new() -> Self {
        Self {
            buffer: Cursor::new(Vec::new()),
        }
    }
}

impl std::io::Write for SourceLicenceAnalyzer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.buffer.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.buffer.flush()
    }
}

const TARGET: &str = "SPDX-License-Identifier:";

fn is_whitespace(line: &str, index: usize) -> bool {
    let line_bytes = line.as_bytes();
    match line_bytes[index] {
        b' ' | b'\t' => true,
        _ => false,
    }
}

fn parse_license_identifer(line: &str) -> Result<SimpleExpression, SpdxFileAnalyzeError> {
    let mut start = line.find(TARGET).unwrap() + TARGET.len();
    while is_whitespace(line, start) {
        start = start + 1
    }
    let remains = &line[start..];
    Ok(SimpleExpression::parse(remains)?)
}

impl FileAnalyzer for SourceLicenceAnalyzer {
    type Output = Result<Option<SimpleExpression>, SpdxFileAnalyzeError>;

    fn finish(self) -> Self::Output {
        let buffered = self.buffer.get_ref();
        let lines = BufReader::new(Cursor::new(buffered)).lines();
        for line in lines {
            let line = line?;
            if line.contains(TARGET) {
                return Ok(Some(parse_license_identifer(&line)?));
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use crate::analyzers::{license::SourceLicenceAnalyzer, FileAnalyzer};

    #[test]
    fn test_find_license_identifier() {
        let mut analyzer = SourceLicenceAnalyzer::new();
        analyzer
            .write(b"// SPDX-License-Identifier: GPL-3\n")
            .unwrap();
        analyzer.write(b"// more comment here").unwrap();
        analyzer.flush().unwrap();
        let result = analyzer.finish();
        let result = result.unwrap(); // unwrap Option
        let result = result.unwrap(); // unwrap Ok
        assert_eq!(result.document_ref, None);
        assert_eq!(result.identifier.as_str(), "GPL-3");
    }
}
