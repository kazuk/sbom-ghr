use ::sha1::Sha1;
use digest::Digest;
use spdx_rs::models::{Algorithm, Checksum};

use crate::analyzers::FileAnalyzer;

pub struct Sha1Writer {
    sha1: Sha1,
}

impl Sha1Writer {
    pub fn new() -> Self {
        Self { sha1: Sha1::new() }
    }
}

impl std::io::Write for Sha1Writer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.sha1.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl FileAnalyzer for Sha1Writer {
    type Output = Checksum;

    fn finish(self) -> Self::Output {
        let hash = base16ct::lower::encode_string(&self.sha1.finalize());
        Checksum::new(Algorithm::SHA1, &hash)
    }
}
