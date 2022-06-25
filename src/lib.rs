use std::{
    collections::HashMap,
    io::{Cursor, SeekFrom},
};

use anyhow::{anyhow, Result};
use octocrab::Octocrab;
use url::Url;

use crate::{
    analyzers::SpdxFileAnalyzeSuccess,
    packages::{GitPackage, TarPackage, ZipPackage},
    spdx::SpdxDocument,
};

mod analyzers;
mod packages;
mod spdx;

fn file_name_from_url(url: &Url) -> Result<String> {
    let segments = url
        .path_segments()
        .ok_or_else(|| anyhow!("can not take to path segments from url {}", url))?;
    let last_segment = segments
        .last()
        .ok_or_else(|| anyhow!("can not take a last segment from url : {}", url))?;
    Ok(last_segment.to_string())
}

async fn download_file_from_url<W: std::io::Write + std::io::Seek>(
    url: &Url,
    file: &mut W,
) -> Result<()> {
    let http_client = reqwest::Client::default();
    let response = http_client.get(url.as_str()).send().await?;
    let mut content = Cursor::new(response.bytes().await?);
    std::io::copy(&mut content, file)?;
    file.seek(SeekFrom::Start(0))?;
    Ok(())
}

#[derive(clap::Args, Debug)]
pub struct DescribeArgs {
    owner: String,
    repo: String,
    tag: String,
}

type Files = HashMap<String, SpdxFileAnalyzeSuccess>;

impl DescribeArgs {
    async fn analyze_tar(tar_url: &Url) -> Result<Files> {
        let mut file = tempfile::tempfile()?;
        download_file_from_url(tar_url, &mut file).await?;
        let files_from_tar = TarPackage::from_read(file).analyze_files()?;
        Ok(files_from_tar)
    }

    async fn analyze_zip(tar_url: &Url) -> Result<Files> {
        let mut file = tempfile::tempfile()?;
        download_file_from_url(tar_url, &mut file).await?;
        let files_from_tar = ZipPackage::from_read(file)?.analyze_files()?;
        Ok(files_from_tar)
    }

    fn analyze_git(clone_url: Url, tag: String) -> Result<Files> {
        let package = GitPackage::checkout(&clone_url, &tag)?;
        Ok(package.analyze_files()?)
    }

    pub async fn run(self) -> Result<()> {
        let mut spdx_doc = SpdxDocument::new(&format!("{}_{}", self.repo, self.tag));
        let octocrab = Octocrab::builder().build()?;
        let repo_client = octocrab.repos(self.owner, self.repo);
        let repo = repo_client.get().await?;
        let release = repo_client.releases().get_by_tag(&self.tag).await?;
        println!("procesing release : {:?}", release);
        let git_analyze_task = {
            let clone_url = repo.clone_url.unwrap().clone();
            tokio::spawn(async move { Self::analyze_git(clone_url, self.tag) })
        };
        let tar_analyze_task = if let Some(ref tar_url) = release.tarball_url {
            let tar_url = tar_url.clone();
            Some(tokio::spawn(
                async move { Self::analyze_tar(&tar_url).await },
            ))
        } else {
            None
        };
        let zip_analyze_task = if let Some(ref zip_url) = release.zipball_url {
            let zip_url = zip_url.clone();
            Some(tokio::spawn(
                async move { Self::analyze_zip(&zip_url).await },
            ))
        } else {
            None
        };

        let git_result = git_analyze_task.await?;

        let zip_result = if let Some(zip_task) = zip_analyze_task {
            Some(zip_task.await?)
        } else {
            None
        };
        let tar_result = if let Some(tar_task) = tar_analyze_task {
            Some(tar_task.await?)
        } else {
            None
        };

        for asset in release.assets {
            println!("processing asset : {:?}", asset);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
