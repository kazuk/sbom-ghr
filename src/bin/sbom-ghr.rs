use anyhow::Result;
use clap::Parser;
use sbom_ghr::DescribeArgs;

#[derive(clap::Parser, Debug)]
#[clap(name = "sbom-ghr", author, about, version)]
struct Args {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand, Debug)]
enum Commands {
    Describe(DescribeArgs),
}

impl Commands {
    pub async fn run(self) -> Result<()> {
        match self {
            Commands::Describe(a) => a.run().await,
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    args.command.run().await?;

    Ok(())
}
