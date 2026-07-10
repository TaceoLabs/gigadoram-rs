mod common;

use std::path::{Path, PathBuf};

use clap::Parser;
use eyre::{Context, Result};
use mpc_net::{
    config::{NetworkConfig, NetworkConfigFile},
    tcp::TcpNetwork,
};

use common::{
    DoramBenchmarkConfig, doram_config, generate_queries, print_report, print_startup_config,
    run_party,
};

#[derive(Clone, Debug, Parser)]
#[command(about = "Run the TCP three-party DORAM benchmark")]
struct Cli {
    #[command(flatten)]
    doram: DoramBenchmarkConfig,

    #[arg(long)]
    network: PathBuf,

    #[arg(long, default_value_t = false)]
    progress: bool,
}

fn main() -> Result<()> {
    common::install_tracing();

    let cli = Cli::parse();
    let doram_config = doram_config(&cli.doram)?;
    let network_config = read_network_config(&cli.network)?;
    print_startup_config(
        &cli.doram,
        doram_config,
        "tcp",
        Some((&cli.network, &network_config)),
    );

    let queries = generate_queries(&cli.doram);
    let net = TcpNetwork::new(network_config)?;
    let report = run_party(&cli.doram, doram_config, &queries, net, cli.progress)?;
    print_report(&cli.doram, &report);

    Ok(())
}

fn read_network_config(path: &Path) -> Result<NetworkConfig> {
    let config_file: NetworkConfigFile = toml::from_str(
        &std::fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?,
    )
    .with_context(|| format!("failed to parse {}", path.display()))?;
    NetworkConfig::try_from(config_file)
        .with_context(|| format!("failed to load network config from {}", path.display()))
}
