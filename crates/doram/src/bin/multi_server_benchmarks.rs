mod common;

use std::path::PathBuf;

use clap::Parser;
use eyre::Result;
use mpc_net::tcp::TcpNetwork;

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
}

fn main() -> Result<()> {
    common::install_tracing();

    let cli = Cli::parse();
    let doram_config = doram_config(&cli.doram)?;
    let network_config = common::read_network_config(&cli.network)?;
    print_startup_config(
        &cli.doram,
        doram_config,
        "tcp",
        Some((&cli.network, &network_config)),
    );
    let queries = generate_queries(&cli.doram);
    let net = TcpNetwork::new(network_config)?;
    let report = run_party(&cli.doram, doram_config, &queries, net)?;
    print_report(&cli.doram, &report);

    Ok(())
}
