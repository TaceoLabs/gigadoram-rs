mod common;

use clap::Parser;
use eyre::{Result, WrapErr, eyre};
use mpc_core::protocols::rep3::id::PartyID;
use primitives::run_parties;

use common::{
    DoramBenchmarkConfig, doram_config, generate_queries, print_report, print_startup_config,
    run_party,
};

#[derive(Clone, Debug, Parser)]
#[command(about = "Run the local three-party DORAM benchmark")]
struct Cli {
    #[command(flatten)]
    doram: DoramBenchmarkConfig,
}

fn main() -> Result<()> {
    common::install_tracing();

    let cli = Cli::parse();
    let doram_config = doram_config(&cli.doram)?;
    print_startup_config(&cli.doram, doram_config, "local", None);
    let queries = generate_queries(&cli.doram);
    let reports = run_parties(|net| {
        run_party(&cli.doram, doram_config, &queries, net).wrap_err("party failed")
    })
    .into_iter()
    .collect::<Result<Vec<_>>>()?;

    let party_zero_report = reports
        .iter()
        .find(|report| report.party == PartyID::ID0)
        .ok_or_else(|| eyre!("missing party 0 report"))?;
    print_report(&cli.doram, party_zero_report);

    Ok(())
}
