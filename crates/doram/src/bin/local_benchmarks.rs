mod common;

use std::time::{Duration, Instant};

use circuits::network::CircuitNetwork;
use clap::Parser;
use eyre::{Result, WrapErr, ensure, eyre};
use mpc_core::protocols::rep3::id::PartyID;
use mpc_net::{ConnectionStats, Network, local::LocalNetwork};
use structures::OhTablePrfNetwork;

use common::{
    DoramBenchmarkConfig, doram_config, generate_queries, print_report, print_startup_config,
    run_party,
};

#[derive(Clone, Debug, Parser)]
#[command(about = "Run the local three-party DORAM benchmark")]
struct Cli {
    #[command(flatten)]
    doram: DoramBenchmarkConfig,

    #[arg(long, default_value_t = 0.0)]
    network_latency_ms: f64,
}

fn main() -> Result<()> {
    common::install_tracing();

    let cli = Cli::parse();
    ensure!(
        cli.network_latency_ms >= 0.0,
        "network latency must be non-negative"
    );

    let send_latency = Duration::from_secs_f64(cli.network_latency_ms / 1_000.0);
    let doram_config = doram_config(&cli.doram)?;
    let transport = if send_latency.is_zero() {
        "local".to_owned()
    } else {
        format!(
            "local fixed-latency ({:.3} ms/send)",
            cli.network_latency_ms
        )
    };
    print_startup_config(&cli.doram, doram_config, &transport, None);
    if !send_latency.is_zero() {
        tracing::info!(
            "\nLatency model\n|- min: 0.229 ms\n|- avg: 0.236 ms\n|- max: 0.244 ms\n|- mdev: 0.003 ms\n`- applied: {:.3} ms/send",
            cli.network_latency_ms
        );
    }

    let queries = generate_queries(&cli.doram);
    let reports = run_local_parties(send_latency, |net| {
        run_party(&cli.doram, doram_config, &queries, net).wrap_err("party failed")
    })?
    .into_iter()
    .collect::<Result<Vec<_>>>()?;

    let party_zero_report = reports
        .iter()
        .find(|report| report.party == PartyID::ID0)
        .ok_or_else(|| eyre!("missing party 0 report"))?;
    print_report(&cli.doram, party_zero_report);

    Ok(())
}

fn run_local_parties<R, F>(send_latency: Duration, f: F) -> Result<[R; 3]>
where
    R: Send,
    F: Fn(FixedLatencyNetwork) -> R + Sync,
{
    let [net0, net1, net2] = LocalNetwork::new_3_parties();

    std::thread::scope(|scope| {
        let f = &f;
        let party_0 = scope.spawn(move || {
            f(FixedLatencyNetwork {
                inner: net0,
                send_latency,
            })
        });
        let party_1 = scope.spawn(move || {
            f(FixedLatencyNetwork {
                inner: net1,
                send_latency,
            })
        });
        let party_2 = scope.spawn(move || {
            f(FixedLatencyNetwork {
                inner: net2,
                send_latency,
            })
        });

        Ok([
            party_0.join().map_err(|_| eyre!("party 0 panicked"))?,
            party_1.join().map_err(|_| eyre!("party 1 panicked"))?,
            party_2.join().map_err(|_| eyre!("party 2 panicked"))?,
        ])
    })
}

struct FixedLatencyNetwork {
    inner: LocalNetwork,
    send_latency: Duration,
}

impl Network for FixedLatencyNetwork {
    fn id(&self) -> usize {
        self.inner.id()
    }

    fn send(&self, to: usize, data: &[u8]) -> eyre::Result<()> {
        wait_fixed_latency(self.send_latency);
        self.inner.send(to, data)
    }

    fn recv(&self, from: usize) -> eyre::Result<Vec<u8>> {
        self.inner.recv(from)
    }

    fn get_connection_stats(&self) -> ConnectionStats {
        self.inner.get_connection_stats()
    }
}

impl OhTablePrfNetwork for FixedLatencyNetwork {}
impl CircuitNetwork for FixedLatencyNetwork {}

fn wait_fixed_latency(duration: Duration) {
    if duration.is_zero() {
        return;
    }

    let start = Instant::now();
    while start.elapsed() < duration {
        std::hint::spin_loop();
    }
}
