mod common;

use std::{collections::BTreeMap, mem::size_of, path::PathBuf};

use circuits::lowmc;
use clap::Parser;
use eyre::Result;
use mpc_core::{MpcState, protocols::rep3::Rep3State};
use mpc_net::{ConnectionStats, Network, tcp::TcpNetwork};
use primitives::BlockShare;
use structures::OhTablePrfNetwork;

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

const TCP_STRIPES: usize = 20;
const STRIPED_SMALL_SEND_THRESHOLD: usize = 64 * 1024;

fn main() -> Result<()> {
    common::install_tracing();

    let cli = Cli::parse();
    let doram_config = doram_config(&cli.doram)?;
    let network_config = common::read_network_config(&cli.network)?;
    let transport = format!("tcp striped x{TCP_STRIPES}");
    print_startup_config(
        &cli.doram,
        doram_config,
        &transport,
        Some((&cli.network, &network_config)),
    );
    let queries = generate_queries(&cli.doram);
    let net = StripedTcpNetwork::new(TcpNetwork::networks::<TCP_STRIPES>(network_config)?);
    let report = run_party(&cli.doram, doram_config, &queries, net)?;
    print_report(&cli.doram, &report);

    Ok(())
}

struct StripedTcpNetwork {
    nets: [TcpNetwork; TCP_STRIPES],
}

impl StripedTcpNetwork {
    fn new(nets: [TcpNetwork; TCP_STRIPES]) -> Self {
        Self { nets }
    }
}

impl Network for StripedTcpNetwork {
    fn id(&self) -> usize {
        self.nets[0].id()
    }

    fn send(&self, to: usize, data: &[u8]) -> Result<()> {
        if data.len() < STRIPED_SMALL_SEND_THRESHOLD {
            let mut framed = Vec::with_capacity(size_of::<u64>() + data.len());
            framed.extend_from_slice(&(data.len() as u64).to_le_bytes());
            framed.extend_from_slice(data);
            return self.nets[0].send(to, &framed);
        }

        self.nets[0].send(to, &(data.len() as u64).to_le_bytes())?;
        let chunk_size = data.len().div_ceil(TCP_STRIPES);
        std::thread::scope(|scope| {
            let handles = self
                .nets
                .iter()
                .enumerate()
                .map(|(i, net)| {
                    let start = (i * chunk_size).min(data.len());
                    let end = (start + chunk_size).min(data.len());
                    scope.spawn(move || net.send(to, &data[start..end]))
                })
                .collect::<Vec<_>>();

            for handle in handles {
                handle.join().expect("striped TCP send thread panicked")?;
            }
            Ok(())
        })
    }

    fn recv(&self, from: usize) -> Result<Vec<u8>> {
        let header = self.nets[0].recv(from)?;
        if header.len() < size_of::<u64>() {
            eyre::bail!("invalid striped TCP frame header");
        }

        let len = u64::from_le_bytes(header[..size_of::<u64>()].try_into().unwrap()) as usize;
        if len < STRIPED_SMALL_SEND_THRESHOLD {
            let data = header[size_of::<u64>()..].to_vec();
            if data.len() != len {
                eyre::bail!("invalid small striped TCP frame length");
            }
            return Ok(data);
        }

        if header.len() != size_of::<u64>() {
            eyre::bail!("invalid large striped TCP frame header");
        }
        let chunks = std::thread::scope(|scope| {
            let handles = self
                .nets
                .iter()
                .map(|net| scope.spawn(move || net.recv(from)))
                .collect::<Vec<_>>();
            handles
                .into_iter()
                .map(|handle| handle.join().expect("striped TCP recv thread panicked"))
                .collect::<Result<Vec<_>>>()
        })?;

        let mut data = Vec::with_capacity(chunks.iter().map(Vec::len).sum());
        for chunk in chunks {
            data.extend(chunk);
        }
        if data.len() != len {
            eyre::bail!("invalid large striped TCP frame length");
        }
        Ok(data)
    }

    fn get_connection_stats(&self) -> ConnectionStats {
        let mut totals = BTreeMap::new();
        for stats in self.nets.iter().map(Network::get_connection_stats) {
            for (party, (sent, received)) in stats.iter() {
                let total = totals.entry(party).or_insert((0, 0));
                total.0 += sent;
                total.1 += received;
            }
        }
        ConnectionStats::new(self.id(), totals)
    }
}

impl OhTablePrfNetwork for StripedTcpNetwork {
    fn evaluate_repeated_lowmc(
        &self,
        expanded_key: &[BlockShare],
        inputs: &[BlockShare],
        state: &mut Rep3State,
    ) -> Result<Vec<BlockShare>> {
        if inputs.is_empty() {
            return Ok(Vec::new());
        }

        let chunk_size = inputs.len().div_ceil(TCP_STRIPES).max(1);
        let chunks = inputs.chunks(chunk_size).collect::<Vec<_>>();
        let mut states = (0..chunks.len())
            .map(|_| state.fork(0))
            .collect::<Result<Vec<_>>>()?;

        let parts = std::thread::scope(|scope| {
            let handles = chunks
                .into_iter()
                .zip(self.nets.iter())
                .zip(states.iter_mut())
                .map(|((chunk, net), state)| {
                    scope.spawn(move || {
                        lowmc::encrypt_many_with_repeated_key(expanded_key, chunk, net, state)
                    })
                })
                .collect::<Vec<_>>();

            handles
                .into_iter()
                .map(|handle| handle.join().expect("parallel LowMC thread panicked"))
                .collect::<Result<Vec<_>>>()
        })?;

        Ok(parts.into_iter().flatten().collect())
    }
}
