mod common;

use std::{collections::BTreeMap, mem::size_of, path::PathBuf};

use circuits::{
    batcher::{apply_compare_swap_dummy_pair_deltas, compare_swap_dummy_pair_deltas},
    dummy_check::dummy_check_circuit,
    lowmc,
    network::CircuitNetwork,
    replace_if_dummy::replace_if_dummy_circuit,
    xy_if_xs_equal::xy_if_xs_equal_circuit,
};
use clap::Parser;
use eyre::Result;
use mpc_core::{MpcState, protocols::rep3::Rep3State};
use mpc_net::{ConnectionStats, Network, tcp::TcpNetwork};
use primitives::{BlockShare, XShare, YShare, types::BitShare};
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

impl CircuitNetwork for StripedTcpNetwork {
    fn evaluate_dummy_check(
        &self,
        xs: &[XShare],
        log_n: usize,
        state: &mut Rep3State,
    ) -> Result<Vec<BitShare>> {
        if xs.is_empty() {
            return Ok(Vec::new());
        }

        let chunks = self.chunks(xs);
        let mut states = self.fork_states(state, chunks.len())?;
        let parts = std::thread::scope(|scope| {
            let handles = chunks
                .into_iter()
                .zip(self.nets.iter())
                .zip(states.iter_mut())
                .map(|((chunk, net), state)| {
                    scope.spawn(move || dummy_check_circuit(chunk, log_n, net, state))
                })
                .collect::<Vec<_>>();

            handles
                .into_iter()
                .map(|handle| handle.join().expect("parallel dummy_check thread panicked"))
                .collect::<Result<Vec<_>>>()
        })?;

        Ok(parts.into_iter().flatten().collect())
    }

    fn evaluate_replace_if_dummy(
        &self,
        xs: &[XShare],
        replacements: &[XShare],
        log_n: usize,
        state: &mut Rep3State,
    ) -> Result<Vec<XShare>> {
        assert_eq!(xs.len(), replacements.len());
        if xs.is_empty() {
            return Ok(Vec::new());
        }

        let ranges = self.ranges(xs.len());
        let mut states = self.fork_states(state, ranges.len())?;
        let parts = std::thread::scope(|scope| {
            let handles = ranges
                .into_iter()
                .zip(self.nets.iter())
                .zip(states.iter_mut())
                .map(|((range, net), state)| {
                    scope.spawn(move || {
                        replace_if_dummy_circuit(
                            &xs[range.clone()],
                            &replacements[range],
                            log_n,
                            net,
                            state,
                        )
                    })
                })
                .collect::<Vec<_>>();

            handles
                .into_iter()
                .map(|handle| {
                    handle
                        .join()
                        .expect("parallel replace_if_dummy thread panicked")
                })
                .collect::<Result<Vec<_>>>()
        })?;

        Ok(parts.into_iter().flatten().collect())
    }

    fn evaluate_xy_if_xs_equal(
        &self,
        x: &[XShare],
        x_query: &[XShare],
        y: &[YShare],
        state: &mut Rep3State,
    ) -> Result<(Vec<XShare>, Vec<YShare>, Vec<BitShare>)> {
        assert_eq!(x.len(), x_query.len());
        assert_eq!(x.len(), y.len());
        if x.is_empty() {
            return Ok((Vec::new(), Vec::new(), Vec::new()));
        }

        let ranges = self.ranges(x.len());
        let mut states = self.fork_states(state, ranges.len())?;
        let parts = std::thread::scope(|scope| {
            let handles = ranges
                .into_iter()
                .zip(self.nets.iter())
                .zip(states.iter_mut())
                .map(|((range, net), state)| {
                    scope.spawn(move || {
                        xy_if_xs_equal_circuit(
                            &x[range.clone()],
                            &x_query[range.clone()],
                            &y[range],
                            net,
                            state,
                        )
                    })
                })
                .collect::<Vec<_>>();

            handles
                .into_iter()
                .map(|handle| {
                    handle
                        .join()
                        .expect("parallel xy_if_xs_equal thread panicked")
                })
                .collect::<Result<Vec<_>>>()
        })?;

        let mut xs = Vec::with_capacity(x.len());
        let mut ys = Vec::with_capacity(y.len());
        let mut found = Vec::with_capacity(x.len());
        for (x_part, y_part, found_part) in parts {
            xs.extend(x_part);
            ys.extend(y_part);
            found.extend(found_part);
        }
        Ok((xs, ys, found))
    }

    fn compare_swap_dummy_pairs(
        &self,
        pairs: &[(usize, usize)],
        dummy_flags: &mut [BitShare],
        xs: &mut [XShare],
        ys: &mut [YShare],
        state: &mut Rep3State,
    ) -> Result<()> {
        if pairs.is_empty() {
            return Ok(());
        }

        let chunks = self.chunks(pairs);
        let mut states = self.fork_states(state, chunks.len())?;
        let dummy_flags_in = &*dummy_flags;
        let xs_in = &*xs;
        let ys_in = &*ys;
        let parts = std::thread::scope(|scope| {
            let handles = chunks
                .into_iter()
                .zip(self.nets.iter())
                .zip(states.iter_mut())
                .map(|((chunk, net), state)| {
                    scope.spawn(move || {
                        compare_swap_dummy_pair_deltas(
                            chunk,
                            dummy_flags_in,
                            xs_in,
                            ys_in,
                            net,
                            state,
                        )
                    })
                })
                .collect::<Vec<_>>();

            handles
                .into_iter()
                .map(|handle| {
                    handle
                        .join()
                        .expect("parallel compare_swap thread panicked")
                })
                .collect::<Result<Vec<_>>>()
        })?;

        let selected_row_deltas = parts.into_iter().flatten().collect::<Vec<_>>();
        apply_compare_swap_dummy_pair_deltas(pairs, &selected_row_deltas, dummy_flags, xs, ys);
        Ok(())
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

impl StripedTcpNetwork {
    fn ranges(&self, len: usize) -> Vec<std::ops::Range<usize>> {
        let chunk_size = len.div_ceil(TCP_STRIPES).max(1);
        (0..len)
            .step_by(chunk_size)
            .map(|start| start..(start + chunk_size).min(len))
            .collect()
    }

    fn chunks<'a, T>(&self, values: &'a [T]) -> Vec<&'a [T]> {
        let chunk_size = values.len().div_ceil(TCP_STRIPES).max(1);
        values.chunks(chunk_size).collect()
    }

    fn fork_states(&self, state: &mut Rep3State, count: usize) -> Result<Vec<Rep3State>> {
        (0..count).map(|_| state.fork(0)).collect()
    }
}
