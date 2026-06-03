use std::{
    collections::HashMap,
    path::Path,
    time::{Duration, Instant},
};

use clap::{ArgAction, Args};
use doram::{GigaDoram, GigaDoramConfig, GigaDoramTiming};
use eyre::{Result, ensure};
use mpc_core::protocols::rep3::{Rep3State, conversion::A2BType, id::PartyID};
use mpc_net::{Network, tcp::NetworkConfig};
use primitives::{X, Y, Y_BITS, YField, open_y, promote_public, promote_public_y, random_bigint};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

#[derive(Clone, Debug, Args)]
pub struct DoramBenchmarkConfig {
    #[arg(long, default_value = "100000")]
    pub num_queries: usize,

    #[arg(long, default_value = "25")]
    pub log_address_space: usize,

    #[arg(long, default_value = "5")]
    pub num_levels: usize,

    #[arg(long, default_value = "4")]
    pub log_amp_factor: usize,

    #[arg(long, action = ArgAction::Set, default_value_t = false)]
    pub build_bottom_level_at_startup: bool,

    #[arg(long, default_value = "42")]
    pub seed: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct BenchmarkQuery {
    x: X,
    y: Y,
    is_write: bool,
}

#[derive(Clone, Debug)]
pub struct PartyReport {
    pub party: PartyID,
    pub setup_time: Duration,
    pub total_time: Duration,
    pub timing: GigaDoramTiming,
    pub bytes_sent: usize,
    pub bytes_received: usize,
}

pub fn install_tracing() {
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::{EnvFilter, fmt};

    let fmt_layer = fmt::layer()
        .with_target(false)
        .with_line_number(false)
        .compact();
    let filter_layer = EnvFilter::try_new("info").expect("default tracing filter should be valid");

    let _ = tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt_layer)
        .try_init();
}

pub fn doram_config(config: &DoramBenchmarkConfig) -> Result<GigaDoramConfig> {
    Ok(GigaDoramConfig::new(
        config.log_address_space,
        config.num_levels,
        config.log_amp_factor,
    ))
}

pub fn generate_queries(config: &DoramBenchmarkConfig) -> Vec<BenchmarkQuery> {
    let mut rng = ChaCha20Rng::seed_from_u64(config.seed);
    let address_space_size = 1usize << config.log_address_space;
    (0..config.num_queries)
        .map(|_| BenchmarkQuery {
            x: rng.gen_range(0..address_space_size) as X,
            y: benchmark_y(rng.r#gen()),
            is_write: rng.gen_bool(0.5),
        })
        .collect()
}

pub fn print_startup_config(
    config: &DoramBenchmarkConfig,
    doram_config: GigaDoramConfig,
    transport: &str,
    network: Option<(&Path, &NetworkConfig)>,
) {
    let real_entries = 1usize << config.log_address_space;

    if let Some((network_path, network_config)) = network {
        tracing::info!(
            concat!(
                "\nNetwork\n",
                "|- config: {}\n",
                "|- my_id: {}\n",
                "|- bind_addr: {}\n",
                "`- parties: {}",
            ),
            network_path.display(),
            network_config.my_id,
            network_config.bind_addr,
            network_config.parties.len(),
        );
    }

    tracing::info!(
        concat!(
            "\nStarting DORAM benchmark\n",
            "|- mode: {}\n",
            "|- queries: {}\n",
            "|- seed: {}\n",
            "|- build_bottom_level_at_startup: {}\n",
            "|- log_address_space: {}\n",
            "|- real_entries: {}\n",
            "|- data_block_bits: {}\n",
            "|- num_levels: {}\n",
            "|- log_amp_factor: {}\n",
            "|- amp_factor: {}\n",
            "|- log_speed_cache_size: {}\n",
            "|- speed_cache_size: {}\n",
            "|- fill_time: {}\n",
            "|- stash_size: {}\n",
            "`- bottom_level_entries: {}",
        ),
        transport,
        config.num_queries,
        config.seed,
        config.build_bottom_level_at_startup,
        config.log_address_space,
        real_entries,
        Y_BITS,
        doram_config.num_levels,
        doram_config.log_amp_factor,
        doram_config.amp_factor(),
        doram_config.log_speed_cache_size,
        doram_config.speed_cache_size(),
        doram_config.fill_time(),
        doram_config.stash_size,
        real_entries,
    );
}

pub fn run_party<N: Network>(
    config: &DoramBenchmarkConfig,
    doram_config: GigaDoramConfig,
    queries: &[BenchmarkQuery],
    net: N,
) -> Result<PartyReport> {
    let mut state = Rep3State::new(&net, A2BType::Direct)?;
    let mut timing = GigaDoramTiming::default();
    let mut oracle = HashMap::<X, Y>::new();

    let total_start = Instant::now();
    let setup_start = Instant::now();
    let mut doram = if config.build_bottom_level_at_startup {
        let bottom_num_elements = 1usize << config.log_address_space;
        let ys = (0..bottom_num_elements)
            .map(|y| promote_public_y(state.id, benchmark_y(y as u64)))
            .collect::<Vec<_>>();
        GigaDoram::new_with_initial_bottom_level(
            doram_config,
            ys,
            &net,
            &mut state,
            Some(&mut timing),
        )?
    } else {
        GigaDoram::new(doram_config, state.id)
    };
    let setup_time = setup_start.elapsed();

    for query in queries {
        let initial_value = if config.build_bottom_level_at_startup {
            benchmark_y(query.x as u64)
        } else {
            Y::default()
        };
        let expected = oracle.get(&query.x).copied().unwrap_or(initial_value);
        let x = promote_public(state.id, query.x);

        let result = if query.is_write {
            let y = promote_public_y(state.id, query.y);
            doram.write(x, y, &net, &mut state, Some(&mut timing))?
        } else {
            doram.read(x, &net, &mut state, Some(&mut timing))?
        };

        let opened = open_y(&result, &net);
        ensure!(
            opened == expected,
            "party {:?}: query for x={} returned {:?}, expected {:?}",
            state.id,
            query.x,
            opened,
            expected
        );

        if query.is_write {
            oracle.insert(query.x, query.y);
        }
    }

    let total_time = total_start.elapsed();
    let (bytes_sent, bytes_received) = net
        .get_connection_stats()
        .iter()
        .fold((0, 0), |(sent_acc, recv_acc), (_, (sent, recv))| {
            (sent_acc + sent, recv_acc + recv)
        });

    Ok(PartyReport {
        party: state.id,
        setup_time,
        total_time,
        timing,
        bytes_sent,
        bytes_received,
    })
}

fn benchmark_y(seed: u64) -> Y {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    random_bigint::<YField, _>(&mut rng)
}

pub fn print_report(config: &DoramBenchmarkConfig, report: &PartyReport) {
    let bottom_level = config.num_levels - 1;
    let bottom_build = report
        .timing
        .time_total_builds
        .get(bottom_level)
        .copied()
        .unwrap_or(Duration::ZERO);
    let other_builds = report
        .timing
        .time_total_builds
        .iter()
        .enumerate()
        .filter_map(|(level, duration)| (level != bottom_level).then_some(*duration))
        .sum::<Duration>();
    let queries_per_sec = config.num_queries as f64 / report.total_time.as_secs_f64();
    let bytes_total = report.bytes_sent + report.bytes_received;
    let query_accounted = report.timing.time_total_query_prf
        + report.timing.time_total_query_speed_cache
        + report.timing.time_total_query_ohtable
        + report.timing.time_total_query_writeback;
    let query_other = report
        .timing
        .time_total_queries
        .saturating_sub(query_accounted);

    tracing::info!(
        concat!(
            "\nDORAM benchmark ({:?})\n",
            "|- Parameters\n",
            "|  |- queries: {}\n",
            "|  |- build_bottom_level_at_startup: {}\n",
            "|  |- log_address_space: {}\n",
            "|  |- log_linear_level_size: {}\n",
            "|  |- log_amp_factor: {}\n",
            "|  |- num_levels: {}\n",
            "|  `- data_block_bits: {}\n",
            "|- Timing\n",
            "|  |- total: {}\n",
            "|  |- setup: {}\n",
            "|  |- Build\n",
            "|  |  |- prf_eval: {}\n",
            "|  |  |- batcher_sorting: {}\n",
            "|  |  |- bottom_level: {}\n",
            "|  |  `- other_levels: {}\n",
            "|  `- Query\n",
            "|     |- total: {}\n",
            "|     |- prf_eval: {}\n",
            "|     |- speed_cache: {}\n",
            "|     |- ohtable_levels: {}\n",
            "|     |  |- dummy_cmux: {}\n",
            "|     |  |- tag_reveal: {}\n",
            "|     |  |- cht_lookup: {}\n",
            "|     |  |- receiver_index: {}\n",
            "|     |  `- bookkeeping: {}\n",
            "|     |- writeback: {}\n",
            "|     `- other: {}\n",
            "`- Summary\n",
            "   |- queries_per_sec: {:.2}\n",
            "   |- bytes_sent: {}\n",
            "   |- bytes_received: {}\n",
            "   `- bytes_total: {}",
        ),
        report.party,
        config.num_queries,
        config.build_bottom_level_at_startup,
        config.log_address_space,
        config.log_address_space - (config.num_levels - 1) * config.log_amp_factor,
        config.log_amp_factor,
        config.num_levels,
        Y_BITS,
        format_duration(report.total_time),
        format_duration(report.setup_time),
        format_duration(report.timing.time_total_build_prf),
        format_duration(report.timing.time_total_batcher),
        format_duration(bottom_build),
        format_duration(other_builds),
        format_duration(report.timing.time_total_queries),
        format_duration(report.timing.time_total_query_prf),
        format_duration(report.timing.time_total_query_speed_cache),
        format_duration(report.timing.time_total_query_ohtable),
        format_duration(report.timing.time_total_query_ohtable_details.dummy_cmux),
        format_duration(report.timing.time_total_query_ohtable_details.tag_reveal),
        format_duration(report.timing.time_total_query_ohtable_details.cht_lookup),
        format_duration(
            report
                .timing
                .time_total_query_ohtable_details
                .receiver_index
        ),
        format_duration(report.timing.time_total_query_ohtable_details.bookkeeping),
        format_duration(report.timing.time_total_query_writeback),
        format_duration(query_other),
        queries_per_sec,
        report.bytes_sent,
        report.bytes_received,
        bytes_total,
    );
}

fn format_duration(duration: Duration) -> String {
    format!("{:.3} ms", duration.as_secs_f64() * 1_000.0)
}
