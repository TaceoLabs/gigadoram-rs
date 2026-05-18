use std::{
    collections::HashMap,
    fs::{self, File},
    io::Write,
    path::PathBuf,
    time::{Duration, Instant},
};

use clap::{ArgAction, Parser};
use doram::{GigaDoram, GigaDoramConfig, GigaDoramTiming};
use eyre::{Result, WrapErr, ensure, eyre};
use mpc_core::protocols::{
    rep3::{Rep3State, conversion::A2BType, id::PartyID},
    rep3_ring::{binary, ring::bit::Bit},
};
use mpc_net::{Network, local::LocalNetwork};
use primitives::{X, Y, promote_public, run_parties};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

#[derive(Clone, Debug, Parser)]
#[command(about = "Run the local three-party DORAM benchmark")]
struct BenchmarkConfig {
    #[arg(long = "num-query-tests", alias = "num-queries")]
    num_queries: usize,
    #[arg(long)]
    log_address_space: usize,
    #[arg(long)]
    num_levels: usize,
    #[arg(long)]
    log_amp_factor: usize,
    #[arg(long, action = ArgAction::Set, default_value_t = false)]
    build_bottom_level_at_startup: bool,
    #[arg(long, default_value = ".")]
    output_dir: PathBuf,
    #[arg(long, default_value = "42")]
    seed: u64,
}

struct PartyReport {
    party: PartyID,
    total_time: Duration,
    timing: GigaDoramTiming,
    total_num_bytes: usize,
}

fn main() -> Result<()> {
    let config = BenchmarkConfig::parse();
    let reports = run_benchmark(config.clone())?;

    for report in &reports {
        write_report(&config, report)?;
    }

    println!("Success!");
    for report in &reports {
        let path = config.output_dir.join(format!(
            "doram_timing_report{}.txt",
            report.party as usize + 1
        ));
        println!("Output written to {}", path.display());
    }

    Ok(())
}

fn run_benchmark(config: BenchmarkConfig) -> Result<[PartyReport; 3]> {
    let doram_config = GigaDoramConfig::new(
        config.log_address_space,
        config.num_levels,
        config.log_amp_factor,
    );

    ensure!(
        config.log_address_space < Y::BITS as usize - doram_config.num_levels,
        "benchmark y values must not overlap DORAM alibi bits"
    );

    let address_space_size = 1usize << config.log_address_space;
    let queries = generate_queries(config.num_queries, address_space_size, config.seed);
    run_parties(|net| run_party(&config, doram_config, &queries, net).wrap_err("party failed"))
        .into_iter()
        .collect::<Result<Vec<_>>>()?
        .try_into()
        .map_err(|_| eyre!("expected exactly 3 party reports"))
}

fn generate_queries(num_queries: usize, address_space_size: usize, seed: u64) -> Vec<(X, Y, bool)> {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    (0..num_queries)
        .map(|_| {
            let is_write = rng.gen_bool(0.5);
            let x = rng.gen_range(1..address_space_size) as X;
            let y = rng.gen_range(1..address_space_size) as Y;
            (x, y, is_write)
        })
        .collect()
}

fn run_party(
    config: &BenchmarkConfig,
    doram_config: GigaDoramConfig,
    queries: &[(X, Y, bool)],
    net: LocalNetwork,
) -> Result<PartyReport> {
    let mut state = Rep3State::new(&net, A2BType::Direct)?;
    let mut timing = GigaDoramTiming::default();
    let mut oracle = HashMap::<X, Y>::new();

    let total_start = Instant::now();
    let mut doram = if config.build_bottom_level_at_startup {
        let bottom_num_elements = (1usize << config.log_address_space) - 1;
        let ys = (1..=bottom_num_elements)
            .map(|y| promote_public(state.id, y as Y))
            .collect::<Vec<_>>();
        GigaDoram::new_with_initial_bottom_level(
            doram_config,
            ys,
            &net,
            &mut state,
            Some(&mut timing),
        )?
    } else {
        GigaDoram::new(doram_config)
    };

    for &(x, y, is_write) in queries {
        let initial_value = if config.build_bottom_level_at_startup {
            x as Y
        } else {
            0
        };
        let expected = oracle.get(&x).copied().unwrap_or(initial_value);

        let result = doram.read_and_maybe_write(
            promote_public(state.id, x),
            promote_public(state.id, y),
            promote_public(state.id, Bit::new(is_write)),
            &net,
            &mut state,
            Some(&mut timing),
        )?;
        
        let opened = binary::open(&result, &net)?.0;
        ensure!(
            opened == expected,
            "party {:?}: query for x={x} returned {opened}, expected {expected}",
            state.id
        );

        if is_write {
            oracle.insert(x, y);
        }
    }

    let total_time = total_start.elapsed();
    let total_num_bytes = net
        .get_connection_stats()
        .iter()
        .map(|(_, (sent, recv))| sent + recv)
        .sum();

    Ok(PartyReport {
        party: state.id,
        total_time,
        timing,
        total_num_bytes,
    })
}

fn write_report(config: &BenchmarkConfig, report: &PartyReport) -> Result<()> {
    fs::create_dir_all(&config.output_dir)
        .with_context(|| format!("failed to create {}", config.output_dir.display()))?;

    let mut file = File::create(config.output_dir.join(format!(
        "doram_timing_report{}.txt",
        report.party as usize + 1
    )))?;
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

    writeln!(file, "DORAM Parameters")?;
    writeln!(file, "Number of queries: {}", config.num_queries)?;
    writeln!(
        file,
        "Build bottom level at startup: {}",
        config.build_bottom_level_at_startup
    )?;
    writeln!(file, "Log address space size: {}", config.log_address_space)?;
    writeln!(file, "Data block size (bits): {}", Y::BITS)?;
    writeln!(
        file,
        "Log linear level size: {}",
        config.log_address_space - (config.num_levels - 1) * config.log_amp_factor
    )?;
    writeln!(file, "Log amp factor: {}", config.log_amp_factor)?;
    writeln!(file, "Num levels: {}", config.num_levels)?;
    writeln!(file)?;
    writeln!(file, "Timing Breakdown")?;
    writeln!(
        file,
        "Total time including builds: {} us",
        report.total_time.as_secs_f64() * 1_000_000.0
    )?;
    writeln!(
        file,
        "Time spent in queries: {} us",
        report.timing.time_total_queries.as_secs_f64() * 1_000_000.0
    )?;
    writeln!(
        file,
        "Time spent in query PRF eval: {} us",
        report.timing.time_total_query_prf.as_secs_f64() * 1_000_000.0
    )?;
    writeln!(
        file,
        "Time spent querying linear level: {} us",
        report.timing.time_total_query_speed_cache.as_secs_f64() * 1_000_000.0
    )?;
    writeln!(
        file,
        "Time spent in build PRF eval: {} us",
        report.timing.time_total_build_prf.as_secs_f64() * 1_000_000.0
    )?;
    writeln!(
        file,
        "Time spent in batcher sorting: {} us",
        report.timing.time_total_batcher.as_secs_f64() * 1_000_000.0
    )?;
    writeln!(
        file,
        "Time spent building bottom level: {} us",
        bottom_build.as_secs_f64() * 1_000_000.0
    )?;
    writeln!(
        file,
        "Time spent building other levels: {} us ",
        other_builds.as_secs_f64() * 1_000_000.0
    )?;
    writeln!(file)?;
    writeln!(file, "SUMMARY")?;
    writeln!(
        file,
        "Total time including builds: {} us ",
        report.total_time.as_secs_f64() * 1_000_000.0
    )?;
    writeln!(
        file,
        "Total number of bytes sent: {}",
        report.total_num_bytes
    )?;
    writeln!(file, "Queries/sec: {queries_per_sec}")?;

    Ok(())
}
