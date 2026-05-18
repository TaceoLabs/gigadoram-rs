use std::{
    collections::HashMap,
    env,
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use doram::{GigaDoram, GigaDoramConfig, GigaDoramTiming};
use eyre::{Result, WrapErr, bail, ensure, eyre};
use mpc_core::protocols::{
    rep3::{Rep3State, conversion::A2BType, id::PartyID},
    rep3_ring::{binary, ring::bit::Bit},
};
use mpc_net::{Network, local::LocalNetwork};
use primitives::{X, Y, promote_public};

#[derive(Clone, Debug)]
struct BenchmarkConfig {
    num_query_tests: usize,
    log_address_space: usize,
    num_levels: usize,
    log_amp_factor: usize,
    prf_circuit_filename: String,
    build_bottom_level_at_startup: bool,
    num_threads: usize,
    output_dir: PathBuf,
}

#[derive(Clone, Copy, Debug)]
struct Query {
    x: X,
    y: Y,
    is_write: bool,
}

#[derive(Clone, Debug)]
struct PartyReport {
    party: PartyID,
    total_time: Duration,
    timing: GigaDoramTiming,
    total_num_bytes: usize,
}

fn main() -> Result<()> {
    let config = BenchmarkConfig::parse(env::args().skip(1))?;
    let reports = run_benchmark(config.clone())?;

    for report in &reports {
        write_report(&config, report)?;
    }

    println!("Success!");
    for report in &reports {
        println!(
            "Output written to {}",
            report_path(&config.output_dir, report.party).display()
        );
    }

    Ok(())
}

impl BenchmarkConfig {
    fn parse(args: impl IntoIterator<Item = String>) -> Result<Self> {
        let mut num_query_tests = None;
        let mut log_address_space = None;
        let mut num_levels = None;
        let mut log_amp_factor = None;
        let mut prf_circuit_filename = String::from("LowMC_reuse_wires.txt");
        let mut build_bottom_level_at_startup = None;
        let mut num_threads = 1usize;
        let mut output_dir = PathBuf::from(".");

        let args = args.into_iter().collect::<Vec<_>>();
        let mut i = 0;
        while i < args.len() {
            let flag = &args[i];
            if !flag.starts_with("--") {
                i += 1;
                continue;
            }

            let value = args
                .get(i + 1)
                .ok_or_else(|| eyre!("missing value for {flag}"))?;

            match flag.as_str() {
                "--num-query-tests" => num_query_tests = Some(parse_usize(flag, value)?),
                "--log-address-space" => log_address_space = Some(parse_usize(flag, value)?),
                "--num-levels" => num_levels = Some(parse_usize(flag, value)?),
                "--log-amp-factor" => log_amp_factor = Some(parse_usize(flag, value)?),
                "--prf-circuit-filename" => prf_circuit_filename = value.clone(),
                "--build-bottom-level-at-startup" => {
                    build_bottom_level_at_startup = Some(parse_bool(flag, value)?);
                }
                "--num-threads" => num_threads = parse_usize(flag, value)?,
                "--output-dir" => output_dir = PathBuf::from(value),
                other => bail!("unrecognized argument: {other}"),
            }

            i += 2;
        }

        Ok(Self {
            num_query_tests: num_query_tests
                .ok_or_else(|| eyre!("missing argument: --num-query-tests"))?,
            log_address_space: log_address_space
                .ok_or_else(|| eyre!("missing argument: --log-address-space"))?,
            num_levels: num_levels.ok_or_else(|| eyre!("missing argument: --num-levels"))?,
            log_amp_factor: log_amp_factor
                .ok_or_else(|| eyre!("missing argument: --log-amp-factor"))?,
            prf_circuit_filename,
            build_bottom_level_at_startup: build_bottom_level_at_startup
                .ok_or_else(|| eyre!("missing argument: --build-bottom-level-at-startup"))?,
            num_threads,
            output_dir,
        })
    }
}

fn parse_usize(flag: &str, value: &str) -> Result<usize> {
    value
        .parse()
        .with_context(|| format!("invalid integer for {flag}: {value}"))
}

fn parse_bool(flag: &str, value: &str) -> Result<bool> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => bail!("invalid boolean for {flag}: {value}"),
    }
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

    let address_space_size = 1usize
        .checked_shl(config.log_address_space as u32)
        .ok_or_else(|| eyre!("address space is too large"))?;
    ensure!(
        address_space_size > 1,
        "address space must contain at least one nonzero address"
    );

    let queries = generate_queries(config.num_query_tests, address_space_size);
    let [net0, net1, net2] = LocalNetwork::new_3_parties();

    std::thread::scope(|scope| {
        let config = &config;
        let queries = &queries;

        let party0 = scope.spawn(move || run_party(config, doram_config, queries, net0));
        let party1 = scope.spawn(move || run_party(config, doram_config, queries, net1));
        let party2 = scope.spawn(move || run_party(config, doram_config, queries, net2));

        Ok([
            party0.join().unwrap()?,
            party1.join().unwrap()?,
            party2.join().unwrap()?,
        ])
    })
}

fn generate_queries(num_queries: usize, address_space_size: usize) -> Vec<Query> {
    let mut rng = DeterministicRng::new(0x6769_6761_646f_7261);
    (0..num_queries)
        .map(|_| {
            let is_write = rng.next_u64() & 1 == 1;
            let x = rng.sample_nonzero(address_space_size);
            let y = if is_write {
                rng.sample_nonzero(address_space_size) as Y
            } else {
                0
            };

            Query { x, y, is_write }
        })
        .collect()
}

fn run_party(
    config: &BenchmarkConfig,
    doram_config: GigaDoramConfig,
    queries: &[Query],
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
        GigaDoram::new_with_initial_bottom_level_timed(
            doram_config,
            ys,
            &net,
            &mut state,
            &mut timing,
        )?
    } else {
        GigaDoram::new(doram_config)
    };

    for query in queries {
        let initial_value = if config.build_bottom_level_at_startup {
            query.x as Y
        } else {
            0
        };
        let expected = oracle.get(&query.x).copied().unwrap_or(initial_value);

        let result = doram.read_and_maybe_write_timed(
            promote_public(state.id, query.x),
            promote_public(state.id, query.y),
            promote_public(state.id, Bit::new(query.is_write)),
            &net,
            &mut state,
            &mut timing,
        )?;
        let opened = binary::open(&result, &net)?.0;
        ensure!(
            opened == expected,
            "party {:?}: query for x={} returned {}, expected {}",
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

    let mut file = File::create(report_path(&config.output_dir, report.party))?;
    let bottom_level = config.num_levels - 1;
    let bottom_build = build_time(&report.timing, bottom_level);
    let other_builds = report
        .timing
        .time_total_builds
        .iter()
        .enumerate()
        .filter_map(|(level, duration)| (level != bottom_level).then_some(*duration))
        .sum::<Duration>();
    let queries_per_sec = config.num_query_tests as f64 / report.total_time.as_secs_f64();

    writeln!(file, "DORAM Parameters")?;
    writeln!(file, "Number of queries: {}", config.num_query_tests)?;
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
    writeln!(file, "PRF circuit file: {}", config.prf_circuit_filename)?;
    writeln!(file, "Num threads: {}", config.num_threads)?;
    writeln!(file)?;
    writeln!(file, "Timing Breakdown")?;
    writeln!(
        file,
        "Total time including builds: {} us",
        duration_us(report.total_time)
    )?;
    writeln!(
        file,
        "Time spent in queries: {} us",
        duration_us(report.timing.time_total_queries)
    )?;
    writeln!(
        file,
        "Time spent in query PRF eval: {} us",
        duration_us(report.timing.time_total_query_prf)
    )?;
    writeln!(
        file,
        "Time spent querying linear level: {} us",
        duration_us(report.timing.time_total_query_speed_cache)
    )?;
    writeln!(
        file,
        "Time spent in build PRF eval: {} us",
        duration_us(report.timing.time_total_build_prf)
    )?;
    writeln!(
        file,
        "Time spent in batcher sorting: {} us",
        duration_us(report.timing.time_total_batcher)
    )?;
    writeln!(
        file,
        "Time spent building bottom level: {} us",
        duration_us(bottom_build)
    )?;
    writeln!(
        file,
        "Time spent building other levels: {} us ",
        duration_us(other_builds)
    )?;
    writeln!(file)?;
    writeln!(file, "SUMMARY")?;
    writeln!(
        file,
        "Total time including builds: {} us ",
        duration_us(report.total_time)
    )?;
    writeln!(
        file,
        "Total number of bytes sent: {}",
        report.total_num_bytes
    )?;
    writeln!(file, "Queries/sec: {queries_per_sec}")?;

    Ok(())
}

fn build_time(timing: &GigaDoramTiming, level: usize) -> Duration {
    timing
        .time_total_builds
        .get(level)
        .copied()
        .unwrap_or(Duration::ZERO)
}

fn duration_us(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1_000_000.0
}

fn report_path(output_dir: &Path, party: PartyID) -> PathBuf {
    output_dir.join(format!("doram_timing_report{}.txt", party_number(party)))
}

fn party_number(party: PartyID) -> usize {
    match party {
        PartyID::ID0 => 1,
        PartyID::ID1 => 2,
        PartyID::ID2 => 3,
    }
}

struct DeterministicRng {
    state: u64,
}

impl DeterministicRng {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self
            .state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.state
    }

    fn sample_nonzero(&mut self, address_space_size: usize) -> X {
        let num_nonzero = address_space_size - 1;
        (self.next_u64() as usize % num_nonzero + 1) as X
    }
}
