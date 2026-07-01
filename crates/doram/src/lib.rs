//! GigaDoram: a three-party distributed oblivious RAM.
//!
//! [`GigaDoram`] is generic over the stored value type `V: DoramValue`, so the
//! same protocol serves `u32`/`u64`/`u128` and field `BigInt` values. Aliases
//! are exported for the common choices: [`GigaDoramU32`], [`GigaDoramU64`],
//! [`GigaDoramU128`], [`GigaDoramField`], and [`GigaDoramBn254`].
//!
//! A DORAM is built from a small writable [`SpeedCache`] in front of a stack of
//! oblivious hash table levels ([`OhTable`]); [`GigaDoram::read`] and
//! [`GigaDoram::write`] are the entry points, rebuilding levels as needed.

use std::time::{Duration, Instant};

use circuits::{
    lowmc::{self, ROUND_KEYS, packed_u8_lanes_with_speed_cache::SpeedCachePrecomputeData},
    oblivious_sort::ObliviousSort,
    replace_if_dummy::replace_if_dummy_circuit,
};
use data_structures::{OHTableParams, OhTable, OhTableQueryTiming, OhTableTiming, SpeedCache};
use eyre::{Result, ensure};
use mpc_core::protocols::{
    rep3::{Rep3State, id::PartyID},
    rep3_ring::{arithmetic, binary, ring::bit::Bit},
};
use mpc_net::Network;
use primitives::{
    AlibiShare, ArrayShuffler, Block, BlockShare, DoramValue, Record, X, XShare, alibi_from_blocks,
    alibi_to_blocks, dummy_x, open_many, promote_public, upcast_x_to_block,
};

/// `GigaDoram` storing `u32` values.
pub type GigaDoramU32 = GigaDoram<u32>;
/// `GigaDoram` storing `u64` values.
pub type GigaDoramU64 = GigaDoram<u64>;
/// `GigaDoram` storing `u128` values.
pub type GigaDoramU128 = GigaDoram<u128>;
/// `GigaDoram` storing a prime field's `BigInt` values.
pub type GigaDoramField<F> = GigaDoram<primitives::FieldValue<F>>;
/// `GigaDoram` storing `ark_bn254::Fr` field values (the historical default).
pub type GigaDoramBn254 = GigaDoramField<primitives::YField>;

pub const EMPIRICAL_CHT_STASH_SIZE: usize = 8;
pub const PROVEN_CHT_STASH_SIZE: usize = 50;

/// Which cuckoo-hash-table analysis the stash size and column lengths are
/// based on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChtBounds {
    /// Empirically chosen stash size with column load factor 1.2.
    Empirical,
    /// Proven stash bound with column load factor 2.0.
    Proven,
}

impl ChtBounds {
    fn stash_size(self) -> usize {
        match self {
            Self::Empirical => EMPIRICAL_CHT_STASH_SIZE,
            Self::Proven => PROVEN_CHT_STASH_SIZE,
        }
    }

    fn column_load_factor(self) -> f64 {
        match self {
            Self::Empirical => 1.2,
            Self::Proven => 2.0,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GigaDoramConfig {
    pub log_address_space_size: usize,
    pub num_levels: usize,
    pub log_speed_cache_size: usize,
    pub log_amp_factor: usize,
    pub stash_size: usize,
    pub cht_bounds: ChtBounds,
}

impl GigaDoramConfig {
    pub fn new(log_address_space_size: usize, num_levels: usize, log_amp_factor: usize) -> Self {
        Self::with_cht_bounds(
            log_address_space_size,
            num_levels,
            log_amp_factor,
            ChtBounds::Empirical,
        )
    }

    pub fn with_proven_cht_bounds(
        log_address_space_size: usize,
        num_levels: usize,
        log_amp_factor: usize,
    ) -> Self {
        Self::with_cht_bounds(
            log_address_space_size,
            num_levels,
            log_amp_factor,
            ChtBounds::Proven,
        )
    }

    pub fn with_cht_bounds(
        log_address_space_size: usize,
        num_levels: usize,
        log_amp_factor: usize,
        cht_bounds: ChtBounds,
    ) -> Self {
        Self::with_stash_size(
            log_address_space_size,
            num_levels,
            log_amp_factor,
            cht_bounds.stash_size(),
            cht_bounds,
        )
    }

    pub fn with_stash_size(
        log_address_space_size: usize,
        num_levels: usize,
        log_amp_factor: usize,
        stash_size: usize,
        cht_bounds: ChtBounds,
    ) -> Self {
        assert!(num_levels > 0, "DORAM must have at least one OHTable level");

        let x = (num_levels - 1)
            .checked_mul(log_amp_factor)
            .expect("level span should fit usize");
        let log_speed_cache_size = log_address_space_size
            .checked_sub(x)
            .expect("address-space log is too small for num_levels and amplification");

        let config = Self {
            log_address_space_size,
            num_levels,
            log_speed_cache_size,
            log_amp_factor,
            stash_size,
            cht_bounds,
        };
        config.validate();
        config
    }

    pub fn speed_cache_size(&self) -> usize {
        1usize << self.log_speed_cache_size
    }

    pub fn fill_time(&self) -> usize {
        self.speed_cache_size() - self.stash_size
    }

    pub fn amp_factor(&self) -> usize {
        1usize << self.log_amp_factor
    }

    pub fn validate(&self) {
        assert!(
            self.num_levels > 0,
            "DORAM must have at least one OHTable level"
        );
        assert!(
            self.log_address_space_size < X::BITS as usize,
            "must reserve 2^N..2^(N+1)-1 as dummy labels inside x"
        );
        assert!(
            self.log_speed_cache_size < usize::BITS as usize,
            "speed-cache size shift is too large"
        );
        assert!(
            self.log_amp_factor < usize::BITS as usize,
            "amplification factor shift is too large"
        );
        assert!(
            self.stash_size < self.speed_cache_size(),
            "stash must fit inside the speed cache"
        );
        assert!(
            self.num_levels <= u8::BITS as usize,
            "alibi bits must fit in YRecord's alibi byte"
        );
        assert_eq!(
            self.log_address_space_size,
            self.log_speed_cache_size + (self.num_levels - 1) * self.log_amp_factor,
            "address-space size must match the bottom-level capacity"
        );
    }
}

#[derive(Clone, Debug)]
pub struct GigaDoram<V: DoramValue> {
    pub config: GigaDoramConfig,
    pub speed_cache: SpeedCache<V>,
    pub levels: Vec<Option<OhTable<V>>>,
    pub base_b_state_vec: Vec<usize>,
    had_initial_bottom_level: bool,
}

#[derive(Clone, Debug, Default)]
pub struct GigaDoramTiming {
    pub time_total_builds: Vec<Duration>,
    pub time_total_build_prf: Duration,
    pub time_total_batcher: Duration,
    pub time_total_queries: Duration,
    pub time_total_query_prf: Duration,
    pub time_total_query_speed_cache: Duration,
    pub time_total_query_ohtable: Duration,
    pub time_total_query_ohtable_details: OhTableQueryTiming,
    pub time_total_query_writeback: Duration,
}

impl GigaDoramTiming {
    fn record_build(&mut self, level: usize, elapsed: Duration) {
        if self.time_total_builds.len() <= level {
            self.time_total_builds.resize(level + 1, Duration::ZERO);
        }
        self.time_total_builds[level] += elapsed;
    }
}

impl<V: DoramValue> GigaDoram<V> {
    pub fn new(config: GigaDoramConfig, id: PartyID) -> Self {
        config.validate();

        let mut speed_cache =
            SpeedCache::new(config.speed_cache_size(), config.log_address_space_size, id);
        speed_cache.skip(config.stash_size);

        Self {
            config,
            speed_cache,
            levels: vec![None; config.num_levels],
            base_b_state_vec: vec![0; config.num_levels],
            had_initial_bottom_level: false,
        }
    }

    pub fn new_with_initial_bottom_level<N: Network>(
        config: GigaDoramConfig,
        ys: Vec<V::Share>,
        net: &N,
        state: &mut Rep3State,
        timing: Option<&mut GigaDoramTiming>,
    ) -> Result<Self> {
        config.validate();

        let bottom_num_elements = 1usize << config.log_address_space_size;
        ensure!(
            ys.len() == bottom_num_elements,
            "initial bottom level must contain exactly every address in [0, 2^N)"
        );

        let mut doram = Self {
            config,
            speed_cache: SpeedCache::new(
                config.speed_cache_size(),
                config.log_address_space_size,
                state.id,
            ),
            levels: vec![None; config.num_levels],
            base_b_state_vec: vec![0; config.num_levels],
            had_initial_bottom_level: true,
        };

        let bottom_level = doram.config.num_levels - 1;
        let xs = (0..bottom_num_elements)
            .map(|x| promote_public(state.id, x as X))
            .collect::<Vec<_>>();
        let ys = ys
            .into_iter()
            .map(Record::<V>::from_value)
            .collect::<Vec<_>>();

        doram.new_ohtable_of_level(bottom_level, xs, ys, net, state, timing)?;
        doram.insert_stash(bottom_level, state.id);

        Ok(doram)
    }

    /// WARN: This leaks that the access is a read
    pub fn read<N: Network>(
        &mut self,
        query_x: XShare,
        net: &N,
        state: &mut Rep3State,
        timing: Option<&mut GigaDoramTiming>,
    ) -> Result<V::Share> {
        self.read_and_maybe_write(query_x, None, net, state, timing)
    }

    /// WARN: This leaks that the access is a write
    pub fn write<N: Network>(
        &mut self,
        query_x: XShare,
        query_y: V::Share,
        net: &N,
        state: &mut Rep3State,
        timing: Option<&mut GigaDoramTiming>,
    ) -> Result<V::Share> {
        self.read_and_maybe_write(query_x, Some(query_y), net, state, timing)
    }

    pub fn num_levels(&self) -> usize {
        self.config.num_levels
    }

    pub fn speed_cache_len(&self) -> usize {
        self.speed_cache.num_stored
    }

    fn read_and_maybe_write<N: Network>(
        &mut self,
        query_x: XShare,
        write_y: Option<V::Share>,
        net: &N,
        state: &mut Rep3State,
        mut timing: Option<&mut GigaDoramTiming>,
    ) -> Result<V::Share> {
        // If we need to rebuild before we can query
        if !self.speed_cache.is_writeable() {
            self.rebuild(net, state, timing.as_deref_mut())?;
        }

        let query_start = Instant::now();

        // Compute PRFs for each live level
        let live_levels = self
            .levels
            .iter()
            .enumerate()
            .filter_map(|(level, table)| table.as_ref().map(|_| level))
            .collect::<Vec<_>>();
        let mut speed_cache_precompute_data = self.speed_cache.precompute_query(query_x);
        let start = Instant::now();
        let qs = self.evaluate_prf_tags(
            &live_levels,
            query_x,
            speed_cache_precompute_data.as_mut(),
            net,
            state,
        )?;
        if let Some(timing) = &mut timing {
            timing.time_total_query_prf += start.elapsed();
        }

        // Query the SpeedCache and extract alibi bits
        let start = Instant::now();
        let (mut y_accum, mut found) =
            self.speed_cache
                .query(query_x, speed_cache_precompute_data, net, state)?;
        if let Some(timing) = &mut timing {
            timing.time_total_query_speed_cache += start.elapsed();
        }
        let mut alibi_mask = y_accum.get_alibi_bits(self.config.num_levels);

        // Traverse each live level and query the corresponding table
        for (&level, &q) in live_levels.iter().zip(&qs) {
            let start = Instant::now();
            let use_dummy = binary::xor(&alibi_mask[level], &found);
            let table = self.levels[level]
                .as_mut()
                .expect("live level should still exist during query");
            let mut ohtable_timing = OhTableQueryTiming::default();
            let table_timing = timing.is_some().then_some(&mut ohtable_timing);
            let (y_returned, found_returned) =
                table.query(q, use_dummy, net, state, table_timing)?;

            y_accum ^= y_returned;
            found ^= found_returned;
            alibi_mask = y_accum.get_alibi_bits(self.config.num_levels);
            if let Some(timing) = &mut timing {
                timing.time_total_query_ohtable += start.elapsed();
                timing
                    .time_total_query_ohtable_details
                    .add_assign(&ohtable_timing);
            }
        }

        // Write the new value on writes, or refresh the old value on reads.
        // Either way the speed-cache entry starts with a fresh (zero) alibi byte.
        let start = Instant::now();
        let value_to_write = Record::<V>::from_value(write_y.unwrap_or(y_accum.value));
        self.speed_cache.write(vec![query_x], vec![value_to_write]);
        if let Some(timing) = &mut timing {
            timing.time_total_query_writeback += start.elapsed();
            timing.time_total_queries += query_start.elapsed();
        }

        // Return the full-field value (alibi bits live separately now).
        Ok(y_accum.value)
    }

    fn rebuild<N: Network>(
        &mut self,
        net: &N,
        state: &mut Rep3State,
        mut timing: Option<&mut GigaDoramTiming>,
    ) -> Result<()> {
        // Check up to which level we need to rebuild and whether the range is inclusive
        let (rebuild_to, need_to_extract_from_rebuild_to) = self.rebuild_target();

        // Extract from the SpeedCache and reset it
        let (mut extracted_xs, mut extracted_ys) = self.speed_cache.extract();
        self.speed_cache = SpeedCache::new(
            self.config.speed_cache_size(),
            self.config.log_address_space_size,
            state.id,
        );

        let last_level_to_extract = rebuild_to + usize::from(need_to_extract_from_rebuild_to);
        for level in 0..last_level_to_extract {
            let Some(table) = self.levels[level].as_ref() else {
                continue;
            };

            let mut xs = Vec::new();
            let mut ys = Vec::new();
            table.extract(&mut xs, &mut ys);
            let offset = extracted_xs.len();
            let end = offset + self.num_elements_at(level, self.base_b_state_vec[level]);
            // Pad missing entries with the dummy sentinel
            extracted_xs.resize(end, dummy_x(state.id, self.config.log_address_space_size));
            extracted_ys.resize(end, Record::<V>::default());
            extracted_xs[offset..offset + xs.len()].clone_from_slice(&xs);
            extracted_ys[offset..offset + ys.len()].clone_from_slice(&ys);
        }

        ensure!(
            !extracted_xs.is_empty(),
            "rebuild needs at least one extracted item"
        );
        ensure!(
            extracted_xs.len() == extracted_ys.len(),
            "rebuild extracted mismatched x/y lengths"
        );

        for y in extracted_ys.iter_mut() {
            *y = y.clear_alibi();
        }

        if rebuild_to == self.config.num_levels - 1 {
            if self.had_initial_bottom_level {
                let shuffler = ArrayShuffler::new(extracted_xs.len(), state);
                let values = Record::<V>::get_y_values(&extracted_ys);
                let alibis = Record::<V>::get_alibis(&extracted_ys);
                let mut value_blocks = V::to_blocks(&values);
                let mut y_alibi = alibi_to_blocks(&alibis);
                shuffler.forward(&mut extracted_xs, net, state)?;
                for col in value_blocks.iter_mut() {
                    shuffler.forward(col, net, state)?;
                }
                shuffler.forward(&mut y_alibi, net, state)?;
                extracted_ys = Record::<V>::from_columns(
                    V::from_blocks(value_blocks),
                    alibi_from_blocks(y_alibi),
                );
            }

            (extracted_xs, extracted_ys) = self.cleanse_bottom_level(
                extracted_xs,
                extracted_ys,
                net,
                state,
                timing.as_deref_mut(),
            )?;
        } else {
            let target_num_elements =
                self.num_elements_at(rebuild_to, self.base_b_state_vec[rebuild_to] + 1);
            assert_eq!(extracted_xs.len(), target_num_elements);
            self.relabel_dummies(&mut extracted_xs, net, state)?;
        }

        for level in 0..rebuild_to {
            self.delete_level(level);
        }
        if need_to_extract_from_rebuild_to {
            self.delete_level(rebuild_to);
        }

        self.new_ohtable_of_level(rebuild_to, extracted_xs, extracted_ys, net, state, timing)?;
        self.insert_stash(rebuild_to, state.id);

        Ok(())
    }

    fn rebuild_target(&self) -> (usize, bool) {
        let amp_factor = self.config.amp_factor();
        let mut rebuild_to = 0;
        let mut need_to_extract_from_rebuild_to = false;

        while rebuild_to < self.config.num_levels - 1 {
            if self.base_b_state_vec[rebuild_to] < amp_factor - 1 {
                need_to_extract_from_rebuild_to = self.levels[rebuild_to].is_some();
                break;
            }

            rebuild_to += 1;
        }

        if rebuild_to == self.config.num_levels - 1 {
            need_to_extract_from_rebuild_to = self.base_b_state_vec[rebuild_to] != 0;
        }

        (rebuild_to, need_to_extract_from_rebuild_to)
    }

    fn new_ohtable_of_level<N: Network>(
        &mut self,
        level: usize,
        xs: Vec<XShare>,
        ys: Vec<Record<V>>,
        net: &N,
        state: &mut Rep3State,
        mut timing: Option<&mut GigaDoramTiming>,
    ) -> Result<()> {
        assert!(level < self.config.num_levels);
        assert_eq!(xs.len(), ys.len());
        assert!(xs.len() >= self.config.stash_size);

        if level == self.config.num_levels - 1 {
            self.base_b_state_vec[level] = 1;
        } else {
            self.base_b_state_vec[level] += 1;
            assert!(self.base_b_state_vec[level] < self.config.amp_factor());
        }

        let base_b_num = if level == self.config.num_levels - 1 {
            1
        } else {
            self.base_b_state_vec[level]
        };
        let d = self.config.cht_bounds.column_load_factor();
        let log_single_col_len = level * self.config.log_amp_factor
            + self.config.log_speed_cache_size
            + ((d * base_b_num as f64) as usize).ilog2() as usize
            + 1;

        let params = OHTableParams::new(
            xs.len(),
            self.num_dummies(level),
            self.config.stash_size,
            log_single_col_len as u32,
            self.config.log_address_space_size,
        );
        let key = Self::generate_prf_key(state);
        let start = Instant::now();
        let mut ohtable_timing = OhTableTiming::default();
        let table_timing = timing.is_some().then_some(&mut ohtable_timing);
        let table = OhTable::new(params, xs, ys, key, net, state, table_timing);
        if let Some(timing) = &mut timing {
            timing.time_total_build_prf += ohtable_timing.build_prf;
            timing.record_build(level, start.elapsed());
        }
        self.levels[level] = Some(table);

        Ok(())
    }

    fn delete_level(&mut self, level: usize) {
        self.levels[level] = None;
        if level < self.config.num_levels - 1
            && self.base_b_state_vec[level] == self.config.amp_factor() - 1
        {
            self.base_b_state_vec[level] = 0;
        }
    }

    fn insert_stash(&mut self, level: usize, party_id: PartyID) {
        let (stash_xs, stash_ys) = {
            let table = self.levels[level]
                .as_ref()
                .expect("newly rebuilt level should exist");
            let stash_ys = table
                .stash_ys
                .iter()
                .map(|y| y.set_alibi_bit(level, party_id))
                .collect::<Vec<_>>();
            (table.stash_xs.clone(), stash_ys)
        };

        self.speed_cache.write(stash_xs, stash_ys);
    }

    fn num_dummies(&self, level: usize) -> usize {
        self.config
            .amp_factor()
            .pow(level as u32)
            .checked_mul(self.config.fill_time())
            .expect("number of dummies should fit usize")
    }

    fn num_elements_at(&self, level: usize, state: usize) -> usize {
        if level == self.config.num_levels - 1 {
            self.bottom_num_elements()
        } else {
            state << (level * self.config.log_amp_factor + self.config.log_speed_cache_size)
        }
    }

    fn bottom_num_elements(&self) -> usize {
        1usize << self.config.log_address_space_size
    }

    fn dummy_label(&self, offset: usize) -> X {
        let label = (1u64 << self.config.log_address_space_size) + offset as u64;
        assert!(label <= X::MAX as u64, "dummy label must fit x_type");
        label as X
    }

    fn relabel_dummies<N: Network>(
        &self,
        xs: &mut [XShare],
        net: &N,
        state: &mut Rep3State,
    ) -> Result<()> {
        let replacements = xs
            .iter()
            .enumerate()
            .map(|(i, _)| promote_public(state.id, self.dummy_label(i)))
            .collect::<Vec<_>>();
        let relabeled = replace_if_dummy_circuit(
            xs,
            &replacements,
            self.config.log_address_space_size,
            net,
            state,
        )?;
        xs.clone_from_slice(&relabeled);

        Ok(())
    }

    fn cleanse_bottom_level<N: Network>(
        &self,
        mut xs: Vec<XShare>,
        mut ys: Vec<Record<V>>,
        net: &N,
        state: &mut Rep3State,
        mut timing: Option<&mut GigaDoramTiming>,
    ) -> Result<(Vec<XShare>, Vec<Record<V>>)> {
        ensure!(
            xs.len() == ys.len(),
            "bottom cleanse received mismatched x/y lengths"
        );
        let bottom_num_elements = self.bottom_num_elements();

        let mut dummy_flags = xs
            .iter()
            .map(|x| x.get_bit(self.config.log_address_space_size))
            .collect::<Vec<_>>();

        if self.had_initial_bottom_level {
            ensure!(
                xs.len() >= bottom_num_elements,
                "initial bottom cleanse needs enough extracted entries for the bottom level"
            );

            let dummy_flags = open_many(&dummy_flags, net);
            let mut cleansed_xs = Vec::with_capacity(bottom_num_elements);
            let mut cleansed_ys = Vec::with_capacity(bottom_num_elements);

            for ((x, y), is_dummy) in xs.into_iter().zip(ys).zip(dummy_flags) {
                if !is_dummy.convert() {
                    cleansed_xs.push(x);
                    cleansed_ys.push(y);
                }
            }

            ensure!(
                cleansed_xs.len() == bottom_num_elements,
                "initial bottom cleanse found wrong number of real entries"
            );

            return Ok((cleansed_xs, cleansed_ys));
        }

        let sort_len = xs.len().next_power_of_two();
        let mut values = Record::<V>::get_y_values(&ys);
        let mut alibis = Record::<V>::get_alibis(&ys);
        xs.resize(
            sort_len,
            dummy_x(state.id, self.config.log_address_space_size),
        );
        values.resize(sort_len, V::zero_share());
        alibis.resize(sort_len, AlibiShare::default());
        dummy_flags.resize(sort_len, promote_public(state.id, Bit::new(true)));
        let start = Instant::now();
        ObliviousSort::sort::<V, _>(
            &mut dummy_flags,
            &mut xs,
            &mut values,
            &mut alibis,
            net,
            state,
        )?;
        if let Some(timing) = &mut timing {
            timing.time_total_batcher += start.elapsed();
        }

        xs.truncate(bottom_num_elements);
        values.truncate(bottom_num_elements);
        alibis.truncate(bottom_num_elements);
        ys = Record::<V>::from_columns(values, alibis);
        self.relabel_dummies(&mut xs, net, state)?;

        Ok((xs, ys))
    }

    fn generate_prf_key(state: &mut Rep3State) -> Vec<BlockShare> {
        (0..ROUND_KEYS)
            .map(|_| arithmetic::rand::<Block>(state))
            .collect()
    }

    fn evaluate_prf_tags<N: Network>(
        &self,
        levels: &[usize],
        input: XShare,
        speed_cache_precompute_data: Option<&mut SpeedCachePrecomputeData<V>>,
        net: &N,
        state: &mut Rep3State,
    ) -> Result<Vec<BlockShare>> {
        let keys = levels
            .iter()
            .map(|&level| {
                let table = self.levels[level]
                    .as_ref()
                    .expect("live level should have an OHTable");
                assert_eq!(table.key.len(), ROUND_KEYS);
                table.key.as_slice()
            })
            .collect::<Vec<_>>();
        lowmc::packed_u8_lanes_with_speed_cache::encrypt_many_with_repeated_input(
            &keys,
            upcast_x_to_block(input),
            speed_cache_precompute_data,
            net,
            state,
        )
    }
}
