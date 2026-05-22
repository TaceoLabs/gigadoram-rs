use std::time::{Duration, Instant};

use circuits::{
    batcher::Batcher,
    dummy_check::dummy_check_circuit,
    lowmc2::{self as lowmc, ROUND_KEYS},
    replace_if_dummy::replace_if_dummy_circuit,
};
use eyre::{Result, ensure};
use mpc_core::protocols::{
    rep3::{Rep3State, id::PartyID},
    rep3_ring::{
        arithmetic,
        binary::{self, and_with_public, or_public},
        ring::{bit::Bit, ring_impl::RingElement},
    },
};
use mpc_net::Network;
use primitives::{
    ArrayShuffler, BitShare, Block, BlockShare, X, XShare, Y, YShare, bit_to_binary_mask,
    open_many, promote_public, upcast_x_to_block,
};
use structures::{OHTableParams, OhTable, OhTableQueryTiming, OhTableTiming, SpeedCache};

pub const EMPIRICAL_CHT_STASH_SIZE: usize = 8;
pub const PROVEN_CHT_STASH_SIZE: usize = 50;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GigaDoramConfig {
    pub log_address_space_size: usize,
    pub num_levels: usize,
    pub log_speed_cache_size: usize,
    pub log_amp_factor: usize,
    pub stash_size: usize,
}

impl GigaDoramConfig {
    pub fn new(log_address_space_size: usize, num_levels: usize, log_amp_factor: usize) -> Self {
        Self::with_stash_size(
            log_address_space_size,
            num_levels,
            log_amp_factor,
            EMPIRICAL_CHT_STASH_SIZE,
        )
    }

    pub fn with_proven_cht_bounds(
        log_address_space_size: usize,
        num_levels: usize,
        log_amp_factor: usize,
    ) -> Self {
        Self::with_stash_size(
            log_address_space_size,
            num_levels,
            log_amp_factor,
            PROVEN_CHT_STASH_SIZE,
        )
    }

    pub fn with_stash_size(
        log_address_space_size: usize,
        num_levels: usize,
        log_amp_factor: usize,
        stash_size: usize,
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
            self.num_levels < Y::BITS as usize,
            "alibi bits would occupy all of y; reduce num_levels or use a larger Y type"
        );
        assert!(
            self.log_address_space_size < Y::BITS as usize - self.num_levels,
            "user data (up to log_address_space_size bits) would overlap alibi bits stored \
             in the top num_levels bits of y"
        );
        assert_eq!(
            self.log_address_space_size,
            self.log_speed_cache_size + (self.num_levels - 1) * self.log_amp_factor,
            "address-space size must match the bottom-level capacity"
        );
    }
}

#[derive(Clone, Debug)]
pub struct GigaDoram {
    pub config: GigaDoramConfig,
    pub speed_cache: SpeedCache,
    pub levels: Vec<Option<OhTable>>,
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

impl GigaDoram {
    pub fn new(config: GigaDoramConfig) -> Self {
        config.validate();

        let mut speed_cache = SpeedCache::new(config.speed_cache_size());
        speed_cache.skip(config.stash_size);

        Self {
            config,
            speed_cache,
            levels: (0..config.num_levels).map(|_| None).collect(),
            base_b_state_vec: vec![0; config.num_levels],
            had_initial_bottom_level: false,
        }
    }

    pub fn new_with_initial_bottom_level<N: Network>(
        config: GigaDoramConfig,
        ys: Vec<YShare>,
        net: &N,
        state: &mut Rep3State,
        timing: Option<&mut GigaDoramTiming>,
    ) -> Result<Self> {
        config.validate();

        let bottom_num_elements = (1usize << config.log_address_space_size) - 1;
        ensure!(
            ys.len() == bottom_num_elements,
            "initial bottom level must contain exactly every nonzero address"
        );

        let mut doram = Self {
            config,
            speed_cache: SpeedCache::new(config.speed_cache_size()),
            levels: (0..config.num_levels).map(|_| None).collect(),
            base_b_state_vec: vec![0; config.num_levels],
            had_initial_bottom_level: true,
        };

        let bottom_level = doram.config.num_levels - 1;
        let xs = (1..=bottom_num_elements)
            .map(|x| promote_public(state.id, x as X))
            .collect::<Vec<_>>();
        let ys = ys
            .into_iter()
            .map(|y| doram.clear_alibi_bits(y))
            .collect::<Vec<_>>();

        doram.new_ohtable_of_level_inner(bottom_level, xs, ys, net, state, timing)?;
        doram.insert_stash(bottom_level, state.id);

        Ok(doram)
    }

    // Only for tests: calling this leaks that the access pattern is a read.
    #[doc(hidden)]
    pub fn read<N: Network>(
        &mut self,
        query_x: XShare,
        net: &N,
        state: &mut Rep3State,
    ) -> Result<YShare> {
        self.read_and_maybe_write(
            query_x,
            YShare::default(),
            promote_public(state.id, Bit::new(false)),
            net,
            state,
            None,
        )
    }

    // Only for tests: calling this leaks that the access pattern is a write.
    #[doc(hidden)]
    pub fn write<N: Network>(
        &mut self,
        query_x: XShare,
        query_y: YShare,
        net: &N,
        state: &mut Rep3State,
    ) -> Result<YShare> {
        self.read_and_maybe_write(
            query_x,
            query_y,
            promote_public(state.id, Bit::new(true)),
            net,
            state,
            None,
        )
    }

    pub fn num_levels(&self) -> usize {
        self.config.num_levels
    }

    pub fn speed_cache_len(&self) -> usize {
        self.speed_cache.len()
    }

    pub fn read_and_maybe_write<N: Network>(
        &mut self,
        query_x: XShare,
        query_y: YShare,
        is_write: BitShare,
        net: &N,
        state: &mut Rep3State,
        mut timing: Option<&mut GigaDoramTiming>,
    ) -> Result<YShare> {
        // If we need to rebuild before we can query
        if !self.speed_cache.is_writeable() {
            self.rebuild_inner(net, state, timing.as_deref_mut())?;
        }

        let query_start = Instant::now();

        // Compute PRFs for each live level
        let live_levels = self
            .levels
            .iter()
            .enumerate()
            .filter_map(|(level, table)| table.as_ref().map(|_| level))
            .collect::<Vec<_>>();
        let prf_start = Instant::now();
        let qs = self.evaluate_prf_tags(&live_levels, query_x, net, state)?;
        if let Some(timing) = &mut timing {
            timing.time_total_query_prf += prf_start.elapsed();
        }

        // Query the SpeedCache and extract alibi bits
        let speed_cache_start = Instant::now();
        let (mut y_accum, mut found) = self.speed_cache.query(query_x, net, state)?;
        if let Some(timing) = &mut timing {
            timing.time_total_query_speed_cache += speed_cache_start.elapsed();
        }
        let mut alibi_mask = self.extract_alibi_bits(&y_accum);

        // Traverse each live level and query the corresponding table
        for (&level, &q) in live_levels.iter().zip(&qs) {
            let ohtable_start = Instant::now();
            let table = self.levels[level]
                .as_mut()
                .expect("live level should still exist during query");
            let use_dummy = binary::xor(&alibi_mask[level], &found);
            let mut ohtable_timing = OhTableQueryTiming::default();
            let table_timing = timing.is_some().then_some(&mut ohtable_timing);
            let (y_returned, found_returned) =
                table.query_with_timing(q, use_dummy, net, state, table_timing)?;

            y_accum ^= y_returned;
            found ^= found_returned;
            alibi_mask = self.extract_alibi_bits(&y_accum);
            if let Some(timing) = &mut timing {
                timing.time_total_query_ohtable += ohtable_start.elapsed();
                timing
                    .time_total_query_ohtable_details
                    .add_assign(&ohtable_timing);
            }
        }

        // Write the new value (in case of a write) or the old value (in case of a read) to the SpeedCache
        let writeback_start = Instant::now();
        let is_write_mask = bit_to_binary_mask(&is_write);
        let value_to_write = binary::cmux(&is_write_mask, &query_y, &y_accum, net, state)?;
        self.speed_cache
            .write(vec![query_x], vec![self.clear_alibi_bits(value_to_write)]);
        if let Some(timing) = &mut timing {
            timing.time_total_query_writeback += writeback_start.elapsed();
        }

        if let Some(timing) = &mut timing {
            timing.time_total_queries += query_start.elapsed();
        }

        // Reset alibi bits for returned value as well
        Ok(self.clear_alibi_bits(y_accum))
    }

    fn rebuild_inner<N: Network>(
        &mut self,
        net: &N,
        state: &mut Rep3State,
        mut timing: Option<&mut GigaDoramTiming>,
    ) -> Result<()> {
        // Check up to which level we need to rebuild and whether the range is inclusive
        let (rebuild_to, need_to_extract_from_rebuild_to) = self.rebuild_target();

        // Extract from the SpeedCache and reset it
        let (mut extracted_xs, mut extracted_ys) = self.speed_cache.extract();
        self.speed_cache = SpeedCache::new(self.config.speed_cache_size());

        let last_level_to_extract = rebuild_to + usize::from(need_to_extract_from_rebuild_to);
        for level in 0..last_level_to_extract {
            let Some(table) = self.levels[level].as_ref() else {
                continue;
            };

            let mut xs = Vec::new();
            let mut ys = Vec::new();
            table.extract(&mut xs, &mut ys);
            extracted_xs.extend(xs);
            extracted_ys.extend(ys);
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
            *y = self.clear_alibi_bits(*y);
        }

        if rebuild_to == self.config.num_levels - 1 {
            // When there was an initial bottom level, shuffle before cleansing so the
            // subsequent reveal_to_all / open_many inside cleanse_bottom_level_inner is
            // safe: no single party knows the full permutation, so the revealed dummy
            // flags don't expose original positions.
            if self.had_initial_bottom_level {
                let shuffler = ArrayShuffler::new(extracted_xs.len(), state);
                shuffler.forward(&mut extracted_xs, net, state)?;
                shuffler.forward(&mut extracted_ys, net, state)?;
            }

            (extracted_xs, extracted_ys) = self.cleanse_bottom_level_inner(
                extracted_xs,
                extracted_ys,
                net,
                state,
                timing.as_deref_mut(),
            )?;
        } else {
            self.relabel_dummies(&mut extracted_xs, net, state)?;
        }

        for level in 0..rebuild_to {
            self.delete_level(level);
        }
        if need_to_extract_from_rebuild_to {
            self.delete_level(rebuild_to);
        }

        self.new_ohtable_of_level_inner(
            rebuild_to,
            extracted_xs,
            extracted_ys,
            net,
            state,
            timing,
        )?;
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

    fn new_ohtable_of_level_inner<N: Network>(
        &mut self,
        level: usize,
        xs: Vec<XShare>,
        ys: Vec<YShare>,
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

        let mut params =
            OHTableParams::new(xs.len(), self.num_dummies(level), self.config.stash_size);
        params.log_single_col_len = self.cht_log_single_col_len(level);
        let key = Self::generate_prf_key(state);
        let build_start = Instant::now();
        let mut ohtable_timing = OhTableTiming::default();
        let table_timing = timing.is_some().then_some(&mut ohtable_timing);
        let table = OhTable::new(params, xs, ys, key, net, state, table_timing)?;
        if let Some(timing) = &mut timing {
            timing.time_total_build_prf += ohtable_timing.build_prf;
            timing.record_build(level, build_start.elapsed());
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
                .map(|y| self.set_alibi_bit(*y, level, party_id))
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

    fn cht_log_single_col_len(&self, level: usize) -> u32 {
        let base_b_num = if level == self.config.num_levels - 1 {
            1
        } else {
            self.base_b_state_vec[level]
        };
        assert!(base_b_num > 0);

        let expansion = if self.config.stash_size == PROVEN_CHT_STASH_SIZE {
            2.0
        } else {
            1.2
        };
        let expanded_base = (expansion * base_b_num as f64) as usize;
        assert!(expanded_base > 0);

        let base_log = level
            .checked_mul(self.config.log_amp_factor)
            .and_then(|log| log.checked_add(self.config.log_speed_cache_size))
            .expect("CHT column log should fit usize");
        let expanded_log = usize::BITS as usize - expanded_base.leading_zeros() as usize;

        (base_log + expanded_log) as u32
    }

    fn bottom_num_elements(&self) -> usize {
        (1usize << self.config.log_address_space_size) - 1
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

    fn cleanse_bottom_level_inner<N: Network>(
        &self,
        mut xs: Vec<XShare>,
        mut ys: Vec<YShare>,
        net: &N,
        state: &mut Rep3State,
        mut timing: Option<&mut GigaDoramTiming>,
    ) -> Result<(Vec<XShare>, Vec<YShare>)> {
        ensure!(
            xs.len() == ys.len(),
            "bottom cleanse received mismatched x/y lengths"
        );
        let bottom_num_elements = self.bottom_num_elements();

        let mut dummy_flags =
            dummy_check_circuit(&xs, self.config.log_address_space_size, net, state)?;

        // Fast path: caller has already applied an oblivious pre-cleanse shuffle, so
        // revealing dummy flags here is safe — the shuffled positions are independent of
        // the original access pattern (no single party knows the full permutation).
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
        xs.resize(sort_len, XShare::default());
        ys.resize(sort_len, YShare::default());
        dummy_flags.resize(sort_len, promote_public(state.id, Bit::new(true)));
        let batcher_start = Instant::now();
        Batcher::sort_dummies_to_end(&mut dummy_flags, &mut xs, &mut ys, net, state)?;
        if let Some(timing) = &mut timing {
            timing.time_total_batcher += batcher_start.elapsed();
        }

        xs.truncate(bottom_num_elements);
        ys.truncate(bottom_num_elements);
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
        let inputs = vec![upcast_x_to_block(input); levels.len()];
        lowmc::encrypt_many(&keys, &inputs, net, state)
    }

    fn extract_alibi_bits(&self, y: &YShare) -> Vec<BitShare> {
        (0..self.config.num_levels)
            .map(|level| y.get_bit(Y::BITS as usize - 1 - level))
            .collect()
    }

    fn set_alibi_bit(&self, y: YShare, level: usize, party_id: PartyID) -> YShare {
        let mask = 1u64 << (Y::BITS as usize - 1 - level);
        or_public(&y, &RingElement(mask), party_id)
    }

    fn clear_alibi_bits(&self, y: YShare) -> YShare {
        let keep_bits = Y::BITS as usize - self.config.num_levels;
        let mask = if keep_bits == Y::BITS as usize {
            Y::MAX
        } else {
            (1u64 << keep_bits) - 1
        };
        and_with_public(&y, &RingElement(mask))
    }
}
