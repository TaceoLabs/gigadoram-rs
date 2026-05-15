use circuits::lowmc::{self, ROUND_KEYS};
use eyre::{Result, ensure};
use mpc_core::protocols::{
    rep3::{Rep3State, id::PartyID},
    rep3_ring::{
        arithmetic,
        binary::{self, and_with_public, or_public},
        ring::ring_impl::RingElement,
    },
};
use mpc_net::Network;
use primitives::{BitShare, Block, BlockShare, XShare, Y, YShare, upcast_x_to_block};
use structures::{OHTableParams, OhTable, SpeedCache};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GigaDoramConfig {
    pub num_levels: usize,
    pub log_stupid_level_size: usize,
    pub log_amp_factor: usize,
    pub stash_size: usize,
}

impl GigaDoramConfig {
    pub fn speed_cache_size(&self) -> usize {
        1usize << self.log_stupid_level_size
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
            self.log_stupid_level_size < usize::BITS as usize,
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
            self.num_levels <= Y::BITS as usize,
            "alibi bits are stored in the high bits of y"
        );
    }
}

#[derive(Clone, Debug)]
pub struct GigaDoram {
    pub config: GigaDoramConfig,
    pub speed_cache: SpeedCache,
    pub levels: Vec<Option<OhTable>>,
    pub base_b_state_vec: Vec<usize>,
}

impl GigaDoram {
    pub fn new(config: GigaDoramConfig) -> Self {
        config.validate();

        let mut speed_cache = SpeedCache::new(config.speed_cache_size());
        // Mirrors the C++ bottomless initialization: reserve room for future stashes.
        speed_cache.skip(config.stash_size);

        Self {
            config,
            speed_cache,
            levels: (0..config.num_levels).map(|_| None).collect(),
            base_b_state_vec: vec![0; config.num_levels],
        }
    }

    pub fn read<N: Network>(
        &mut self,
        query_x: XShare,
        net: &N,
        state: &mut Rep3State,
    ) -> Result<YShare> {
        self.read_and_maybe_write(query_x, None, net, state)
    }

    pub fn write<N: Network>(
        &mut self,
        query_x: XShare,
        query_y: YShare,
        net: &N,
        state: &mut Rep3State,
    ) -> Result<YShare> {
        self.read_and_maybe_write(query_x, Some(query_y), net, state)
    }

    pub fn num_levels(&self) -> usize {
        self.config.num_levels
    }

    pub fn speed_cache_len(&self) -> usize {
        self.speed_cache.len()
    }

    fn read_and_maybe_write<N: Network>(
        &mut self,
        query_x: XShare,
        write_y: Option<YShare>,
        net: &N,
        state: &mut Rep3State,
    ) -> Result<YShare> {
        if !self.speed_cache.is_writeable() {
            self.rebuild(net, state)?;
        }

        let (mut y_accum, mut found) = self.speed_cache.query(query_x, net, state)?;
        let mut alibi_mask = self.extract_alibi_bits(&y_accum);

        let live_levels = self
            .levels
            .iter()
            .enumerate()
            .filter_map(|(level, table)| table.as_ref().map(|_| level))
            .collect::<Vec<_>>();
        let qs = self.evaluate_prf_tags(&live_levels, query_x, net, state)?;

        for (&level, &q) in live_levels.iter().zip(&qs) {
            let table = self.levels[level]
                .as_mut()
                .expect("live level should still exist during query");
            let use_dummy = binary::xor(&alibi_mask[level], &found);
            let (y_returned, found_returned) = table.query(q, use_dummy, net, state)?;

            y_accum ^= y_returned;
            found ^= found_returned;
            alibi_mask = self.extract_alibi_bits(&y_accum);
        }

        let value_to_write = write_y.unwrap_or(y_accum);
        self.speed_cache
            .write(vec![query_x], vec![self.clear_alibi_bits(value_to_write)]);

        Ok(self.clear_alibi_bits(y_accum))
    }

    fn rebuild<N: Network>(&mut self, net: &N, state: &mut Rep3State) -> Result<()> {
        let (rebuild_to, need_to_extract_from_rebuild_to) = self.rebuild_target();

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

        for level in 0..rebuild_to {
            self.delete_level(level);
        }
        if need_to_extract_from_rebuild_to {
            self.delete_level(rebuild_to);
        }

        for y in extracted_ys.iter_mut() {
            *y = self.clear_alibi_bits(*y);
        }

        self.new_ohtable_of_level(rebuild_to, extracted_xs, extracted_ys, net, state)?;
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
        ys: Vec<YShare>,
        net: &N,
        state: &mut Rep3State,
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

        let params = OHTableParams::new(xs.len(), self.num_dummies(level), self.config.stash_size);
        let key = Self::generate_prf_key(state);
        let table = OhTable::new(params, xs, ys, key, net, state);
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
