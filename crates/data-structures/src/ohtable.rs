use std::time::{Duration, Instant};

use circuits::lowmc::{self, ROUND_KEYS};
use eyre::Ok;
use mpc_core::protocols::{
    rep3::{Rep3State, id::PartyID, network::Rep3NetworkExt},
    rep3_ring::{
        arithmetic::{self},
        binary,
        casts::downcast,
        ring::ring_impl::RingElement,
    },
};
use mpc_net::Network;
use primitives::{
    ArrayShuffler, Block, BlockShare, LocalPermutation, XShare, YShare, bit_to_binary_mask,
    downcast_many, reshare_3_to_2, reveal_to_party, set_low_u32,
    types::{BitShare, input},
    upcast_x_to_block_many, upcast_y_to_block_many,
};

use crate::cht;
pub type OhTableParams = OHTableParams;
pub type ObliviousHashTable = OhTable;

pub const BUILDER_ID: PartyID = PartyID::ID0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OHTableParams {
    pub num_elements: usize,
    pub num_dummies: usize,
    pub stash_size: usize,
    pub builder: PartyID,
    pub log_single_col_len: u32,
}

impl OHTableParams {
    pub fn new(
        num_elements: usize,
        num_dummies: usize,
        stash_size: usize,
        log_single_col_len: u32,
    ) -> Self {
        Self {
            num_elements,
            num_dummies,
            stash_size,
            builder: BUILDER_ID,
            log_single_col_len,
        }
    }

    pub fn validate(&self) {
        assert!(
            self.stash_size <= self.num_elements,
            "stash cannot be larger than the number of real elements"
        );
        assert!(
            self.cht_full_table_length() >= self.total_size(),
            "CHT table must be large enough for all real and dummy entries"
        );
    }

    pub fn total_size(&self) -> usize {
        self.num_elements + self.num_dummies
    }

    pub fn cht_full_table_length(&self) -> usize {
        2usize << self.log_single_col_len
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OhTable {
    pub params: OHTableParams,
    pub key: Vec<BlockShare>,
    pub stash_xs: Vec<XShare>,
    pub stash_ys: Vec<YShare>,
    pub builder_stash_indices: Vec<usize>,
    pub qs_builder_order: Vec<BlockShare>,
    pub xs_builder_order: Vec<XShare>,
    pub ys_builder_order: Vec<YShare>,
    pub dummy_indices: Vec<XShare>,
    pub xs_receiver_order: Vec<XShare>,
    pub ys_receiver_order: Vec<YShare>,
    pub cht_2shares: Option<Vec<Block>>,
    pub receiver_shuffle: Option<LocalPermutation>,
    pub query_count: usize,
    pub touched: Vec<bool>,
    pub last_query_trace: Option<OhTableQueryTrace>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OhTableQueryTrace {
    pub old_query_count: usize,
    pub selected_receiver_index: usize,
    pub was_touched_before: bool,
}

#[derive(Clone, Debug, Default)]
pub struct OhTableTiming {
    pub build_prf: Duration,
}

#[derive(Clone, Debug, Default)]
pub struct OhTableQueryTiming {
    pub dummy_cmux: Duration,
    pub tag_reveal: Duration,
    pub cht_lookup: Duration,
    pub receiver_index: Duration,
    pub bookkeeping: Duration,
}

impl OhTableQueryTiming {
    pub fn add_assign(&mut self, other: &Self) {
        self.dummy_cmux += other.dummy_cmux;
        self.tag_reveal += other.tag_reveal;
        self.cht_lookup += other.cht_lookup;
        self.receiver_index += other.receiver_index;
        self.bookkeeping += other.bookkeeping;
    }
}

impl OhTable {
    pub fn new<N: Network>(
        params: OHTableParams,
        xs: Vec<XShare>,
        ys: Vec<YShare>,
        key: Vec<BlockShare>,
        net: &N,
        state: &mut Rep3State,
        timing: Option<&mut OhTableTiming>,
    ) -> Self {
        params.validate();
        assert_eq!(xs.len(), params.num_elements);
        assert_eq!(ys.len(), params.num_elements);
        assert_eq!(key.len(), ROUND_KEYS);

        let mut table = Self {
            params,
            key,
            stash_xs: vec![XShare::zero_share(); params.stash_size],
            stash_ys: vec![YShare::zero_share(); params.stash_size],
            builder_stash_indices: vec![0; params.stash_size],
            qs_builder_order: vec![BlockShare::zero_share(); params.total_size()],
            xs_builder_order: vec![XShare::zero_share(); params.total_size()],
            ys_builder_order: vec![YShare::zero_share(); params.total_size()],
            dummy_indices: vec![XShare::zero_share(); params.num_dummies],
            xs_receiver_order: vec![XShare::zero_share(); params.total_size()],
            ys_receiver_order: vec![YShare::zero_share(); params.total_size()],
            cht_2shares: None,
            receiver_shuffle: None,
            query_count: 0,
            touched: vec![false; params.total_size()],
            last_query_trace: None,
        };

        table
            .build(xs, ys, net, state, timing)
            .expect("OHTable build should succeed");
        table
    }

    pub fn build<N: Network>(
        &mut self,
        xs: Vec<XShare>,
        ys: Vec<YShare>,
        net: &N,
        state: &mut Rep3State,
        mut timing: Option<&mut OhTableTiming>,
    ) -> eyre::Result<()> {
        assert_eq!(xs.len(), self.params.num_elements);
        assert_eq!(ys.len(), self.params.num_elements);

        // Evaluate PRF tags.
        let start = Instant::now();
        self.fill_prf_tags(&xs, net, state)?;
        if let Some(timing) = &mut timing {
            timing.build_prf += start.elapsed();
        }

        // Shuffle tags, payloads, and source indices into builder order.
        self.shuffle_builder_order(xs, ys, net, state)?;

        // Build the CHT from revealed builder-order tags.
        let stashed_indices = self.build_cht(net, state)?;

        // Shuffle payloads into receiver order.
        let receiver_shuffle = self.shuffle_receiver_order(net, state)?;

        // Move stashed entries into receiver-order stash slots.
        self.place_stash(stashed_indices, receiver_shuffle, net, state)?;

        Ok(())
    }

    pub fn query<N: Network>(
        &mut self,
        q: BlockShare,
        use_dummy: BitShare,
        net: &N,
        state: &mut Rep3State,
        mut timing: Option<&mut OhTableQueryTiming>,
    ) -> eyre::Result<(YShare, BitShare)> {
        assert!(self.query_count < self.params.num_dummies);

        // TODO: Maybe just pass dummy as a Block
        let start = Instant::now();
        let use_dummy = bit_to_binary_mask(&use_dummy);
        let q_or_dummy = binary::cmux(&use_dummy, &arithmetic::rand(state), &q, net, state)?;
        if let Some(timing) = &mut timing {
            timing.dummy_cmux += start.elapsed();
        }

        let start = Instant::now();
        let q_clear = reveal_to_receivers(&q_or_dummy, self.params.builder, net, state)?;
        if let Some(timing) = &mut timing {
            timing.tag_reveal += start.elapsed();
        }

        let start = Instant::now();
        let old_query_count = self.query_count;
        let dummy_index = downcast(self.dummy_indices[old_query_count]);

        let lookup_result = cht::lookup_from_2shares(
            self.params.log_single_col_len,
            self.cht_2shares.as_ref().unwrap(),
            q_clear.0,
            dummy_index,
            self.params.builder,
            net,
            state,
        )?;
        if let Some(timing) = &mut timing {
            timing.cht_lookup += start.elapsed();
        }

        let start = Instant::now();
        let index_receiver_order = if state.id != self.params.builder {
            let receiver_shuffle = self
                .receiver_shuffle
                .as_mut()
                .expect("OHTable must be built before querying");
            let index_receiver_order = receiver_shuffle.evaluate_at(lookup_result.index);

            if state.id == self.params.builder.prev() {
                net.send_next(index_receiver_order)
                    .expect("should send index to receiver");
            }
            index_receiver_order
        } else {
            net.recv_prev()?
        };
        if let Some(timing) = &mut timing {
            timing.receiver_index += start.elapsed();
        }

        let start = Instant::now();
        let was_touched_before = self.touched[index_receiver_order];
        assert!(!was_touched_before);
        self.touched[index_receiver_order] = true;

        self.query_count += 1;
        self.last_query_trace = Some(OhTableQueryTrace {
            old_query_count,
            selected_receiver_index: index_receiver_order,
            was_touched_before,
        });
        if let Some(timing) = &mut timing {
            timing.bookkeeping += start.elapsed();
        }

        Ok((
            self.ys_receiver_order[index_receiver_order],
            lookup_result.found,
        ))
    }

    pub fn extract(&self, extract_xs: &mut Vec<XShare>, extract_ys: &mut Vec<YShare>) {
        assert_eq!(self.query_count, self.params.num_dummies);

        extract_xs.clear();
        extract_ys.clear();
        extract_xs.reserve(self.params.num_elements - self.params.stash_size);
        extract_ys.reserve(self.params.num_elements - self.params.stash_size);

        for (i, touched) in self.touched.iter().copied().enumerate() {
            if touched {
                continue;
            }
            extract_xs.push(self.xs_receiver_order[i]);
            extract_ys.push(self.ys_receiver_order[i]);
        }

        assert_eq!(
            extract_xs.len(),
            self.params.num_elements - self.params.stash_size
        );
        assert_eq!(
            extract_ys.len(),
            self.params.num_elements - self.params.stash_size
        );
    }

    fn fill_prf_tags<N: Network>(
        &mut self,
        xs: &[XShare],
        net: &N,
        state: &mut Rep3State,
    ) -> eyre::Result<()> {
        let inputs = upcast_x_to_block_many(xs);
        let keys = vec![self.key.as_slice(); inputs.len()];
        let qs = lowmc::encrypt_many(&keys, &inputs, net, state)?;
        self.qs_builder_order[..self.params.num_elements].copy_from_slice(&qs);
        Ok(())
    }

    fn shuffle_builder_order<N: Network>(
        &mut self,
        xs: Vec<XShare>,
        ys: Vec<YShare>,
        net: &N,
        state: &mut Rep3State,
    ) -> eyre::Result<()> {
        self.xs_builder_order[..self.params.num_elements].clone_from_slice(&xs);
        self.ys_builder_order[..self.params.num_elements].clone_from_slice(&ys);

        let mut xs_blocks = upcast_x_to_block_many(&self.xs_builder_order);
        let mut ys_blocks = upcast_y_to_block_many(&self.ys_builder_order);
        let mut indices = (0..self.params.total_size())
            .map(|i| binary::promote_to_trivial_share(state.id, &RingElement(i as Block)))
            .collect::<Vec<_>>();

        ArrayShuffler::new(self.params.total_size(), state).shuffle_many(
            &mut [
                self.qs_builder_order.as_mut_slice(),
                xs_blocks.as_mut_slice(),
                ys_blocks.as_mut_slice(),
            ],
            &mut [indices.as_mut_slice()],
            net,
            state,
        )?;

        self.xs_builder_order = downcast_many(xs_blocks);
        self.ys_builder_order = downcast_many(ys_blocks);
        self.dummy_indices = downcast_many(indices[self.params.num_elements..].to_vec());
        Ok(())
    }

    fn build_cht<N: Network>(
        &mut self,
        net: &N,
        state: &mut Rep3State,
    ) -> eyre::Result<Vec<usize>> {
        let (cht, stashed_indices) = match self.reveal_qs_to_builder(net, state)? {
            Some(qs) => {
                let mut compacted = Vec::with_capacity(self.params.num_elements);
                for (i, q) in qs.into_iter().enumerate() {
                    if q != Block::default() {
                        compacted.push(set_low_u32(q, i as u32));
                    }
                }

                let builder_local_perm = LocalPermutation::new(self.params.num_elements, None);
                builder_local_perm.shuffle(&mut compacted);
                cht::build(
                    self.params.stash_size,
                    self.params.log_single_col_len,
                    &compacted,
                )
            }
            None => cht::dummy(self.params.stash_size, self.params.log_single_col_len),
        };

        let cht_table = cht.into_iter().map(RingElement).collect::<Vec<_>>();
        let cht_shares = input(self.params.builder, &cht_table, net, state)?;
        self.cht_2shares = Some(
            reshare_3_to_2(
                &cht_shares,
                self.params.builder.next(),
                self.params.builder.prev(),
                state,
            )
            .into_iter()
            .map(|share| share.0)
            .collect(),
        );
        Ok(stashed_indices)
    }

    fn shuffle_receiver_order<N: Network>(
        &mut self,
        net: &N,
        state: &mut Rep3State,
    ) -> eyre::Result<Option<LocalPermutation>> {
        self.xs_receiver_order
            .clone_from_slice(&self.xs_builder_order);
        self.ys_receiver_order
            .clone_from_slice(&self.ys_builder_order);

        let mut xs_blocks = upcast_x_to_block_many(&self.xs_receiver_order);
        let mut ys_blocks = upcast_y_to_block_many(&self.ys_receiver_order);
        let receiver_shuffler = ArrayShuffler::new(self.params.total_size(), state);

        receiver_shuffler.forward_many_known_to_p_and_next(
            self.params.builder.next(),
            &mut [xs_blocks.as_mut_slice(), ys_blocks.as_mut_slice()],
            net,
            state,
        )?;

        self.xs_receiver_order = downcast_many(xs_blocks);
        self.ys_receiver_order = downcast_many(ys_blocks);

        Ok(if state.id == self.params.builder {
            None
        } else if state.id == self.params.builder.next() {
            Some(receiver_shuffler.next_shared_perm)
        } else {
            Some(receiver_shuffler.prev_shared_perm)
        })
    }

    fn place_stash<N: Network>(
        &mut self,
        stashed_indices: Vec<usize>,
        mut receiver_shuffle: Option<LocalPermutation>,
        net: &N,
        state: &Rep3State,
    ) -> eyre::Result<()> {
        let builder_stash_indices = if state.id == self.params.builder {
            net.send_to(self.params.builder.prev(), stashed_indices.clone())?;
            net.send_to(self.params.builder.next(), stashed_indices.clone())?;
            stashed_indices
        } else {
            net.recv_from(self.params.builder)?
        };

        self.builder_stash_indices = builder_stash_indices.clone();

        let receiver_indices = if state.id == self.params.builder {
            net.recv_from(self.params.builder.prev())?
        } else {
            let receiver_shuffle = receiver_shuffle
                .as_mut()
                .expect("receiver party should have a receiver shuffle");
            let receiver_indices = builder_stash_indices
                .into_iter()
                .map(|i| receiver_shuffle.evaluate_at(i))
                .collect::<Vec<_>>();

            if state.id == self.params.builder.prev() {
                net.send_next(receiver_indices.clone())?;
            }

            receiver_indices
        };

        for (stash_pos, receiver_index) in receiver_indices.into_iter().enumerate() {
            self.touched[receiver_index] = true;
            self.stash_xs[stash_pos] = self.xs_receiver_order[receiver_index];
            self.stash_ys[stash_pos] = self.ys_receiver_order[receiver_index];
        }

        self.receiver_shuffle = receiver_shuffle;
        Ok(())
    }

    fn reveal_qs_to_builder<N: Network>(
        &self,
        net: &N,
        state: &mut Rep3State,
    ) -> eyre::Result<Option<Vec<Block>>> {
        if state.id == self.params.builder {
            let prev_b = net.recv_from::<Vec<RingElement<Block>>>(self.params.builder.prev())?;
            Ok(Some(
                self.qs_builder_order
                    .iter()
                    .zip(prev_b.iter())
                    .map(|(own, prev_b)| (own.a ^ own.b ^ *prev_b).0)
                    .collect(),
            ))
        } else if state.id == self.params.builder.prev() {
            net.send_to(
                self.params.builder,
                self.qs_builder_order
                    .iter()
                    .map(|q| q.b)
                    .collect::<Vec<_>>(),
            )?;
            Ok(None)
        } else {
            Ok(None)
        }
    }
}

fn reveal_to_receivers<N: Network>(
    share: &BlockShare,
    builder: PartyID,
    net: &N,
    state: &Rep3State,
) -> eyre::Result<RingElement<Block>> {
    let prev_open = reveal_to_party(share, builder.prev(), net, state)?;
    let next_open = reveal_to_party(share, builder.next(), net, state)?;

    if state.id == builder.prev() {
        Ok(prev_open.expect("previous receiver should reconstruct the query tag"))
    } else if state.id == builder.next() {
        Ok(next_open.expect("next receiver should reconstruct the query tag"))
    } else {
        Ok(RingElement(0))
    }
}
