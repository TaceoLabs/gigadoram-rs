use circuits::lowmc::GigadoramLowMc;
use eyre::Ok;
use mpc_core::protocols::{
    rep3::{Rep3State, id::PartyID, network::Rep3NetworkExt},
    rep3_ring::{
        arithmetic::{self},
        binary,
        casts::{cast_gc, downcast},
        ring::ring_impl::RingElement,
    },
};
use mpc_net::Network;
use primitives::{
    ArrayShuffler, Block, BlockShare, LocalPermutation, XShare, Y, YShare, reshare_3_to_2,
    types::{BitShare, input},
};

use crate::cht;

const LOWMC_REUSE_WIRES: &str = include_str!("../../circuits/src/lowmc/LowMC_reuse_wires.txt");

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
    pub key_size_blocks: usize,
}

impl OHTableParams {
    pub fn new(num_elements: usize, num_dummies: usize, stash_size: usize) -> Self {
        let min_full_table_len = num_elements + num_dummies;
        let single_col_len = min_full_table_len.div_ceil(2).next_power_of_two().max(1);

        Self {
            num_elements,
            num_dummies,
            stash_size,
            builder: BUILDER_ID,
            log_single_col_len: single_col_len.trailing_zeros(),
            key_size_blocks: GigadoramLowMc::ROUND_KEYS,
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
    qs_builder_order: Vec<BlockShare>,
    xs_builder_order: Vec<XShare>,
    ys_builder_order: Vec<YShare>,
    dummy_indices: Vec<XShare>,
    xs_receiver_order: Vec<XShare>,
    ys_receiver_order: Vec<YShare>,
    cht_2shares: Option<Vec<Block>>,
    receiver_shuffle: Option<LocalPermutation>,
    query_count: usize,
    touched: Vec<bool>,
}

impl OhTable {
    pub fn new<N: Network>(
        params: OHTableParams,
        xs: Vec<XShare>,
        ys: Vec<YShare>,
        key: Vec<BlockShare>,
        net: &N,
        state: &mut Rep3State,
    ) -> Self {
        params.validate();
        assert_eq!(xs.len(), params.num_elements);
        assert_eq!(ys.len(), params.num_elements);
        if params.key_size_blocks != 0 {
            assert_eq!(key.len(), params.key_size_blocks);
        }

        let mut table = Self {
            params,
            key,
            stash_xs: vec![XShare::zero_share(); params.stash_size],
            stash_ys: vec![YShare::zero_share(); params.stash_size],
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
        };

        table
            .build(xs, ys, net, state)
            .expect("OHTable build should succeed");
        table
    }

    pub fn build<N: Network>(
        &mut self,
        xs: Vec<XShare>,
        ys: Vec<YShare>,
        net: &N,
        state: &mut Rep3State,
    ) -> eyre::Result<()> {
        assert_eq!(xs.len(), self.params.num_elements);
        assert_eq!(ys.len(), self.params.num_elements);

        // compute qs
        let prf_input_size_blocks = self.prf_key_size_blocks() + 1;
        let mut keys_and_inputs =
            vec![BlockShare::zero_share(); prf_input_size_blocks * self.params.num_elements];

        for i in 0..self.params.num_elements {
            let input_offset = prf_input_size_blocks * i;
            keys_and_inputs[input_offset..input_offset + self.prf_key_size_blocks()]
                .copy_from_slice(&self.key);
            let dst_index = prf_input_size_blocks * (i + 1) - 1;

            keys_and_inputs[dst_index] = downcast(xs[i].clone());
        }

        let qs = self.evaluate_prf_tags(keys_and_inputs, net, state)?;
        self.qs_builder_order[..self.params.num_elements].copy_from_slice(&qs);

        let builder_shuffler = ArrayShuffler::new(self.params.total_size(), state);
        self.xs_builder_order[..self.params.num_elements].clone_from_slice(&xs);
        self.ys_builder_order[..self.params.num_elements].clone_from_slice(&ys);
        let mut indices_builder_order = vec![XShare::zero_share(); self.params.total_size()];

        builder_shuffler.forward(&mut self.qs_builder_order, net, state)?;
        builder_shuffler.forward(&mut self.xs_builder_order, net, state)?;
        builder_shuffler.forward(&mut self.ys_builder_order, net, state)?;
        builder_shuffler.indices::<u32, _>(&mut indices_builder_order, net, state)?;

        self.dummy_indices = indices_builder_order[self.params.num_elements..].to_vec();

        let qs_in_clear = self.reveal_qs_to_builder(net, state)?;
        let mut qs_in_clear_compacted = vec![Block::default(); self.params.num_elements];
        let (cht, stashed_indices) = if state.id == self.params.builder {
            let mut j = 0;
            let qs_in_clear = qs_in_clear.expect("builder should receive revealed qs");
            for i in 0..self.params.total_size() {
                if qs_in_clear[i] != Block::default() {
                    qs_in_clear_compacted[j] = attach_index(qs_in_clear[i], i as u32);
                    j += 1;
                }
            }

            assert_eq!(
                j, self.params.num_elements,
                "number of revealed qs should match number of real elements"
            );

            let builder_local_perm = LocalPermutation::new(self.params.num_elements, None);
            builder_local_perm.shuffle(&mut qs_in_clear_compacted);

            cht::build(
                self.params.stash_size,
                self.params.log_single_col_len,
                &qs_in_clear_compacted,
            )
        } else {
            cht::dummy(self.params.stash_size, self.params.log_single_col_len)
        };

        let cht_table = cht
            .iter()
            .map(|&value| RingElement(value))
            .collect::<Vec<_>>();
        let cht_shares = input(self.params.builder, &cht_table, net, state)?;
        self.cht_2shares = Some(
            reshare_3_to_2(&cht_shares, state)
                .iter()
                .map(|share| share.0)
                .collect(),
        );

        self.xs_receiver_order
            .clone_from_slice(&self.xs_builder_order);
        self.ys_receiver_order
            .clone_from_slice(&self.ys_builder_order);
        let mut receiver_shuffler = ArrayShuffler::new(self.params.total_size(), state);
        self.forward_receiver_order_known_to_receivers(&mut receiver_shuffler, net, state)?;
        let mut receiver_shuffle = self.receiver_shuffle_for_party(&receiver_shuffler);

        let stash_indices_builder = self.receive_stash_indices_from_builder(stashed_indices);
        let mut stash_indices_receiver = vec![0; self.params.stash_size];
        for i in 0..self.params.stash_size {
            stash_indices_receiver[i] = receiver_shuffle.evaluate_at(stash_indices_builder[i]);
        }
        let stash_indices_receiver = self.sync_stash_indices_with_builder(stash_indices_receiver);

        // Pretend that stashed indices have already been queried.
        for (stash_pos, &stash_index_receiver_order) in stash_indices_receiver.iter().enumerate() {
            assert!(stash_index_receiver_order < self.params.total_size());
            let stash_index_receiver_order = stash_index_receiver_order;
            self.touched[stash_index_receiver_order] = true;
            self.stash_xs[stash_pos] = self.xs_receiver_order[stash_index_receiver_order].clone();
            self.stash_ys[stash_pos] = self.ys_receiver_order[stash_index_receiver_order].clone();
        }

        self.receiver_shuffle = Some(receiver_shuffle);
        Ok(())
    }

    pub fn query<N: Network>(
        &mut self,
        q: BlockShare,
        use_dummy: BitShare,
        net: &N,
        state: &mut Rep3State,
    ) -> eyre::Result<(YShare, BitShare)> {
        assert!(self.query_count < self.params.num_dummies);

        // TODO: Maybe just pass dummy as a Block
        let use_dummy = cast_gc(use_dummy, net, state)?;

        let q_or_dummy = binary::cmux(&use_dummy, &arithmetic::rand(state), &q, net, state)?;

        let q_clear = if state.id == self.params.builder {
            RingElement(0)
        } else if state.id == self.params.builder.prev() {
            net.send_prev(q_or_dummy)?;
            let prev_share: BlockShare = net.recv_prev()?;

            q_or_dummy.a ^ q_or_dummy.b ^ prev_share.a
        } else {
            net.send_next(q_or_dummy)?;
            let next_share: BlockShare = net.recv_next()?;

            q_or_dummy.a ^ q_or_dummy.b ^ next_share.a
        };

        let dummy_index = downcast(self.dummy_indices[self.query_count].clone());

        let lookup_result = cht::lookup_from_2shares(
            self.params.log_single_col_len,
            self.cht_2shares.as_ref().unwrap(),
            q_clear.0,
            dummy_index,
            self.params.builder,
            net,
            state,
        )?;

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

        assert!(!self.touched[index_receiver_order]);
        self.touched[index_receiver_order] = true;

        self.query_count += 1;

        Ok((
            self.ys_receiver_order[index_receiver_order].clone(),
            lookup_result.found,
        ))
    }

    pub fn extract(&self, extract_xs: &mut Vec<XShare>, extract_ys: &mut Vec<YShare>) {
        assert_eq!(self.query_count, self.params.num_dummies);

        extract_xs.clear();
        extract_ys.clear();
        extract_xs.reserve(self.params.num_elements - self.params.stash_size);
        extract_ys.reserve(self.params.num_elements - self.params.stash_size);

        for i in 0..self.params.total_size() {
            if self.touched[i] {
                continue;
            }
            extract_xs.push(self.xs_receiver_order[i].clone());
            extract_ys.push(self.ys_receiver_order[i].clone());
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

    fn prf_key_size_blocks(&self) -> usize {
        if self.params.key_size_blocks == 0 {
            self.key.len()
        } else {
            self.params.key_size_blocks
        }
    }

    fn evaluate_prf_tags<N: Network>(
        &self,
        keys_and_inputs: Vec<BlockShare>,
        net: &N,
        state: &mut Rep3State,
    ) -> eyre::Result<Vec<BlockShare>> {
        todo!()
    }

    fn reveal_qs_to_builder<N: Network>(
        &self,
        net: &N,
        state: &mut Rep3State,
    ) -> eyre::Result<Option<Vec<Block>>> {
        if self.params.builder == state.id {
            let prev_qs = net.recv_many::<BlockShare>(self.params.builder.prev())?;
            return Ok(Some(
                self.qs_builder_order[..self.params.num_elements]
                    .iter()
                    .map(|q| (q.a, q.b))
                    .zip(prev_qs)
                    .map(|((a, b), prev)| (a ^ b ^ prev.a).0)
                    .collect::<Vec<Block>>(),
            ));
        } else if self.params.builder.prev() == state.id {
            net.send_many(
                self.params.builder,
                &self.qs_builder_order[..self.params.num_elements],
            )?;
        }

        Ok(None)
    }

    fn forward_receiver_order_known_to_receivers<N: Network>(
        &mut self,
        receiver_shuffler: &mut ArrayShuffler,
        net: &N,
        state: &mut Rep3State,
    ) -> eyre::Result<()> {
        receiver_shuffler.forward_known_to_p_and_next(
            self.params.builder.next(),
            &mut self.xs_receiver_order,
            net,
            state,
        )?;
        receiver_shuffler.forward_known_to_p_and_next(
            self.params.builder.next(),
            &mut self.ys_receiver_order,
            net,
            state,
        )?;
        Ok(())
    }

    fn receiver_shuffle_for_party(&self, receiver_shuffler: &ArrayShuffler) -> LocalPermutation {
        // The C++ version stores prev_shared_perm on prev_party(builder) and
        // next_shared_perm on next_party(builder). This local model keeps the
        // evaluator-side permutation used by the receiver-order index mapping.
        receiver_shuffler.next_shared_perm.clone()
    }

    fn receive_stash_indices_from_builder(&self, stash_indices_builder: Vec<usize>) -> Vec<usize> {
        assert_eq!(stash_indices_builder.len(), self.params.stash_size);
        stash_indices_builder
    }

    fn sync_stash_indices_with_builder(&self, stash_indices_receiver: Vec<usize>) -> Vec<usize> {
        assert_eq!(stash_indices_receiver.len(), self.params.stash_size);
        stash_indices_receiver
    }
}

const KEEP_UPPER_96: u128 = u128::MAX << 32;

pub fn attach_index(q: u128, i: u32) -> u128 {
    (q & KEEP_UPPER_96) | i as u128
}
