//! Small linear cache for recently accessed ORAM entries.
//! Queries scan stored addresses, remove the matching address mask from the
//! cache, and return the matched value/found bit.

use std::ops::BitXor;

use circuits::{
    lowmc::packed_u8_lanes_with_speed_cache::{SpeedCachePrecomputeData, SpeedCacheQueryResult},
    xy_if_xs_equal::xy_if_xs_equal_circuit,
};
use mpc_core::protocols::{
    rep3::{Rep3State, id::PartyID},
    rep3_ring::ring::{bit::Bit, ring_impl::RingElement},
};
use mpc_net::Network;
use primitives::{
    DoramValue, Record, X, XShare, bit_to_binary_mask, cmux_many_custom, dummy_x, is_zero_many,
    promote_public, types::BitShare,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpeedCache<V: DoramValue> {
    pub length: usize,
    pub log_address_space_size: usize,
    pub num_stored: usize,
    pub addrs: Vec<XShare>,
    pub data: Vec<Record<V>>,
}

impl<V: DoramValue> SpeedCache<V> {
    pub fn new(length: usize, log_address_space_size: usize, id: PartyID) -> Self {
        Self {
            length,
            log_address_space_size,
            num_stored: 0,
            addrs: vec![dummy_x(id, log_address_space_size); length],
            data: vec![Record::default(); length],
        }
    }

    pub fn query(
        &mut self,
        query_addr: XShare,
        precompute_data: Option<SpeedCachePrecomputeData<V>>,
        net: &impl Network,
        state: &mut Rep3State,
    ) -> eyre::Result<(Record<V>, BitShare)> {
        if self.num_stored == 0 {
            return Ok((Record::default(), promote_public(state.id, Bit::new(false))));
        }

        let length_for_query = self.num_stored;
        let (x_if_found, y_if_found, found_out) =
            match precompute_data.and_then(|mut query| query.take_result()) {
                Some(result) => (result.x_if_found, result.y_if_found, result.found),
                None => {
                    // circuit input:  x_query | x | (y, alibi)
                    // circuit output: x_mask | y | alibi | found
                    let query_addrs = vec![query_addr; length_for_query];
                    let ys = Record::<V>::get_y_values(&self.data[..length_for_query]);
                    let alibis = Record::<V>::get_alibis(&self.data[..length_for_query]);
                    let (x_if_found, y_if_found, alibi_if_found, found_out) =
                        xy_if_xs_equal_circuit::<V>(
                            &self.addrs[..length_for_query],
                            &query_addrs,
                            &ys,
                            &alibis,
                            net,
                            state,
                        )?;
                    (
                        x_if_found,
                        Record::<V>::from_columns(y_if_found, alibi_if_found),
                        found_out,
                    )
                }
            };

        let sentinel = RingElement((1 as X) << self.log_address_space_size);

        // Update addrs with the following logic for each entry:
        // if addrs_i matches query_addr, then the addr_i after the query becomes a dummy sentinel (bit N set) share.
        // else the addrs_i is updated obliviously, but the value it opens to remains unchanged
        self.addrs[..length_for_query]
            .iter_mut()
            .zip(x_if_found)
            .zip(&found_out)
            .for_each(|((x, x_mask), found)| {
                let found_mask = bit_to_binary_mask::<X>(found);
                *x ^= x_mask ^ (found_mask & sentinel);
            });

        let y_xor = y_if_found
            .into_iter()
            .reduce(BitXor::bitxor)
            .expect("circuit output should be non-empty");

        let found_xor = found_out
            .into_iter()
            .reduce(BitXor::bitxor)
            .expect("circuit output should be non-empty");

        Ok((y_xor, found_xor))
    }

    pub fn query_many(
        &mut self,
        query_addrs: &[XShare],
        precomputed: Option<Vec<SpeedCacheQueryResult<V>>>,
        net: &impl Network,
        state: &mut Rep3State,
    ) -> eyre::Result<Vec<(Record<V>, BitShare)>> {
        let count = query_addrs.len();
        if self.num_stored == 0 {
            return Ok(vec![
                (
                    Record::default(),
                    promote_public(state.id, Bit::new(false))
                );
                count
            ]);
        }
        let length = self.num_stored;
        let (x, y, found) = match precomputed {
            Some(results) => {
                assert_eq!(results.len(), count);
                results
                    .into_iter()
                    .fold((Vec::new(), Vec::new(), Vec::new()), |mut all, result| {
                        all.0.extend(result.x_if_found);
                        all.1.extend(result.y_if_found);
                        all.2.extend(result.found);
                        all
                    })
            }
            None => {
                let ys = Record::<V>::get_y_values(&self.data[..length]);
                let alibis = Record::<V>::get_alibis(&self.data[..length]);
                let mut addrs = Vec::with_capacity(count * length);
                let mut queries = Vec::with_capacity(count * length);
                let mut values = Vec::with_capacity(count * length);
                let mut all_alibis = Vec::with_capacity(count * length);
                for &query in query_addrs {
                    addrs.extend_from_slice(&self.addrs[..length]);
                    queries.extend(std::iter::repeat_n(query, length));
                    values.extend_from_slice(&ys);
                    all_alibis.extend_from_slice(&alibis);
                }
                let xor = addrs
                    .iter()
                    .zip(&queries)
                    .map(|(x, query)| x ^ query)
                    .collect::<Vec<_>>();
                let found = is_zero_many(&xor, net, state)?;
                let (x, y, alibi) =
                    cmux_many_custom::<V, _>(&found, &addrs, &values, &all_alibis, net, state)?;
                (x, Record::<V>::from_columns(y, alibi), found)
            }
        };

        let sentinel = RingElement((1 as X) << self.log_address_space_size);
        Ok((0..count)
            .map(|query| {
                let range = query * length..(query + 1) * length;
                for ((addr, mask), found) in self.addrs[..length]
                    .iter_mut()
                    .zip(&x[range.clone()])
                    .zip(&found[range.clone()])
                {
                    *addr ^= *mask ^ (bit_to_binary_mask::<X>(found) & sentinel);
                }
                (
                    y[range.clone()]
                        .iter()
                        .copied()
                        .reduce(BitXor::bitxor)
                        .unwrap(),
                    found[range].iter().copied().reduce(BitXor::bitxor).unwrap(),
                )
            })
            .collect())
    }

    pub fn precompute_query(&self, query_addr: XShare) -> Option<SpeedCachePrecomputeData<V>> {
        (self.num_stored > 0).then(|| {
            SpeedCachePrecomputeData::new(
                query_addr,
                self.addrs[..self.num_stored].to_vec(),
                self.data[..self.num_stored].to_vec(),
            )
        })
    }

    pub fn extract(&mut self) -> (Vec<XShare>, Vec<Record<V>>) {
        assert_eq!(self.num_stored, self.length);
        assert_eq!(self.addrs.len(), self.length);
        assert_eq!(self.data.len(), self.length);
        (self.addrs.clone(), self.data.clone())
    }

    pub fn write(&mut self, write_addrs: Vec<XShare>, write_data: Vec<Record<V>>) {
        assert_eq!(write_addrs.len(), write_data.len());
        assert!(
            self.num_stored < self.length,
            "The speed cache is full; rebuild before writing to it"
        );
        assert!(
            self.num_stored + write_addrs.len() <= self.length,
            "write batch exceeds remaining speed cache capacity"
        );

        let start = self.num_stored;
        let end = start + write_addrs.len();
        self.addrs[start..end].clone_from_slice(&write_addrs);
        self.data[start..end].clone_from_slice(&write_data);
        self.num_stored = end;
    }

    pub fn skip(&mut self, num_to_skip: usize) {
        assert!(
            self.num_stored + num_to_skip <= self.length,
            "skip exceeds speed cache capacity"
        );
        self.num_stored += num_to_skip;
    }

    pub fn is_writeable(&self) -> bool {
        self.num_stored < self.length
    }

    pub fn clear(&mut self) {
        self.num_stored = 0;
    }
}
