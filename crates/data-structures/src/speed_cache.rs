//! Small linear cache for recently accessed ORAM entries.
//! Queries scan stored addresses, remove the matching address mask from the
//! cache, and return the matched value/found bit.

use std::ops::BitXor;

use circuits::{
    lowmc::packed_u8_lanes_with_speed_cache::SpeedCachePrecomputeData,
    xy_if_xs_equal::xy_if_xs_equal_circuit,
};
use mpc_core::protocols::{rep3::Rep3State, rep3_ring::ring::bit::Bit};
use mpc_net::Network;
use primitives::{XShare, YShare, promote_public, types::BitShare};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpeedCache {
    pub length: usize,
    pub num_stored: usize,
    pub addrs: Vec<XShare>,
    pub data: Vec<YShare>,
}

impl SpeedCache {
    pub fn new(length: usize) -> Self {
        Self {
            length,
            num_stored: 0,
            addrs: vec![XShare::default(); length],
            data: vec![YShare::default(); length],
        }
    }

    pub fn query(
        &mut self,
        query_addr: XShare,
        precompute_data: Option<SpeedCachePrecomputeData>,
        net: &impl Network,
        state: &mut Rep3State,
    ) -> eyre::Result<(YShare, BitShare)> {
        if self.num_stored == 0 {
            return Ok((YShare::default(), promote_public(state.id, Bit::new(false))));
        }

        let length_for_query = self.num_stored;

        let result = precompute_data.and_then(|mut query| query.take_result());
        let (x_if_found, y_if_found, found_out) = match result {
            Some((x_if_found, y_if_found, found_out)) => (x_if_found, y_if_found, found_out),
            None => {
                // circuit input:  x_query | x | y
                // circuit output: x_mask | y | found
                let query_addrs = vec![query_addr; length_for_query];
                xy_if_xs_equal_circuit(
                    &self.addrs[..length_for_query],
                    &query_addrs,
                    &self.data[..length_for_query],
                    net,
                    state,
                )?
            }
        };

        self.addrs[..length_for_query]
            .iter_mut()
            .zip(x_if_found)
            .for_each(|(x, x_mask)| *x ^= x_mask);

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

    pub fn precompute_query(&self, query_addr: XShare) -> Option<SpeedCachePrecomputeData> {
        (self.num_stored > 0).then(|| {
            SpeedCachePrecomputeData::new(
                query_addr,
                self.addrs[..self.num_stored].to_vec(),
                self.data[..self.num_stored].to_vec(),
            )
        })
    }

    pub fn extract(&mut self) -> (Vec<XShare>, Vec<YShare>) {
        assert_eq!(self.num_stored, self.length);
        assert_eq!(self.addrs.len(), self.length);
        assert_eq!(self.data.len(), self.length);
        (self.addrs.clone(), self.data.clone())
    }

    pub fn write(&mut self, write_addrs: Vec<XShare>, write_data: Vec<YShare>) {
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
