//! Small linear cache for recently accessed ORAM entries.
//! Queries scan stored addresses, remove the matching address mask from the
//! cache, and return the matched value/found bit.

use std::ops::BitXor;

use mpc_core::protocols::{rep3::Rep3State, rep3_ring::ring::bit::Bit};
use mpc_net::Network;
use primitives::{
    XShare, YShare, bit_to_binary_mask, cmux_many_custom, downcast_many, is_zero_many,
    promote_public, types::BitShare,
};

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
        net: &impl Network,
        state: &mut Rep3State,
    ) -> eyre::Result<(YShare, BitShare)> {
        if self.num_stored == 0 {
            return Ok((YShare::default(), promote_public(state.id, Bit::new(false))));
        }

        let length_for_query = self.num_stored;

        let xor = self.addrs[..length_for_query]
            .iter()
            .map(|x| *x ^ query_addr)
            .collect::<Vec<_>>();
        let found_out = is_zero_many(&xor, net, state)?;

        self.query_from_found(found_out, net, state)
    }

    pub fn query_from_found(
        &mut self,
        found_out: Vec<BitShare>,
        net: &impl Network,
        state: &mut Rep3State,
    ) -> eyre::Result<(YShare, BitShare)> {
        let length_for_query = self.num_stored;
        assert_eq!(found_out.len(), length_for_query);

        let found_y = found_out
            .iter()
            .map(bit_to_binary_mask)
            .collect::<Vec<YShare>>();
        let selected = cmux_many_custom(
            &found_y,
            &self.addrs[..length_for_query],
            &self.data[..length_for_query],
            net,
            state,
        )?;

        let selected_x = downcast_many(selected[..length_for_query].to_vec());
        let selected_y = selected[length_for_query..].to_vec();
        Ok(self.query_from_selected(found_out, selected_x, selected_y))
    }

    pub fn query_from_selected(
        &mut self,
        found_out: Vec<BitShare>,
        selected_x: Vec<XShare>,
        selected_y: Vec<YShare>,
    ) -> (YShare, BitShare) {
        let length_for_query = self.num_stored;
        assert_eq!(found_out.len(), length_for_query);
        assert_eq!(selected_x.len(), length_for_query);
        assert_eq!(selected_y.len(), length_for_query);

        self.addrs[..length_for_query]
            .iter_mut()
            .zip(selected_x)
            .for_each(|(x, x_mask)| *x ^= x_mask);

        let y_xor = selected_y
            .iter()
            .copied()
            .into_iter()
            .reduce(BitXor::bitxor)
            .expect("circuit output should be non-empty");
        let found_xor = found_out
            .into_iter()
            .reduce(BitXor::bitxor)
            .expect("circuit output should be non-empty");

        (y_xor, found_xor)
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
}
