use std::ops::BitXor;

use circuits::xy_if_xs_equal::xy_if_xs_equal_circuit;
use mpc_core::protocols::rep3::Rep3State;
use mpc_net::Network;
use primitives::{XShare, YShare, types::BitShare};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpeedCacheQueryResult {
    pub value: Vec<YShare>,
    pub found: Vec<XShare>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpeedCache {
    length: usize,
    num_stored: usize,
    addrs: Vec<XShare>,
    data: Vec<YShare>,
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

    pub fn with_capacity(capacity: usize) -> Self {
        Self::new(capacity)
    }

    pub fn length(&self) -> usize {
        self.length
    }

    pub fn len(&self) -> usize {
        self.num_stored
    }

    pub fn is_empty(&self) -> bool {
        self.num_stored == 0
    }

    pub fn query(
        &mut self,
        query_addr: Vec<XShare>,
        net: &impl Network,
        state: &mut Rep3State,
    ) -> eyre::Result<(YShare, BitShare)> {
        assert_eq!(query_addr.len(), 1);

        let length_for_query = std::cmp::max(1, self.num_stored);

        // circuit input:  x_query | x | y
        // circuit output: x_mask | y | found
        let (x_if_found, y_if_found, found_out) = xy_if_xs_equal_circuit(
            &self.addrs[..length_for_query],
            &query_addr,
            &self.data[..length_for_query],
            net,
            state,
        )?;

        self.addrs[..length_for_query]
            .iter_mut()
            .zip(x_if_found.into_iter())
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

    // TODO: Get the vectors unsafely, no clones
    pub fn extract(&mut self) -> (Vec<XShare>, Vec<YShare>) {
        assert_eq!(self.num_stored, self.length);
        let result = (self.addrs.clone(), self.data.clone());
        self.addrs.clear();
        self.data.clear();
        result
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

impl Default for SpeedCache {
    fn default() -> Self {
        Self::new(0)
    }
}

#[cfg(test)]
mod tests {
    use mpc_core::protocols::{
        rep3::{Rep3State, conversion::A2BType},
        rep3_ring::{
            arithmetic, binary,
            ring::{bit::Bit, ring_impl::RingElement},
        },
    };
    use mpc_net::local::LocalNetwork;

    use super::*;

    fn init_speed_cache(state: &Rep3State) -> SpeedCache {
        let mut cache = SpeedCache::new(2);
        cache.write(
            vec![
                binary::promote_to_trivial_share(state.id, &RingElement(7u32)),
                binary::promote_to_trivial_share(state.id, &RingElement(8u32)),
            ],
            vec![
                binary::promote_to_trivial_share(state.id, &RingElement(70u64)),
                binary::promote_to_trivial_share(state.id, &RingElement(80u64)),
            ],
        );
        cache
    }

    #[test]
    fn test_speed_cache_query() {
        let networks = LocalNetwork::new_3_parties();

        std::thread::scope(|scope| {
            let handles = networks.map(|network| {
                scope.spawn(move || {
                    let mut state = Rep3State::new(&network, A2BType::Direct).unwrap();
                    let mut cache = init_speed_cache(&state);

                    let query_addr = vec![binary::promote_to_trivial_share(
                        state.id,
                        &RingElement(7u32),
                    )];

                    let (value, found) = cache.query(query_addr, &network, &mut state).unwrap();

                    let value = arithmetic::open_bit(value, &network).unwrap();
                    let found = arithmetic::open_bit(found, &network).unwrap();

                    (value, found)
                })
            });

            for handle in handles {
                let (value, found) = handle.join().unwrap();
                assert_eq!(value, RingElement(70u64));
                assert_eq!(found, RingElement(Bit::new(true)));
            }
        });
    }
}
