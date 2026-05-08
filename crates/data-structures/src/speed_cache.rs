use circuits::xy_if_xs_equal::{
    CircuitBlockShare, INPUT_Y_OFFSET, OUTPUT_FOUND_OFFSET, OUTPUT_X_MASK_OFFSET, OUTPUT_Y_OFFSET,
    STORED_X_OFFSET, X_QUERY_OFFSET, pack_x, pack_y, unpack_x, unpack_y, xor_of_all_elements,
    xy_if_xs_equal_circuit,
};
use mpc_core::protocols::{rep3::Rep3State, rep3_ring::binary};
use mpc_net::Network;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpeedCacheQueryResult {
    pub value: Vec<YShare>,
    pub found: Vec<XShare>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpeedCache {
    length: usize,
    num_stored: usize,
    addrs: Vec<X>,
    data: Vec<Y>,
}

impl SpeedCache {
    pub fn new(length: usize) -> Self {
        Self {
            length,
            num_stored: 0,
            addrs: vec![X::zero_share(); length],
            data: vec![Y::zero_share(); length],
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
        query_addr: Vec<X>,
        query_result: &mut Vec<Y>,
        found: &mut Vec<X>,
        net: &impl Network,
        state: &mut Rep3State,
    ) -> eyre::Result<()> {
        assert_eq!(query_addr.len(), 1);

        let length_for_query = std::cmp::max(1, self.num_stored);
        assert!(length_for_query <= self.length);

        let mut circuit_input = vec![CircuitBlockShare::zero_share(); length_for_query];
        let mut remove_duplicate_addr_mask = vec![X::zero_share(); length_for_query];

        for input in circuit_input.iter_mut() {
            *input = pack_x(&query_addr[0], X_QUERY_OFFSET);
        }

        for (i, input) in circuit_input.iter_mut().enumerate().take(self.num_stored) {
            *input ^= pack_x(&self.addrs[i], STORED_X_OFFSET);
            *input ^= pack_y(&self.data[i], INPUT_Y_OFFSET);
        }

        // circuit input:  x_query | x | y
        // circuit output: x_mask | y | found
        // TODO: Single round of communication
        let mut circuit_output = Vec::with_capacity(length_for_query);
        for input in circuit_input.iter().take(length_for_query) {
            circuit_output.push(xy_if_xs_equal_circuit(input, net, state)?);
        }

        for (mask, output) in remove_duplicate_addr_mask
            .iter_mut()
            .zip(circuit_output.iter())
        {
            *mask = unpack_x(output, OUTPUT_X_MASK_OFFSET);
        }

        for (addr, mask) in self
            .addrs
            .iter_mut()
            .take(length_for_query)
            .zip(remove_duplicate_addr_mask.iter())
        {
            *addr = binary::xor(addr, mask);
        }

        let xor_of_all = xor_of_all_elements(&circuit_output);
        query_result.clear();
        query_result.push(unpack_y(&xor_of_all, OUTPUT_Y_OFFSET));

        found.clear();
        found.push(unpack_x(&xor_of_all, OUTPUT_FOUND_OFFSET));

        Ok(())
    }

    pub fn query_address(
        &mut self,
        query_addr: Vec<X>,
        net: &impl Network,
        state: &mut Rep3State,
    ) -> eyre::Result<SpeedCacheQueryResult> {
        let mut value = Vec::with_capacity(1);
        let mut found = Vec::with_capacity(1);
        self.query(query_addr, &mut value, &mut found, net, state)?;
        Ok(SpeedCacheQueryResult { value, found })
    }

    pub fn extract(&self, xs: &mut Vec<X>, ys: &mut Vec<Y>) {
        assert_eq!(self.num_stored, self.length);
        xs.clear();
        ys.clear();
        xs.extend_from_slice(&self.addrs);
        ys.extend_from_slice(&self.data);
    }

    pub fn write(&mut self, write_addrs: Vec<X>, write_data: Vec<Y>) {
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
        rep3_ring::{arithmetic, binary, ring::ring_impl::RingElement},
    };
    use mpc_net::local::LocalNetwork;

    use super::*;

    fn x_share(value: u32) -> X {
        X::new(value, 0)
    }

    fn y_share(value: u64) -> Y {
        Y::new(value, 0)
    }

    #[test]
    fn write_and_extract_follow_stupid_level_flow() {
        let mut cache = SpeedCache::new(2);
        cache.write(vec![x_share(7)], vec![y_share(70)]);

        assert_eq!(cache.len(), 1);

        cache.write(vec![x_share(8)], vec![y_share(80)]);
        let mut xs = Vec::new();
        let mut ys = Vec::new();
        cache.extract(&mut xs, &mut ys);

        assert_eq!(xs, vec![x_share(7), x_share(8)]);
        assert_eq!(ys, vec![y_share(70), y_share(80)]);
    }

    #[test]
    fn skip_advances_occupancy_with_zero_dummies() {
        let mut cache = SpeedCache::new(2);

        cache.skip(2);

        assert!(!cache.is_writeable());
        let mut xs = Vec::new();
        let mut ys = Vec::new();
        cache.extract(&mut xs, &mut ys);
        assert_eq!(xs, vec![X::zero_share(), X::zero_share()]);
        assert_eq!(ys, vec![Y::zero_share(), Y::zero_share()]);
    }

    #[test]
    fn query_finds_value_and_removes_duplicate_address() {
        let networks = LocalNetwork::new_3_parties();

        std::thread::scope(|scope| {
            let handles = networks.map(|network| {
                scope.spawn(move || {
                    let mut state = Rep3State::new(&network, A2BType::Direct).unwrap();
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

                    let query_addr = vec![binary::promote_to_trivial_share(
                        state.id,
                        &RingElement(7u32),
                    )];
                    let query = cache
                        .query_address(query_addr, &network, &mut state)
                        .unwrap();

                    let value = arithmetic::open_bit(query.value[0], &network).unwrap();
                    let found = arithmetic::open_bit(query.found[0], &network).unwrap();

                    let mut xs = Vec::new();
                    let mut ys = Vec::new();
                    cache.extract(&mut xs, &mut ys);
                    let consumed_addr = arithmetic::open_bit(xs[0], &network).unwrap();
                    let untouched_addr = arithmetic::open_bit(xs[1], &network).unwrap();

                    (value, found, consumed_addr, untouched_addr)
                })
            });

            for handle in handles {
                let (value, found, consumed_addr, untouched_addr) = handle.join().unwrap();
                assert_eq!(value, RingElement(70u64));
                assert_eq!(found, RingElement(1u32));
                assert_eq!(consumed_addr, RingElement(0u32));
                assert_eq!(untouched_addr, RingElement(8u32));
            }
        });
    }
}
