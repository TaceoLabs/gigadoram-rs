use crate::{from_2_shares, permutation::LocalPermutation};
use mpc_core::protocols::{
    rep3::{Rep3State, id::PartyID, network::Rep3NetworkExt},
    rep3_ring::{
        Rep3RingShare, binary,
        ring::{int_ring::IntRing2k, ring_impl::RingElement},
    },
};
use mpc_net::Network;
use rand::distributions::{Distribution, Standard};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArrayShuffler {
    pub len: usize,
    pub prev_shared_perm: LocalPermutation,
    pub next_shared_perm: LocalPermutation,
}

impl ArrayShuffler {
    pub fn new(len: usize, state: &mut Rep3State) -> Self {
        assert!(len > 0);
        let mut prev_fy = vec![0; len];
        let mut next_fy = vec![0; len];
        for i in 1..len {
            prev_fy[i] = sample_rng2_index(state, i + 1);
            next_fy[i] = sample_rng1_index(state, i + 1);
        }

        Self {
            len,
            prev_shared_perm: LocalPermutation::from_fisher_yates(prev_fy),
            next_shared_perm: LocalPermutation::from_fisher_yates(next_fy),
        }
    }

    pub fn from_permutations(
        prev_shared_perm: LocalPermutation,
        next_shared_perm: LocalPermutation,
    ) -> Self {
        assert_eq!(prev_shared_perm.len(), next_shared_perm.len());
        Self {
            len: prev_shared_perm.len(),
            prev_shared_perm,
            next_shared_perm,
        }
    }

    pub fn forward<T, N>(
        &self,
        rep_array: &mut [Rep3RingShare<T>],
        net: &N,
        state: &mut Rep3State,
    ) -> eyre::Result<()>
    where
        T: IntRing2k,
        Standard: Distribution<T>,
        N: Network,
    {
        assert_eq!(rep_array.len(), self.len);
        for p in [PartyID::ID0, PartyID::ID1, PartyID::ID2] {
            self.forward_step(p, rep_array, net, state)?;
        }
        Ok(())
    }

    pub fn forward_known_to_p_and_next<T, N>(
        &self,
        p: PartyID,
        rep_array: &mut [Rep3RingShare<T>],
        net: &N,
        state: &mut Rep3State,
    ) -> eyre::Result<()>
    where
        T: IntRing2k,
        Standard: Distribution<T>,
        N: Network,
    {
        assert_eq!(rep_array.len(), self.len);
        self.forward_step(p, rep_array, net, state)
    }

    pub fn forward_known_to_p_and_next_many<T, N>(
        &self,
        p: PartyID,
        rep_arrays: &mut [&mut [Rep3RingShare<T>]],
        net: &N,
        state: &mut Rep3State,
    ) -> eyre::Result<()>
    where
        T: IntRing2k,
        Standard: Distribution<T>,
        N: Network,
    {
        for rep_array in rep_arrays.iter() {
            assert_eq!(rep_array.len(), self.len);
        }

        let total_len = rep_arrays.iter().map(|rep_array| rep_array.len()).sum();
        let mut local_components = Vec::with_capacity(total_len);
        for rep_array in rep_arrays.iter_mut() {
            let mut two_shares = reshare_3_to_2_for(rep_array, p, p.next(), state);
            self.shuffle_forward_step(p, &mut two_shares, state);
            append_from_2_share_components(&mut local_components, two_shares, p, p.next(), state);
        }

        let next_components = net.reshare_many(&local_components)?;
        let mut offset = 0;
        for rep_array in rep_arrays.iter_mut() {
            write_reshared_components(rep_array, &local_components, &next_components, &mut offset);
        }
        debug_assert_eq!(offset, local_components.len());
        Ok(())
    }

    pub fn forward_many_and_inverse_many<T, N>(
        &self,
        forward_arrays: &mut [&mut [Rep3RingShare<T>]],
        inverse_arrays: &mut [&mut [Rep3RingShare<T>]],
        net: &N,
        state: &mut Rep3State,
    ) -> eyre::Result<()>
    where
        T: IntRing2k,
        Standard: Distribution<T>,
        N: Network,
    {
        for rep_array in forward_arrays.iter().chain(inverse_arrays.iter()) {
            assert_eq!(rep_array.len(), self.len);
        }

        for (forward_p, inverse_p) in [
            (PartyID::ID0, PartyID::ID2),
            (PartyID::ID1, PartyID::ID1),
            (PartyID::ID2, PartyID::ID0),
        ] {
            self.forward_inverse_step_many(
                forward_p,
                inverse_p,
                forward_arrays,
                inverse_arrays,
                net,
                state,
            )?;
        }

        Ok(())
    }

    pub fn inverse<T, N>(
        &self,
        rep_array: &mut [Rep3RingShare<T>],
        net: &N,
        state: &mut Rep3State,
    ) -> eyre::Result<()>
    where
        T: IntRing2k,
        Standard: Distribution<T>,
        N: Network,
    {
        assert_eq!(rep_array.len(), self.len);
        for p in [PartyID::ID2, PartyID::ID1, PartyID::ID0] {
            self.inverse_step(p, rep_array, net, state)?;
        }
        Ok(())
    }

    pub fn indices<N>(
        &self,
        indices: &mut [Rep3RingShare<u32>],
        net: &N,
        state: &mut Rep3State,
    ) -> eyre::Result<()>
    where
        N: Network,
    {
        assert_eq!(indices.len(), self.len);
        for (i, index) in indices.iter_mut().enumerate() {
            *index = binary::promote_to_trivial_share(state.id, &RingElement(i as u32));
        }
        self.inverse::<u32, _>(indices, net, state)
    }

    fn forward_step<T, N>(
        &self,
        p: PartyID,
        rep_array: &mut [Rep3RingShare<T>],
        net: &N,
        state: &mut Rep3State,
    ) -> eyre::Result<()>
    where
        T: IntRing2k,
        Standard: Distribution<T>,
        N: Network,
    {
        let mut two_shares = reshare_3_to_2_for(rep_array, p, p.next(), state);
        if state.id == p {
            self.next_shared_perm.shuffle(&mut two_shares);
        } else if state.id == p.next() {
            self.prev_shared_perm.shuffle(&mut two_shares);
        }
        let reshared = from_2_shares(two_shares, p, p.next(), net, state)?;
        rep_array.clone_from_slice(&reshared);
        Ok(())
    }

    fn forward_inverse_step_many<T, N>(
        &self,
        forward_p: PartyID,
        inverse_p: PartyID,
        forward_arrays: &mut [&mut [Rep3RingShare<T>]],
        inverse_arrays: &mut [&mut [Rep3RingShare<T>]],
        net: &N,
        state: &mut Rep3State,
    ) -> eyre::Result<()>
    where
        T: IntRing2k,
        Standard: Distribution<T>,
        N: Network,
    {
        let total_len = forward_arrays
            .iter()
            .chain(inverse_arrays.iter())
            .map(|rep_array| rep_array.len())
            .sum();
        let mut local_components = Vec::with_capacity(total_len);

        for rep_array in forward_arrays.iter_mut() {
            let mut two_shares = reshare_3_to_2_for(rep_array, forward_p, forward_p.next(), state);
            self.shuffle_forward_step(forward_p, &mut two_shares, state);
            append_from_2_share_components(
                &mut local_components,
                two_shares,
                forward_p,
                forward_p.next(),
                state,
            );
        }

        for rep_array in inverse_arrays.iter_mut() {
            let mut two_shares = reshare_3_to_2_for(rep_array, inverse_p, inverse_p.next(), state);
            self.shuffle_inverse_step(inverse_p, &mut two_shares, state);
            append_from_2_share_components(
                &mut local_components,
                two_shares,
                inverse_p,
                inverse_p.next(),
                state,
            );
        }

        let next_components = net.reshare_many(&local_components)?;
        let mut offset = 0;
        for rep_array in forward_arrays.iter_mut() {
            write_reshared_components(rep_array, &local_components, &next_components, &mut offset);
        }
        for rep_array in inverse_arrays.iter_mut() {
            write_reshared_components(rep_array, &local_components, &next_components, &mut offset);
        }
        debug_assert_eq!(offset, local_components.len());
        Ok(())
    }

    fn inverse_step<T, N>(
        &self,
        p: PartyID,
        rep_array: &mut [Rep3RingShare<T>],
        net: &N,
        state: &mut Rep3State,
    ) -> eyre::Result<()>
    where
        T: IntRing2k,
        Standard: Distribution<T>,
        N: Network,
    {
        let mut two_shares = reshare_3_to_2_for(rep_array, p, p.next(), state);
        if state.id == p {
            self.next_shared_perm.inverse_shuffle(&mut two_shares);
        } else if state.id == p.next() {
            self.prev_shared_perm.inverse_shuffle(&mut two_shares);
        }
        let reshared = from_2_shares(two_shares, p, p.next(), net, state)?;
        rep_array.clone_from_slice(&reshared);
        Ok(())
    }

    fn shuffle_forward_step<T: IntRing2k>(
        &self,
        p: PartyID,
        two_shares: &mut [RingElement<T>],
        state: &Rep3State,
    ) {
        if state.id == p {
            self.next_shared_perm.shuffle(two_shares);
        } else if state.id == p.next() {
            self.prev_shared_perm.shuffle(two_shares);
        }
    }

    fn shuffle_inverse_step<T: IntRing2k>(
        &self,
        p: PartyID,
        two_shares: &mut [RingElement<T>],
        state: &Rep3State,
    ) {
        if state.id == p {
            self.next_shared_perm.inverse_shuffle(two_shares);
        } else if state.id == p.next() {
            self.prev_shared_perm.inverse_shuffle(two_shares);
        }
    }
}

fn append_from_2_share_components<T>(
    local_components: &mut Vec<RingElement<T>>,
    local_shares: Vec<RingElement<T>>,
    from_1: PartyID,
    from_2: PartyID,
    state: &mut Rep3State,
) where
    T: IntRing2k,
    Standard: Distribution<T>,
{
    assert_ne!(from_1, from_2);
    assert!(from_1.next() == from_2 || from_1.prev() == from_2);

    local_components.extend(local_shares.into_iter().map(|local_share| {
        let (mut zero_share, other_zero_share) =
            state.rngs.rand.random_elements::<RingElement<T>>();
        zero_share ^= other_zero_share;
        if state.id == from_1 || state.id == from_2 {
            zero_share ^ local_share
        } else {
            zero_share
        }
    }));
}

fn write_reshared_components<T: IntRing2k>(
    rep_array: &mut [Rep3RingShare<T>],
    local_components: &[RingElement<T>],
    next_components: &[RingElement<T>],
    offset: &mut usize,
) {
    for share in rep_array {
        *share = Rep3RingShare::new_ring(local_components[*offset], next_components[*offset]);
        *offset += 1;
    }
}

fn reshare_3_to_2_for<T: IntRing2k>(
    rep_array: &[Rep3RingShare<T>],
    to_1: PartyID,
    to_2: PartyID,
    state: &Rep3State,
) -> Vec<RingElement<T>> {
    assert_ne!(to_1, to_2);

    rep_array
        .iter()
        .map(|share| {
            if state.id == to_1 {
                share.a ^ share.b
            } else if state.id == to_2 {
                if to_2 == to_1.prev() {
                    share.b
                } else {
                    share.a
                }
            } else {
                RingElement(T::zero())
            }
        })
        .collect()
}

fn sample_rng1_index(state: &mut Rep3State, bound: usize) -> usize {
    sample_index(bound, || state.rngs.rand.random_element_rng1::<u128>())
}

fn sample_rng2_index(state: &mut Rep3State, bound: usize) -> usize {
    sample_index(bound, || state.rngs.rand.random_element_rng2::<u128>())
}

fn sample_index(bound: usize, mut sample: impl FnMut() -> u128) -> usize {
    assert!(bound > 0);
    if bound == 1 {
        return 0;
    }

    let bound_u128 = bound as u128;
    let zone = u128::MAX - (u128::MAX % bound_u128);
    loop {
        let candidate = sample();
        if candidate < zone {
            return (candidate % bound_u128) as usize;
        }
    }
}
