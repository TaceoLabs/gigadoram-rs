use crate::{from_2_shares, permutation::LocalPermutation};
use mpc_core::protocols::{
    rep3::{Rep3State, id::PartyID},
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

    pub fn indices<T, N>(
        &self,
        indices: &mut [Rep3RingShare<u32>],
        net: &N,
        state: &mut Rep3State,
    ) -> eyre::Result<()>
    where
        T: IntRing2k,
        Standard: Distribution<T>,
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
