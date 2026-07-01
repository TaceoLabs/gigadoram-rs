use crate::{permutation::LocalPermutation, reshare_3_to_2};
use mpc_core::protocols::{
    rep3::{Rep3State, id::PartyID, network::Rep3NetworkExt},
    rep3_ring::{
        Rep3RingShare,
        ring::{int_ring::IntRing2k, ring_impl::RingElement},
    },
};
use mpc_net::Network;
use rand::distributions::{Distribution, Standard};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArrayShuffler {
    pub prev_shared_perm: LocalPermutation,
    pub next_shared_perm: LocalPermutation,
}

impl ArrayShuffler {
    pub fn new(len: usize, state: &mut Rep3State) -> Self {
        let mut prev_fy = vec![0; len];
        let mut next_fy = vec![0; len];
        for i in 1..len {
            let (next_index, prev_index) = sample_indices(state, i + 1);
            prev_fy[i] = prev_index;
            next_fy[i] = next_index;
        }

        Self {
            prev_shared_perm: LocalPermutation::from_fisher_yates(prev_fy),
            next_shared_perm: LocalPermutation::from_fisher_yates(next_fy),
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
        self.forward_many(&mut [rep_array], net, state)
    }

    pub fn forward_many<T, N>(
        &self,
        rep_arrays: &mut [&mut [Rep3RingShare<T>]],
        net: &N,
        state: &mut Rep3State,
    ) -> eyre::Result<()>
    where
        T: IntRing2k,
        Standard: Distribution<T>,
        N: Network,
    {
        self.shuffle_many(rep_arrays, &mut [], net, state)
    }

    pub fn forward_many_known_to_p_and_next<T, N>(
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
        self.apply_step_many(Some(p), None, rep_arrays, &mut [], net, state)
    }

    pub fn shuffle_many<T, N>(
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
        let steps = match (forward_arrays.is_empty(), inverse_arrays.is_empty()) {
            (false, true) => [
                (Some(PartyID::ID0), None),
                (Some(PartyID::ID1), None),
                (Some(PartyID::ID2), None),
            ],
            (true, false) => [
                (None, Some(PartyID::ID2)),
                (None, Some(PartyID::ID1)),
                (None, Some(PartyID::ID0)),
            ],
            _ => [
                (Some(PartyID::ID0), Some(PartyID::ID2)),
                (Some(PartyID::ID1), Some(PartyID::ID1)),
                (Some(PartyID::ID2), Some(PartyID::ID0)),
            ],
        };

        for (forward_p, inverse_p) in steps {
            self.apply_step_many(
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

    fn apply_step_many<T, N>(
        &self,
        forward_p: Option<PartyID>,
        inverse_p: Option<PartyID>,
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
        let lengths = forward_arrays
            .iter()
            .chain(inverse_arrays.iter())
            .map(|array| array.len())
            .collect::<Vec<_>>();
        let mut two_shares = Vec::with_capacity(lengths.iter().sum());
        let mut owners = Vec::with_capacity(lengths.iter().sum());
        if let Some(p) = forward_p {
            for array in forward_arrays.iter() {
                let mut shares = reshare_3_to_2(array, p, p.next(), state);
                if let Some(permutation) = self.permutation_for(p, state.id) {
                    permutation.shuffle(&mut shares);
                }
                owners.extend((0..array.len()).map(|_| (p, p.next())));
                two_shares.extend(shares);
            }
        }
        if let Some(p) = inverse_p {
            for array in inverse_arrays.iter() {
                let mut shares = reshare_3_to_2(array, p, p.next(), state);
                if let Some(permutation) = self.permutation_for(p, state.id) {
                    permutation.inverse_shuffle(&mut shares);
                }
                owners.extend((0..array.len()).map(|_| (p, p.next())));
                two_shares.extend(shares);
            }
        }

        let reshared = from_2_shares_by_owner(two_shares, owners, net, state)?;
        let mut offset = 0;
        for (array, len) in forward_arrays.iter_mut().zip(lengths.iter().copied()) {
            array.clone_from_slice(&reshared[offset..offset + len]);
            offset += len;
        }
        for (array, len) in inverse_arrays
            .iter_mut()
            .zip(lengths.into_iter().skip(forward_arrays.len()))
        {
            array.clone_from_slice(&reshared[offset..offset + len]);
            offset += len;
        }
        Ok(())
    }

    fn permutation_for(&self, p: PartyID, id: PartyID) -> Option<&LocalPermutation> {
        if id == p {
            Some(&self.next_shared_perm)
        } else if id == p.next() {
            Some(&self.prev_shared_perm)
        } else {
            None
        }
    }
}

fn sample_indices(state: &mut Rep3State, bound: usize) -> (usize, usize) {
    let bound_u128 = bound as u128;
    let zone = u128::MAX - (u128::MAX % bound_u128);
    loop {
        let (rng1, rng2) = state.rngs.rand.random_elements::<u128>();
        if rng1 < zone && rng2 < zone {
            return ((rng1 % bound_u128) as usize, (rng2 % bound_u128) as usize);
        }
    }
}

fn from_2_shares_by_owner<T, N>(
    local_shares: Vec<RingElement<T>>,
    owners: Vec<(PartyID, PartyID)>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<Rep3RingShare<T>>>
where
    T: IntRing2k,
    Standard: Distribution<T>,
    N: Network,
{
    let local_components = local_shares
        .into_iter()
        .zip(owners)
        .map(|(local_share, (from_1, from_2))| {
            let (zero_share, other_zero_share) =
                state.rngs.rand.random_elements::<RingElement<T>>();
            let input = if state.id == from_1 || state.id == from_2 {
                local_share
            } else {
                RingElement(T::zero())
            };
            zero_share ^ other_zero_share ^ input
        })
        .collect::<Vec<_>>();

    let next_components = net.reshare_many(&local_components)?;
    Ok(local_components
        .into_iter()
        .zip(next_components)
        .map(|(local, next)| Rep3RingShare::new_ring(local, next))
        .collect())
}
