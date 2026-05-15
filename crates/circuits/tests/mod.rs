#![allow(dead_code)]

use mpc_core::protocols::{
    rep3::id::PartyID,
    rep3_ring::{
        Rep3RingShare, binary,
        ring::{int_ring::IntRing2k, ring_impl::RingElement},
    },
};
use mpc_net::{Network, local::LocalNetwork};
use primitives::{BlockShare, XShare};

pub fn run_parties<R, F>(f: F) -> [R; 3]
where
    R: Send,
    F: Fn(LocalNetwork) -> R + Sync,
{
    let [net0, net1, net2] = LocalNetwork::new_3_parties();

    std::thread::scope(|scope| {
        let f = &f;
        let party_0 = scope.spawn(move || f(net0));
        let party_1 = scope.spawn(move || f(net1));
        let party_2 = scope.spawn(move || f(net2));

        [
            party_0.join().unwrap(),
            party_1.join().unwrap(),
            party_2.join().unwrap(),
        ]
    })
}

pub fn public_block_share(id: PartyID, value: u128) -> BlockShare {
    binary::promote_to_trivial_share(id, &RingElement(value))
}

pub fn public_x_share(id: PartyID, value: u32) -> XShare {
    binary::promote_to_trivial_share(id, &RingElement(value))
}

pub fn promote_public_values<T: IntRing2k>(values: &[T], id: PartyID) -> Vec<Rep3RingShare<T>> {
    values
        .iter()
        .map(|value| binary::promote_to_trivial_share(id, &RingElement(*value)))
        .collect()
}

pub fn open_binary_values<T, N>(shares: &[Rep3RingShare<T>], net: &N) -> Vec<T>
where
    T: IntRing2k,
    N: Network,
{
    shares
        .iter()
        .map(|share| binary::open(share, net).unwrap().0)
        .collect()
}
