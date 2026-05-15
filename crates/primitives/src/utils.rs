use mpc_core::protocols::{
    rep3::{Rep3State, id::PartyID, network::Rep3NetworkExt},
    rep3_ring::{
        Rep3RingShare,
        arithmetic::RingShare,
        binary::and_vec,
        ring::{bit::Bit, int_ring::IntRing2k, ring_impl::RingElement},
    },
};
use mpc_net::{Network, local::LocalNetwork};
use num_traits::One;
use rand::distributions::{Distribution, Standard};
use rand::{RngCore, seq::SliceRandom, thread_rng};

use crate::{Block, XShare, YShare, upcast_x_to_y};

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

pub fn run_parties_may_panic<R, F>(f: F) -> [std::thread::Result<R>; 3]
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

        [party_0.join(), party_1.join(), party_2.join()]
    })
}

pub fn random_block() -> Block {
    let mut rng = thread_rng();
    random_block_with(&mut rng)
}

pub fn random_blocks(count: usize) -> Vec<Block> {
    let mut rng = thread_rng();
    (0..count).map(|_| random_block_with(&mut rng)).collect()
}

pub fn random_block_with(rng: &mut impl RngCore) -> Block {
    (Block::from(rng.next_u64()) << 64) | Block::from(rng.next_u64())
}

pub fn random_indexed_block(
    log_single_col_len: u32,
    left_vertex: usize,
    right_vertex: usize,
    builder_index: u32,
) -> Block {
    let mut rng = thread_rng();
    random_indexed_block_with(
        &mut rng,
        log_single_col_len,
        left_vertex,
        right_vertex,
        builder_index,
    )
}

pub fn random_indexed_blocks(log_single_col_len: u32, count: usize) -> Vec<Block> {
    let mut rng = thread_rng();
    let column_len = 1usize << log_single_col_len;
    let mut left = (0..column_len).collect::<Vec<_>>();
    let mut right = (0..column_len).collect::<Vec<_>>();

    left.shuffle(&mut rng);
    right.shuffle(&mut rng);

    (0..count)
        .map(|i| {
            random_indexed_block_with(
                &mut rng,
                log_single_col_len,
                left[i],
                right[i],
                (i + 1) as u32,
            )
        })
        .collect()
}

pub fn random_indexed_block_with(
    rng: &mut impl RngCore,
    log_single_col_len: u32,
    left_vertex: usize,
    right_vertex: usize,
    builder_index: u32,
) -> Block {
    let mask = (1u64 << log_single_col_len) - 1;
    let mut high = rng.next_u64();
    high = (high & !mask) | left_vertex as u64;
    high = (high & !(mask << 32)) | ((right_vertex as u64) << 32);

    ((high as Block) << 64) | ((rng.next_u32() as Block) << 32) | builder_index as Block
}

pub fn low_u32(block: Block) -> u32 {
    block as u32
}

pub fn reveal_to_party<T, N>(
    share: &Rep3RingShare<T>,
    target: PartyID,
    net: &N,
    state: &Rep3State,
) -> eyre::Result<Option<RingElement<T>>>
where
    T: IntRing2k,
    N: Network,
{
    if state.id == target {
        let missing = net.recv_from::<RingElement<T>>(target.prev())?;
        Ok(Some(share.a ^ share.b ^ missing))
    } else if state.id == target.prev() {
        net.send_to(target, share.b)?;
        Ok(None)
    } else {
        Ok(None)
    }
}

pub fn is_zero_many<T, N>(
    inputs: &[RingShare<T>],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<RingShare<Bit>>>
where
    T: IntRing2k,
    Standard: Distribution<T>,
    N: Network,
{
    let mut values = inputs.iter().map(|x| !x).collect::<Vec<_>>();

    let mut len = T::K;
    debug_assert!(len.is_power_of_two());
    while len > 1 {
        len >>= 1;
        let mask = (RingElement::one() << len) - RingElement::one();
        let lhs = values.iter().map(|x| *x & mask).collect::<Vec<_>>();
        let rhs = values
            .iter()
            .map(|x| {
                let y = x >> len;
                y & mask
            })
            .collect::<Vec<_>>();
        values = and_vec(&lhs, &rhs, net, state)?;
    }

    Ok(values
        .into_iter()
        .map(|x| RingShare {
            a: RingElement(Bit::new((x.a & RingElement::one()) == RingElement::one())),
            b: RingElement(Bit::new((x.b & RingElement::one()) == RingElement::one())),
        })
        .collect())
}

pub fn cmux_many_custom<N: Network>(
    found: &[YShare],
    x: &[XShare],
    y: &[YShare],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<YShare>> {
    let mut masks = Vec::with_capacity(x.len() + y.len());
    masks.extend_from_slice(found);
    masks.extend_from_slice(found);

    let mut values = Vec::with_capacity(x.len() + y.len());
    values.extend(x.iter().copied().map(upcast_x_to_y));
    values.extend_from_slice(y);

    and_vec(&masks, &values, net, state)
}
