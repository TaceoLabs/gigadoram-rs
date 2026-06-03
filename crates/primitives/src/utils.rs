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
use num_traits::AsPrimitive;
use rand::{
    Rng,
    distributions::{Distribution, Standard},
    seq::SliceRandom,
    thread_rng,
};
use std::any::TypeId;

use crate::{Block, XShare, YShare, upcast_x_to_y};

pub fn run_parties<R, F>(f: F) -> std::thread::Result<[R; 3]>
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

        let r0 = party_0.join();
        let r1 = party_1.join();
        let r2 = party_2.join();
        Ok([r0?, r1?, r2?])
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

pub fn random_indexed_block(
    log_single_col_len: u32,
    left_vertex: usize,
    right_vertex: usize,
    builder_index: u32,
) -> Block {
    let mut rng = thread_rng();
    let mask = (1u64 << log_single_col_len) - 1;
    let mut high: u64 = rng.r#gen();
    high = (high & !mask) | left_vertex as u64;
    high = (high & !(mask << 32)) | ((right_vertex as u64) << 32);

    ((high as Block) << 64) | ((rng.r#gen::<u32>() as Block) << 32) | builder_index as Block
}

pub fn random_indexed_blocks(log_single_col_len: u32, count: usize) -> Vec<Block> {
    let mut rng = thread_rng();
    let column_len = 1usize << log_single_col_len;
    let mut left = (0..column_len).collect::<Vec<_>>();
    let mut right = (0..column_len).collect::<Vec<_>>();

    left.shuffle(&mut rng);
    right.shuffle(&mut rng);

    let mask = (1u64 << log_single_col_len) - 1;
    (0..count)
        .map(|i| {
            let mut high: u64 = rng.r#gen();
            high = (high & !mask) | left[i] as u64;
            high = (high & !(mask << 32)) | ((right[i] as u64) << 32);
            ((high as Block) << 64) | ((rng.r#gen::<u32>() as Block) << 32) | (i + 1) as Block
        })
        .collect()
}

pub fn low_u32(block: Block) -> u32 {
    block as u32
}

pub fn set_low_u32(block: Block, low: u32) -> Block {
    (block & !(u32::MAX as Block)) | low as Block
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
    T: IntRing2k + 'static,
    Standard: Distribution<T>,
    N: Network,
{
    let values = inputs.iter().map(|x| !x).collect::<Vec<_>>();

    if TypeId::of::<T>() == TypeId::of::<u128>() {
        let values =
            unsafe { std::mem::transmute::<Vec<RingShare<T>>, Vec<RingShare<u128>>>(values) };

        let values = fold_zero_stage_many::<u128, u64, _>(values, 64, net, state)?;
        let values = fold_zero_stage_many::<u64, u32, _>(values, 32, net, state)?;
        let values = fold_zero_stage_many::<u32, u16, _>(values, 16, net, state)?;
        let values = fold_zero_stage_many::<u16, u8, _>(values, 8, net, state)?;
        let values = fold_zero_stage_many::<u8, u8, _>(values, 4, net, state)?;
        let values = fold_zero_stage_many::<u8, u8, _>(values, 2, net, state)?;
        let values = fold_zero_stage_many::<u8, u8, _>(values, 1, net, state)?;
        Ok(values.into_iter().map(|value| value.get_bit(0)).collect())
    } else if TypeId::of::<T>() == TypeId::of::<u64>() {
        let values =
            unsafe { std::mem::transmute::<Vec<RingShare<T>>, Vec<RingShare<u64>>>(values) };

        let values = fold_zero_stage_many::<u64, u32, _>(values, 32, net, state)?;
        let values = fold_zero_stage_many::<u32, u16, _>(values, 16, net, state)?;
        let values = fold_zero_stage_many::<u16, u8, _>(values, 8, net, state)?;
        let values = fold_zero_stage_many::<u8, u8, _>(values, 4, net, state)?;
        let values = fold_zero_stage_many::<u8, u8, _>(values, 2, net, state)?;
        let values = fold_zero_stage_many::<u8, u8, _>(values, 1, net, state)?;
        Ok(values.into_iter().map(|value| value.get_bit(0)).collect())
    } else if TypeId::of::<T>() == TypeId::of::<u32>() {
        let values =
            unsafe { std::mem::transmute::<Vec<RingShare<T>>, Vec<RingShare<u32>>>(values) };

        let values = fold_zero_stage_many::<u32, u16, _>(values, 16, net, state)?;
        let values = fold_zero_stage_many::<u16, u8, _>(values, 8, net, state)?;
        let values = fold_zero_stage_many::<u8, u8, _>(values, 4, net, state)?;
        let values = fold_zero_stage_many::<u8, u8, _>(values, 2, net, state)?;
        let values = fold_zero_stage_many::<u8, u8, _>(values, 1, net, state)?;
        Ok(values.into_iter().map(|value| value.get_bit(0)).collect())
    } else if TypeId::of::<T>() == TypeId::of::<u16>() {
        let values =
            unsafe { std::mem::transmute::<Vec<RingShare<T>>, Vec<RingShare<u16>>>(values) };

        let values = fold_zero_stage_many::<u16, u8, _>(values, 8, net, state)?;
        let values = fold_zero_stage_many::<u8, u8, _>(values, 4, net, state)?;
        let values = fold_zero_stage_many::<u8, u8, _>(values, 2, net, state)?;
        let values = fold_zero_stage_many::<u8, u8, _>(values, 1, net, state)?;
        Ok(values.into_iter().map(|value| value.get_bit(0)).collect())
    } else if TypeId::of::<T>() == TypeId::of::<u8>() {
        let values =
            unsafe { std::mem::transmute::<Vec<RingShare<T>>, Vec<RingShare<u8>>>(values) };

        let values = fold_zero_stage_many::<u8, u8, _>(values, 4, net, state)?;
        let values = fold_zero_stage_many::<u8, u8, _>(values, 2, net, state)?;
        let values = fold_zero_stage_many::<u8, u8, _>(values, 1, net, state)?;
        Ok(values.into_iter().map(|value| value.get_bit(0)).collect())
    } else {
        panic!("is_zero_many is not implemented for this ring type");
    }
}

fn fold_zero_stage_many<T, U, N>(
    values: Vec<RingShare<T>>,
    shift: usize,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<RingShare<U>>>
where
    T: IntRing2k,
    U: IntRing2k + 'static,
    T: AsPrimitive<U>,
    Standard: Distribution<U>,
    N: Network,
{
    let local = values
        .into_iter()
        .map(|value| {
            let (mut mask, mask_b) = state.rngs.rand.random_elements::<RingElement<U>>();
            mask ^= mask_b;

            let high_a = value.a >> shift;
            let high_b = value.b >> shift;
            mask ^= RingElement((value.a & high_a).0.as_());
            mask ^= RingElement((value.b & high_a).0.as_());
            mask ^= RingElement((value.a & high_b).0.as_());
            mask
        })
        .collect::<Vec<_>>();
    let next = net.reshare_many(&local)?;
    Ok(local
        .into_iter()
        .zip(next)
        .map(|(a, b)| RingShare::new_ring(a, b))
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
