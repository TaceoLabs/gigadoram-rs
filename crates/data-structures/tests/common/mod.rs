#![allow(dead_code)]

use mpc_net::local::LocalNetwork;
use primitives::Block;
use rand::{RngCore, seq::SliceRandom, thread_rng};

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

pub fn low_u32(block: Block) -> u32 {
    block as u32
}

fn random_block_with(rng: &mut impl RngCore) -> Block {
    (Block::from(rng.next_u64()) << 64) | Block::from(rng.next_u64())
}

fn random_indexed_block_with(
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
