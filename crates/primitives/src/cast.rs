//! Casts between the share types used across the DORAM (`x`/alibi bytes packed
//! into 128-bit blocks for shuffling and sorting, ring up/down-casts).

use crate::{AlibiShare, BlockShare, XShare};
use mpc_core::protocols::rep3_ring::{
    Rep3RingShare, casts::downcast, ring::int_ring::IntRing2k, ring::ring_impl::RingElement,
};
use num_traits::AsPrimitive;

pub fn alibi_to_blocks(alibis: &[AlibiShare]) -> Vec<BlockShare> {
    alibis
        .iter()
        .map(|a| {
            BlockShare::new_ring(
                RingElement(u128::from(a.a.0)),
                RingElement(u128::from(a.b.0)),
            )
        })
        .collect()
}

pub fn alibi_from_blocks(blocks: Vec<BlockShare>) -> Vec<AlibiShare> {
    blocks
        .into_iter()
        .map(|b| AlibiShare::new_ring(RingElement(b.a.0 as u8), RingElement(b.b.0 as u8)))
        .collect()
}

pub fn upcast_x_to_block(share: XShare) -> BlockShare {
    BlockShare::new_ring(
        RingElement(u128::from(share.a.0)),
        RingElement(u128::from(share.b.0)),
    )
}

pub fn upcast_x_to_block_many(shares: &[XShare]) -> Vec<BlockShare> {
    shares.iter().copied().map(upcast_x_to_block).collect()
}

pub fn downcast_many<T, U>(shares: Vec<Rep3RingShare<T>>) -> Vec<Rep3RingShare<U>>
where
    T: IntRing2k + AsPrimitive<U>,
    U: IntRing2k,
{
    shares.into_iter().map(downcast).collect()
}
