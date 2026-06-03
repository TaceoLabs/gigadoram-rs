use crate::{AlibiShare, BlockShare, XShare, YShare};
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

pub fn upcast_x_to_y(share: XShare) -> YShare {
    let mut a = crate::Y::default();
    let mut b = crate::Y::default();
    a.as_mut()[0] = u64::from(share.a.0);
    b.as_mut()[0] = u64::from(share.b.0);
    YShare::new(a, b)
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

pub fn downcast_y_to_x_many(shares: Vec<YShare>) -> Vec<XShare> {
    shares
        .into_iter()
        .map(|share| {
            XShare::new_ring(
                RingElement(share.a.as_ref()[0] as crate::X),
                RingElement(share.b.as_ref()[0] as crate::X),
            )
        })
        .collect()
}

pub fn y_to_block_pairs(shares: &[YShare]) -> (Vec<BlockShare>, Vec<BlockShare>) {
    let mut low = Vec::with_capacity(shares.len());
    let mut high = Vec::with_capacity(shares.len());
    for share in shares {
        low.push(BlockShare::new_ring(
            RingElement(pack_limbs(share.a.as_ref(), 0)),
            RingElement(pack_limbs(share.b.as_ref(), 0)),
        ));
        high.push(BlockShare::new_ring(
            RingElement(pack_limbs(share.a.as_ref(), 2)),
            RingElement(pack_limbs(share.b.as_ref(), 2)),
        ));
    }
    (low, high)
}

pub fn y_from_block_pairs(low: Vec<BlockShare>, high: Vec<BlockShare>) -> Vec<YShare> {
    low.into_iter()
        .zip(high)
        .map(|(low, high)| {
            let mut a = crate::Y::default();
            let mut b = crate::Y::default();
            unpack_limbs(low.a.0, &mut a.as_mut()[..2]);
            unpack_limbs(low.b.0, &mut b.as_mut()[..2]);
            unpack_limbs(high.a.0, &mut a.as_mut()[2..4]);
            unpack_limbs(high.b.0, &mut b.as_mut()[2..4]);
            YShare::new(a, b)
        })
        .collect()
}

fn pack_limbs(limbs: &[u64], start: usize) -> u128 {
    u128::from(limbs[start]) | (u128::from(limbs[start + 1]) << 64)
}

fn unpack_limbs(value: u128, limbs: &mut [u64]) {
    limbs[0] = value as u64;
    limbs[1] = (value >> 64) as u64;
}
