use crate::{BlockShare, XShare, YShare};
use mpc_core::protocols::rep3_ring::{
    Rep3RingShare, casts::downcast, ring::int_ring::IntRing2k, ring::ring_impl::RingElement,
};
use num_traits::AsPrimitive;

pub fn upcast_x_to_y(share: XShare) -> YShare {
    YShare::new_ring(
        RingElement(u64::from(share.a.0)),
        RingElement(u64::from(share.b.0)),
    )
}

pub fn upcast_x_to_block(share: XShare) -> BlockShare {
    BlockShare::new_ring(
        RingElement(u128::from(share.a.0)),
        RingElement(u128::from(share.b.0)),
    )
}

pub fn upcast_y_to_block(share: YShare) -> BlockShare {
    BlockShare::new_ring(
        RingElement(u128::from(share.a.0)),
        RingElement(u128::from(share.b.0)),
    )
}

pub fn upcast_x_to_block_many(shares: &[XShare]) -> Vec<BlockShare> {
    shares.iter().copied().map(upcast_x_to_block).collect()
}

pub fn upcast_y_to_block_many(shares: &[YShare]) -> Vec<BlockShare> {
    shares.iter().copied().map(upcast_y_to_block).collect()
}

pub fn downcast_many<T, U>(shares: Vec<Rep3RingShare<T>>) -> Vec<Rep3RingShare<U>>
where
    T: IntRing2k + AsPrimitive<U>,
    U: IntRing2k,
{
    shares.into_iter().map(downcast).collect()
}
