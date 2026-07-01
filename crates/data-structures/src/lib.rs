//! Oblivious data structures backing GigaDoram.
//!
//! [`ohtable`] is the oblivious hash table that holds each DORAM level, built on
//! the cuckoo hash table in [`cht`]; [`speed_cache`] is the small linear cache of
//! recently accessed entries. All are generic over the stored [`primitives::DoramValue`].

pub mod cht;
pub mod ohtable;
pub mod speed_cache;

pub use cht::*;
pub use ohtable::{
    OHTableParams, ObliviousHashTable, OhTable, OhTableParams, OhTableQueryTiming, OhTableTiming,
};
pub use speed_cache::SpeedCache;
