//! MPC circuits used by GigaDoram.
//!
//! Includes LowMC PRF evaluation ([`lowmc`], with a fused SpeedCache variant),
//! oblivious sorting ([`batcher`]), CHT lookups ([`cht_lookup`]),
//! and [`xy_if_xs_equal`], [`replace_if_dummy`].

pub mod batcher;
pub mod cht_lookup;
pub mod lowmc;
pub mod replace_if_dummy;
pub mod xy_if_xs_equal;
