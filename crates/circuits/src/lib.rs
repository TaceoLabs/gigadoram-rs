//! MPC circuits used by GigaDoram.
//!
//! Includes LowMC PRF evaluation ([`lowmc`], with a fused SpeedCache variant),
//! oblivious sorting ([`oblivious_sort`]), CHT lookups ([`cht_lookup`]),
//! and [`xy_if_xs_equal`], [`replace_if_dummy`].

pub mod cht_lookup;
pub mod lowmc;
pub mod oblivious_sort;
pub mod replace_if_dummy;
pub mod xy_if_xs_equal;
