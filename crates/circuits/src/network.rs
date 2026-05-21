use eyre::Result;
use mpc_core::protocols::rep3::Rep3State;
use mpc_net::{Network, local::LocalNetwork, tcp::TcpNetwork};
use primitives::{XShare, YShare, types::BitShare};

use crate::{
    batcher::compare_swap_dummy_pairs_serial, dummy_check::dummy_check_circuit_serial,
    replace_if_dummy::replace_if_dummy_circuit_serial,
    xy_if_xs_equal::xy_if_xs_equal_circuit_serial,
};

pub trait CircuitNetwork: Network + Sized {
    fn evaluate_dummy_check(
        &self,
        xs: &[XShare],
        log_n: usize,
        state: &mut Rep3State,
    ) -> Result<Vec<BitShare>> {
        dummy_check_circuit_serial(xs, log_n, self, state)
    }

    fn evaluate_replace_if_dummy(
        &self,
        xs: &[XShare],
        replacements: &[XShare],
        log_n: usize,
        state: &mut Rep3State,
    ) -> Result<Vec<XShare>> {
        replace_if_dummy_circuit_serial(xs, replacements, log_n, self, state)
    }

    fn evaluate_xy_if_xs_equal(
        &self,
        x: &[XShare],
        x_query: &[XShare],
        y: &[YShare],
        state: &mut Rep3State,
    ) -> Result<(Vec<XShare>, Vec<YShare>, Vec<BitShare>)> {
        xy_if_xs_equal_circuit_serial(x, x_query, y, self, state)
    }

    fn compare_swap_dummy_pairs(
        &self,
        pairs: &[(usize, usize)],
        dummy_flags: &mut [BitShare],
        xs: &mut [XShare],
        ys: &mut [YShare],
        state: &mut Rep3State,
    ) -> Result<()> {
        compare_swap_dummy_pairs_serial(pairs, dummy_flags, xs, ys, self, state)
    }
}

impl CircuitNetwork for LocalNetwork {}
impl CircuitNetwork for TcpNetwork {}
