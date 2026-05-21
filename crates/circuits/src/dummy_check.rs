use mpc_core::protocols::{rep3::Rep3State, rep3_ring::binary};
use mpc_net::Network;
use primitives::{BitShare, X, XShare, is_zero_many};

use crate::network::CircuitNetwork;

pub fn dummy_check_circuit<N: CircuitNetwork>(
    xs: &[XShare],
    log_n: usize,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<BitShare>> {
    net.evaluate_dummy_check(xs, log_n, state)
}

pub(crate) fn dummy_check_circuit_serial<N: Network>(
    xs: &[XShare],
    log_n: usize,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<BitShare>> {
    assert!(log_n < X::BITS as usize);

    let x_is_zero = is_zero_many(xs, net, state)?;
    Ok(x_is_zero
        .into_iter()
        .zip(xs)
        .map(|(is_zero, x)| binary::xor(&is_zero, &x.get_bit(log_n)))
        .collect())
}
