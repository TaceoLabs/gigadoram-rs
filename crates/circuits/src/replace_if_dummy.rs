use mpc_core::protocols::{rep3::Rep3State, rep3_ring::binary};
use mpc_net::Network;
use primitives::{XShare, bit_to_binary_mask};

use crate::dummy_check::dummy_check_circuit;

pub fn replace_if_dummy_circuit<N: Network>(
    xs: &[XShare],
    replacements: &[XShare],
    log_n: usize,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<XShare>> {
    assert_eq!(xs.len(), replacements.len());

    let is_dummy = dummy_check_circuit(xs, log_n, net, state)?;
    let masks = is_dummy
        .iter()
        .map(bit_to_binary_mask)
        .collect::<Vec<XShare>>();
    let deltas = xs
        .iter()
        .zip(replacements)
        .map(|(x, replacement)| *x ^ *replacement)
        .collect::<Vec<_>>();
    let selected_deltas = binary::and_vec(&masks, &deltas, net, state)?;

    Ok(xs
        .iter()
        .zip(selected_deltas)
        .map(|(x, delta)| *x ^ delta)
        .collect())
}
