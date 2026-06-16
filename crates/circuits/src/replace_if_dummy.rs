use mpc_core::protocols::{rep3::Rep3State, rep3_ring::binary};
use mpc_net::Network;
use primitives::{XShare, bit_to_binary_mask};

pub fn replace_if_dummy_circuit<N: Network>(
    xs: &[XShare],
    replacements: &[XShare],
    log_n: usize,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<XShare>> {
    assert_eq!(xs.len(), replacements.len());

    let masks = xs
        .iter()
        .map(|x| bit_to_binary_mask(&x.get_bit(log_n)))
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
