//! Circuit helper for cache lookups.
//! For each row, it checks whether `x == x_query` and returns masked `x`, masked
//! `y`, and a found bit for the matching rows.

use mpc_core::protocols::{rep3::Rep3State, rep3_ring::casts::downcast};
use mpc_net::Network;
use primitives::{
    XShare, YShare, bit_to_binary_mask, cmux_many_custom, is_zero_many, types::BitShare,
};

pub fn xy_if_xs_equal_circuit(
    x: &[XShare],
    x_query: &[XShare],
    y: &[YShare],
    net: &impl Network,
    state: &mut Rep3State,
) -> eyre::Result<(Vec<XShare>, Vec<YShare>, Vec<BitShare>)> {
    assert_eq!(x.len(), x_query.len());
    assert_eq!(x.len(), y.len());

    let xor = x
        .iter()
        .zip(x_query.iter())
        .map(|(x_i, x_q_i)| x_i ^ x_q_i)
        .collect::<Vec<_>>();
    let found = is_zero_many(&xor, net, state)?;

    let found_y = found
        .iter()
        .map(bit_to_binary_mask)
        .collect::<Vec<YShare>>();

    let selected = cmux_many_custom(&found_y, x, y, net, state)?;

    let x_if_xs_equal = selected[..x.len()]
        .iter()
        .copied()
        .map(downcast)
        .collect::<Vec<XShare>>();
    let y_if_xs_equal = selected[x.len()..].to_vec();

    Ok((x_if_xs_equal, y_if_xs_equal, found))
}
