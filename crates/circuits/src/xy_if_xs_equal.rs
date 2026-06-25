//! Circuit helper for cache lookups.
//! For each row, it checks whether `x == x_query` and returns masked `x`, masked
//! `y`, masked alibi byte, and a found bit for the matching rows.

use mpc_core::protocols::rep3::Rep3State;
use mpc_net::Network;
use primitives::{AlibiShare, DoramValue, XShare, cmux_many_custom, is_zero_many, types::BitShare};

#[expect(clippy::type_complexity)]
pub fn xy_if_xs_equal_circuit<V: DoramValue>(
    x: &[XShare],
    x_query: &[XShare],
    y: &[V::Share],
    alibi: &[AlibiShare],
    net: &impl Network,
    state: &mut Rep3State,
) -> eyre::Result<(Vec<XShare>, Vec<V::Share>, Vec<AlibiShare>, Vec<BitShare>)> {
    assert_eq!(x.len(), x_query.len());
    assert_eq!(x.len(), y.len());
    assert_eq!(x.len(), alibi.len());

    let xor = x
        .iter()
        .zip(x_query.iter())
        .map(|(x_i, x_q_i)| x_i ^ x_q_i)
        .collect::<Vec<_>>();
    let found = is_zero_many(&xor, net, state)?;

    let (x_if_xs_equal, y_if_xs_equal, alibi_if_xs_equal) =
        cmux_many_custom::<V, _>(&found, x, y, alibi, net, state)?;

    Ok((x_if_xs_equal, y_if_xs_equal, alibi_if_xs_equal, found))
}
