use std::vec;

use mpc_core::protocols::{
    rep3::Rep3State,
    rep3_ring::{
        arithmetic::{self, RingShare},
        binary::and_vec,
        ring::int_ring::IntRing2k,
    },
};
use mpc_net::Network;
use primitives::{XShare, YShare, bit_to_binary_mask, types::BitShare};
use rand::distributions::{Distribution, Standard};

// TODO: Takes 4 rounds, can we lower
pub fn xy_if_xs_equal_circuit(
    x: &[XShare],
    x_query: &[XShare],
    y: &[YShare],
    net: &impl Network,
    state: &mut Rep3State,
) -> eyre::Result<(Vec<XShare>, Vec<YShare>, Vec<BitShare>)> {
    // TODO: In single round
    let found = x
        .iter()
        .zip(x_query.iter())
        .map(|(x_i, x_q_i)| arithmetic::eq(*x_i, *x_q_i, net, state))
        .collect::<eyre::Result<Vec<_>>>()?;

    let found_x = found
        .iter()
        .map(bit_to_binary_mask)
        .collect::<Vec<XShare>>();
    let found_y = found
        .iter()
        .map(bit_to_binary_mask)
        .collect::<Vec<YShare>>();

    // TODO: In single round
    let x_if_xs_equal = cmux_many(&found_x, x, &vec![XShare::default(); x.len()], net, state)?;
    let y_if_xs_equal = cmux_many(&found_y, y, &vec![YShare::default(); y.len()], net, state)?;

    Ok((x_if_xs_equal, y_if_xs_equal, found))
}

/// Computes a CMUX: If `c` is `1`, returns `x_t`, otherwise returns `x_f`.
pub fn cmux_many<T: IntRing2k, N: Network>(
    c: &[RingShare<T>],
    x_t: &[RingShare<T>],
    x_f: &[RingShare<T>],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<RingShare<T>>>
where
    Standard: Distribution<T>,
{
    let xor = x_f
        .iter()
        .zip(x_t.iter())
        .map(|(f, t)| f ^ t)
        .collect::<Vec<_>>();
    let and = and_vec(c, &xor, net, state)?;
    let result = and
        .iter()
        .zip(x_f.iter())
        .map(|(a, f)| a ^ f)
        .collect::<Vec<_>>();
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mpc_core::protocols::{
        rep3::{conversion::A2BType, id::PartyID},
        rep3_ring::{Rep3RingShare, binary, ring::ring_impl::RingElement},
    };
    use mpc_net::local::LocalNetwork;

    #[test]
    fn test_xy_if_xs_equal_circuit() {
        let xs = vec![7u32, 8, 7];
        let query = vec![7u32; xs.len()];
        let ys = vec![70u64, 80, 72];
        let networks = LocalNetwork::new_3_parties();

        std::thread::scope(|scope| {
            let handles = networks
                .into_iter()
                .map(|network| {
                    let xs = xs.clone();
                    let query = query.clone();
                    let ys = ys.clone();
                    scope.spawn(move || {
                        let mut state = Rep3State::new(&network, A2BType::Direct).unwrap();
                        let x_shares = promote_public_values(&xs, state.id);
                        let query_shares = promote_public_values(&query, state.id);
                        let y_shares = promote_public_values(&ys, state.id);

                        let (x_out, y_out, found) = xy_if_xs_equal_circuit(
                            &x_shares,
                            &query_shares,
                            &y_shares,
                            &network,
                            &mut state,
                        )
                        .unwrap();

                        (
                            open_binary_values(&x_out, &network),
                            open_binary_values(&y_out, &network),
                            found
                                .iter()
                                .map(|share| binary::open(share, &network).unwrap().0.convert())
                                .collect::<Vec<_>>(),
                        )
                    })
                })
                .collect::<Vec<_>>();

            let [(x0, y0, f0), (x1, y1, f1), (x2, y2, f2)] = handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .collect::<Vec<_>>()
                .try_into()
                .expect("three party outputs");

            let expected_x = vec![7, 0, 7];
            let expected_y = vec![70, 0, 72];
            let expected_found = vec![true, false, true];
            for (x, y, found) in [(x0, y0, f0), (x1, y1, f1), (x2, y2, f2)] {
                assert_eq!(x, expected_x);
                assert_eq!(y, expected_y);
                assert_eq!(found, expected_found);
            }
        });
    }

    fn promote_public_values<T: mpc_core::protocols::rep3_ring::ring::int_ring::IntRing2k>(
        values: &[T],
        id: PartyID,
    ) -> Vec<Rep3RingShare<T>> {
        values
            .iter()
            .map(|value| binary::promote_to_trivial_share(id, &RingElement(*value)))
            .collect()
    }

    fn open_binary_values<T, N>(shares: &[Rep3RingShare<T>], network: &N) -> Vec<T>
    where
        T: mpc_core::protocols::rep3_ring::ring::int_ring::IntRing2k,
        N: Network,
    {
        shares
            .iter()
            .map(|share| binary::open(share, network).unwrap().0)
            .collect()
    }
}
