use std::{ vec};

use mpc_core::protocols::{
    rep3::Rep3State,
    rep3_ring::{
        Rep3RingShare, arithmetic::{self, RingShare, eq}, binary::{self, and_vec}, casts::downcast, ring::{bit::Bit, int_ring::IntRing2k, ring_impl::RingElement}, yao::upcast_many
    },
};
use mpc_net::Network;
use primitives::{ XShare, YShare, types::BitShare};
use rand::distributions::{Distribution, Standard};

// TODO: Takes 4 rounds, can we lower it?
pub fn xy_if_xs_equal_circuit(
    x: &[XShare],
    x_query: &[XShare],
    y: &[YShare],
    net: &impl Network,
    state: &mut Rep3State,
) -> eyre::Result<(Vec<XShare>, Vec<YShare>, Vec<BitShare>)> {
    // TODO: In single round
    let found = x.iter()
        .zip(x_query.iter())
        .map(|(x_i, x_q_i)| arithmetic::eq(*x_i, *x_q_i, net, state))
        .collect::<eyre::Result<Vec<_>>>()?;

    // TODO: In single round
    let found_y: Vec<YShare> = upcast_many(&found, net, state)?;
    let found_x: Vec<XShare> = found_y.iter().map(|&b| downcast(b)).collect();

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
    let xor = x_f.iter().zip(x_t.iter()).map(|(f, t)| f ^ t).collect::<Vec<_>>();
    let and = and_vec(c, &xor, net, state)?;
    let result = and.iter().zip(x_f.iter()).map(|(a, f)| a ^ f).collect::<Vec<_>>();
    Ok(result)
}