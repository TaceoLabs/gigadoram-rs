use eyre::Result;
use mpc_core::protocols::{
    rep3::{Rep3State, id::PartyID, network::Rep3NetworkExt},
    rep3_ring::{
        Rep3RingShare, arithmetic, conversion,
        ring::{bit::Bit, ring_impl::RingElement},
    },
};
use mpc_net::Network;
use primitives::{
    AlibiShare, BitShare, Block, BlockShare, DoramValue, X, XShare, alibi_from_blocks,
    alibi_to_blocks,
};

type PermRing = u32;

/// Oblivious stable sort that moves dummy rows to the end while keeping the
/// `(x, value, alibi)` columns aligned.
///
/// We use the algorithm described in <https://eprint.iacr.org/2019/695.pdf>.
pub struct ObliviousSort;

impl ObliviousSort {
    pub fn sort<V: DoramValue, N: Network>(
        dummy_flags: &mut [BitShare],
        xs: &mut [XShare],
        ys: &mut [V::Share],
        alibis: &mut [AlibiShare],
        net: &N,
        state: &mut Rep3State,
    ) -> Result<()> {
        debug_assert_eq!(xs.len(), dummy_flags.len());
        debug_assert_eq!(ys.len(), dummy_flags.len());
        debug_assert_eq!(alibis.len(), dummy_flags.len());

        let bits = conversion::bit_inject_from_bits_many::<PermRing, _>(dummy_flags, net, state)?;
        let perm = gen_bit_perm(bits, net, state)?;
        let rows = dummy_flags
            .iter()
            .zip(xs.iter())
            .map(|(flag, x)| pack_row(*flag, *x))
            .collect::<Vec<_>>();
        let value_blocks = V::to_blocks(ys);
        let alibi_blocks = alibi_to_blocks(alibis);

        let mut row_sets: Vec<&[BlockShare]> = Vec::with_capacity(2 + value_blocks.len());
        row_sets.push(&rows);
        row_sets.extend(value_blocks.iter().map(Vec::as_slice));
        row_sets.push(&alibi_blocks);

        let mut sorted = apply_inv_many(&perm, &row_sets, net, state)?.into_iter();

        for (i, row) in sorted.next().unwrap().into_iter().enumerate() {
            let (flag, x) = unpack_row(row);
            dummy_flags[i] = flag;
            xs[i] = x;
        }
        let value_cols = (0..V::NUM_BLOCKS)
            .map(|_| sorted.next().unwrap())
            .collect::<Vec<_>>();
        ys.clone_from_slice(&V::from_blocks(value_cols));
        alibis.clone_from_slice(&alibi_from_blocks(sorted.next().unwrap()));
        Ok(())
    }
}

fn gen_bit_perm<N: Network>(
    bits: Vec<Rep3RingShare<PermRing>>,
    net: &N,
    state: &mut Rep3State,
) -> Result<Vec<Rep3RingShare<PermRing>>> {
    let mut zeros = Vec::with_capacity(bits.len());
    let mut ones = Vec::with_capacity(bits.len());
    for bit in bits {
        zeros.push(arithmetic::add_public(-bit, RingElement(1), state.id));
        ones.push(bit);
    }

    let mut sum = Rep3RingShare::zero_share();
    let mut zero_counts = Vec::with_capacity(zeros.len());
    let mut one_counts = Vec::with_capacity(ones.len());
    for zero in &zeros {
        sum = arithmetic::add(sum, *zero);
        zero_counts.push(sum);
    }
    for one in &ones {
        sum = arithmetic::add(sum, *one);
        one_counts.push(sum);
    }

    let zero_positions = arithmetic::local_mul_vec(&zeros, &zero_counts, state);
    let one_positions = arithmetic::local_mul_vec(&ones, &one_counts, state);
    arithmetic::reshare_vec(
        zero_positions
            .into_iter()
            .zip(one_positions)
            .map(|(zero, one)| zero + one)
            .collect(),
        net,
    )
}

fn apply_inv_many<N: Network>(
    rho: &[Rep3RingShare<PermRing>],
    row_sets: &[&[BlockShare]],
    net: &N,
    state: &mut Rep3State,
) -> Result<Vec<Vec<BlockShare>>> {
    let unshuffled = (0..rho.len() as PermRing).collect::<Vec<_>>();
    let (perm_a, perm_b) = state.rngs.rand.random_perm(unshuffled);
    let perm = perm_a
        .into_iter()
        .zip(perm_b)
        .map(|(a, b)| Rep3RingShare::new(a, b))
        .collect::<Vec<_>>();

    let opened = shuffle_reveal_perm(&perm, rho, net, state)?;
    let shuffled_sets = shuffle_rows_many(&perm, row_sets, net, state)?;
    let mut results = Vec::with_capacity(row_sets.len());
    for shuffled in shuffled_sets {
        let mut result = vec![BlockShare::zero_share(); rho.len()];
        for (position, row) in opened.iter().copied().zip(shuffled) {
            result[position.0 as usize - 1] = row;
        }
        results.push(result);
    }
    Ok(results)
}

fn shuffle_rows_many<N: Network>(
    pi: &[Rep3RingShare<PermRing>],
    inputs: &[&[BlockShare]],
    net: &N,
    state: &mut Rep3State,
) -> Result<Vec<Vec<BlockShare>>> {
    let len = pi.len();

    Ok(match state.id {
        PartyID::ID0 => {
            let mut shuffled_3_all = Vec::with_capacity(inputs.len() * len);
            for input in inputs {
                let mut alpha_1 = Vec::with_capacity(len);
                let mut alpha_3 = Vec::with_capacity(len);
                let mut beta_1 = Vec::with_capacity(len);
                for row in *input {
                    let (a1, a3) = state.rngs.rand.random_elements::<RingElement<Block>>();
                    alpha_1.push(a1);
                    alpha_3.push(a3);
                    beta_1.push(row.a ^ row.b);
                }

                let mut shuffled_1 = Vec::with_capacity(len);
                for (pi, alpha) in pi.iter().zip(alpha_1.iter()) {
                    shuffled_1.push(beta_1[pi.a.0 as usize] ^ alpha);
                }
                let mut shuffled_3 = alpha_1;
                for (dst, (pi, alpha)) in shuffled_3.iter_mut().zip(pi.iter().zip(alpha_3)) {
                    *dst = shuffled_1[pi.b.0 as usize] ^ alpha;
                }
                shuffled_3_all.extend(shuffled_3);
            }
            net.send_next_many(&shuffled_3_all)?;

            (0..inputs.len())
                .map(|_| {
                    (0..len)
                        .map(|_| {
                            let (a, b) = state.rngs.rand.random_elements::<RingElement<Block>>();
                            BlockShare::new_ring(a, b)
                        })
                        .collect()
                })
                .collect()
        }
        PartyID::ID1 => {
            let mut beta_sets = Vec::with_capacity(inputs.len());
            let mut shuffled_1_all = Vec::with_capacity(inputs.len() * len);
            for input in inputs {
                let mut alpha_1 = Vec::with_capacity(len);
                let mut beta_2 = Vec::with_capacity(len);
                for row in *input {
                    alpha_1.push(state.rngs.rand.random_element_rng2::<RingElement<Block>>());
                    beta_2.push(row.a);
                }

                for (pi, alpha) in pi.iter().zip(alpha_1) {
                    shuffled_1_all.push(beta_2[pi.b.0 as usize] ^ alpha);
                }
                beta_sets.push(beta_2);
            }
            let delta_all = net.reshare_many(&shuffled_1_all)?;

            let mut results = Vec::with_capacity(inputs.len());
            let mut rand_all = Vec::with_capacity(inputs.len() * len);
            for (set, beta_2) in beta_sets.iter_mut().enumerate() {
                let delta = &delta_all[(set * len)..((set + 1) * len)];
                for (dst, pi) in beta_2.iter_mut().zip(pi) {
                    *dst = delta[pi.a.0 as usize];
                }

                let mut result = Vec::with_capacity(len);
                for beta in beta_2 {
                    let b = state.rngs.rand.random_element_rng2::<RingElement<Block>>();
                    rand_all.push(*beta ^ b);
                    result.push(BlockShare::new_ring(RingElement::default(), b));
                }
                results.push(result);
            }
            let rcv_all: Vec<RingElement<Block>> =
                net.send_and_recv_many(PartyID::ID2, &rand_all, PartyID::ID2)?;
            for (result, (rcv, rand)) in results
                .iter_mut()
                .zip(rcv_all.chunks_exact(len).zip(rand_all.chunks_exact(len)))
            {
                for (res, (&r1, &r2)) in result.iter_mut().zip(rcv.iter().zip(rand)) {
                    res.a = r1 ^ r2;
                }
            }
            results
        }
        PartyID::ID2 => {
            let mut alpha_sets = Vec::with_capacity(inputs.len());
            for _ in inputs {
                let mut alpha_3 = Vec::with_capacity(len);
                for _ in 0..len {
                    alpha_3.push(state.rngs.rand.random_element_rng1::<RingElement<Block>>());
                }
                alpha_sets.push(alpha_3);
            }

            let gamma_all: Vec<RingElement<Block>> = net.recv_prev_many()?;
            debug_assert_eq!(gamma_all.len(), inputs.len() * len);

            let mut beta_sets = Vec::with_capacity(inputs.len());
            for (gamma, mut alpha_3) in gamma_all.chunks_exact(len).zip(alpha_sets) {
                let mut shuffled_1 = Vec::with_capacity(len);
                for (pi, alpha) in pi.iter().zip(alpha_3.iter()) {
                    shuffled_1.push(gamma[pi.a.0 as usize] ^ alpha);
                }
                for (dst, pi) in alpha_3.iter_mut().zip(pi) {
                    *dst = shuffled_1[pi.b.0 as usize];
                }
                beta_sets.push(alpha_3);
            }

            let mut results = Vec::with_capacity(inputs.len());
            let mut rand_all = Vec::with_capacity(inputs.len() * len);
            for beta_set in beta_sets {
                let mut result = Vec::with_capacity(len);
                for beta in beta_set {
                    let a = state.rngs.rand.random_element_rng1::<RingElement<Block>>();
                    rand_all.push(beta ^ a);
                    result.push(BlockShare::new_ring(a, RingElement::default()));
                }
                results.push(result);
            }
            let rcv_all: Vec<RingElement<Block>> =
                net.send_and_recv_many(PartyID::ID1, &rand_all, PartyID::ID1)?;
            for (result, (rcv, rand)) in results
                .iter_mut()
                .zip(rcv_all.chunks_exact(len).zip(rand_all.chunks_exact(len)))
            {
                for (res, (&r1, &r2)) in result.iter_mut().zip(rcv.iter().zip(rand)) {
                    res.b = r1 ^ r2;
                }
            }
            results
        }
    })
}

fn shuffle_reveal_perm<N: Network>(
    pi: &[Rep3RingShare<PermRing>],
    input: &[Rep3RingShare<PermRing>],
    net: &N,
    state: &mut Rep3State,
) -> Result<Vec<RingElement<PermRing>>> {
    let len = pi.len();
    Ok(match state.id {
        PartyID::ID0 => {
            // has p1, p3
            let mut alpha_1 = Vec::with_capacity(len);
            let mut beta_1 = Vec::with_capacity(len);
            for row in input {
                alpha_1.push(
                    state
                        .rngs
                        .rand
                        .random_element_rng1::<RingElement<PermRing>>(),
                );
                beta_1.push(row.a + row.b);
            }
            // shuffle
            let mut shuffled = Vec::with_capacity(len);
            for (pi, alpha) in pi.iter().zip(alpha_1.iter()) {
                shuffled.push(beta_1[pi.a.0 as usize] - alpha);
            }
            net.send_and_recv_many(PartyID::ID2, &shuffled, PartyID::ID2)?
        }
        PartyID::ID1 => {
            // has p2, p1
            let mut alpha_1 = Vec::with_capacity(len);
            let mut beta_2 = Vec::with_capacity(len);
            for row in input {
                alpha_1.push(
                    state
                        .rngs
                        .rand
                        .random_element_rng2::<RingElement<PermRing>>(),
                );
                beta_2.push(row.a);
            }
            // shuffle
            let mut shuffled = Vec::with_capacity(len);
            for (pi, alpha) in pi.iter().zip(alpha_1) {
                shuffled.push(beta_2[pi.b.0 as usize] + alpha);
            }
            net.send_and_recv_many(PartyID::ID2, &shuffled, PartyID::ID2)?
        }
        PartyID::ID2 => {
            let delta = net.recv_many::<RingElement<PermRing>>(PartyID::ID0)?;
            let gamma = net.recv_many::<RingElement<PermRing>>(PartyID::ID1)?;
            // shuffle
            let mut shuffled = Vec::with_capacity(len);
            for p in pi {
                let index = pi[p.b.0 as usize].a.0 as usize;
                shuffled.push(gamma[index] + delta[index]);
            }
            let (send0, send1) = mpc_net::join(
                || net.send_many(PartyID::ID0, &shuffled),
                || net.send_many(PartyID::ID1, &shuffled),
            );
            send0?;
            send1?;
            shuffled
        }
    })
}

#[inline]
fn pack_row(dummy_flag: BitShare, x: XShare) -> BlockShare {
    BlockShare::new_ring(
        RingElement(Block::from(dummy_flag.a.0.convert()) | (Block::from(x.a.0) << 32)),
        RingElement(Block::from(dummy_flag.b.0.convert()) | (Block::from(x.b.0) << 32)),
    )
}

#[inline]
fn unpack_row(row: BlockShare) -> (BitShare, XShare) {
    (
        BitShare::new_ring(
            RingElement(Bit::new(row.a.0 & 1 != 0)),
            RingElement(Bit::new(row.b.0 & 1 != 0)),
        ),
        XShare::new_ring(
            RingElement(((row.a.0 >> 32) & Block::from(X::MAX)) as X),
            RingElement(((row.b.0 >> 32) & Block::from(X::MAX)) as X),
        ),
    )
}
