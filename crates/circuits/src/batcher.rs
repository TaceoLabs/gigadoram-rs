use eyre::Result;
use mpc_core::protocols::{
    rep3::{Rep3State, id::PartyID, network::Rep3NetworkExt},
    rep3_ring::{
        Rep3RingShare, arithmetic, conversion,
        ring::{bit::Bit, ring_impl::RingElement},
    },
};
use mpc_net::Network;
use primitives::{BitShare, Block, BlockShare, X, XShare, Y, YShare};

type PermRing = u32;

pub struct Batcher;

impl Batcher {
    pub fn sort<N: Network>(
        dummy_flags: &mut [BitShare],
        xs: &mut [XShare],
        ys: &mut [YShare],
        net: &N,
        state: &mut Rep3State,
    ) -> Result<()> {
        debug_assert_eq!(xs.len(), dummy_flags.len());
        debug_assert_eq!(ys.len(), dummy_flags.len());
        assert!(
            !dummy_flags.is_empty(),
            "batcher sort does not support empty arrays"
        );

        let bits = conversion::bit_inject_from_bits_many::<PermRing, _>(dummy_flags, net, state)?;
        let perm = gen_bit_perm(bits, net, state)?;
        let rows = dummy_flags
            .iter()
            .zip(xs.iter())
            .zip(ys.iter())
            .map(|((flag, x), y)| pack_row(*flag, *x, *y))
            .collect::<Vec<_>>();

        for (i, row) in apply_inv(&perm, &rows, net, state)?.into_iter().enumerate() {
            let (flag, x, y) = unpack_row(row);
            dummy_flags[i] = flag;
            xs[i] = x;
            ys[i] = y;
        }
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

fn apply_inv<N: Network>(
    rho: &[Rep3RingShare<PermRing>],
    rows: &[BlockShare],
    net: &N,
    state: &mut Rep3State,
) -> Result<Vec<BlockShare>> {
    let unshuffled = (0..rho.len() as PermRing).collect::<Vec<_>>();
    let (perm_a, perm_b) = state.rngs.rand.random_perm(unshuffled);
    let perm = perm_a
        .into_iter()
        .zip(perm_b)
        .map(|(a, b)| Rep3RingShare::new(a, b))
        .collect::<Vec<_>>();

    let opened = shuffle_reveal_perm(&perm, rho, net, state)?;
    let shuffled = shuffle_rows(&perm, rows, net, state)?;
    let mut result = vec![BlockShare::zero_share(); rho.len()];
    for (position, row) in opened.into_iter().zip(shuffled) {
        result[position.0 as usize - 1] = row;
    }
    Ok(result)
}

fn shuffle_rows<N: Network>(
    pi: &[Rep3RingShare<PermRing>],
    input: &[BlockShare],
    net: &N,
    state: &mut Rep3State,
) -> Result<Vec<BlockShare>> {
    let len = pi.len();
    Ok(match state.id {
        PartyID::ID0 => {
            let mut alpha_1 = Vec::with_capacity(len);
            let mut alpha_3 = Vec::with_capacity(len);
            let mut beta_1 = Vec::with_capacity(len);
            for row in input {
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
            net.send_next_many(&shuffled_3)?;

            (0..len)
                .map(|_| {
                    let (a, b) = state.rngs.rand.random_elements::<RingElement<Block>>();
                    BlockShare::new_ring(a, b)
                })
                .collect()
        }
        PartyID::ID1 => {
            let mut alpha_1 = Vec::with_capacity(len);
            let mut beta_2 = Vec::with_capacity(len);
            for row in input {
                alpha_1.push(state.rngs.rand.random_element_rng2::<RingElement<Block>>());
                beta_2.push(row.a);
            }

            let mut shuffled_1 = Vec::with_capacity(len);
            for (pi, alpha) in pi.iter().zip(alpha_1) {
                shuffled_1.push(beta_2[pi.b.0 as usize] ^ alpha);
            }
            let delta = net.reshare_many(&shuffled_1)?;
            for (dst, pi) in beta_2.iter_mut().zip(pi) {
                *dst = delta[pi.a.0 as usize];
            }

            let mut result = Vec::with_capacity(len);
            let mut rand = Vec::with_capacity(len);
            for beta in beta_2 {
                let b = state.rngs.rand.random_element_rng2::<RingElement<Block>>();
                rand.push(beta ^ b);
                result.push(BlockShare::new_ring(RingElement::default(), b));
            }
            let rcv: Vec<RingElement<Block>> =
                net.send_and_recv_many(PartyID::ID2, &rand, PartyID::ID2)?;
            for (res, (r1, r2)) in result.iter_mut().zip(rcv.into_iter().zip(rand)) {
                res.a = r1 ^ r2;
            }
            result
        }
        PartyID::ID2 => {
            let mut alpha_3 = Vec::with_capacity(len);
            for _ in 0..len {
                alpha_3.push(state.rngs.rand.random_element_rng1::<RingElement<Block>>());
            }
            let gamma: Vec<RingElement<Block>> = net.recv_prev_many()?;

            let mut shuffled_1 = Vec::with_capacity(len);
            for (pi, alpha) in pi.iter().zip(alpha_3.iter()) {
                shuffled_1.push(gamma[pi.a.0 as usize] ^ alpha);
            }
            for (dst, pi) in alpha_3.iter_mut().zip(pi) {
                *dst = shuffled_1[pi.b.0 as usize];
            }

            let mut result = Vec::with_capacity(len);
            let mut rand = Vec::with_capacity(len);
            for beta in alpha_3 {
                let a = state.rngs.rand.random_element_rng1::<RingElement<Block>>();
                rand.push(beta ^ a);
                result.push(BlockShare::new_ring(a, RingElement::default()));
            }
            let rcv: Vec<RingElement<Block>> =
                net.send_and_recv_many(PartyID::ID1, &rand, PartyID::ID1)?;
            for (res, (r1, r2)) in result.iter_mut().zip(rcv.into_iter().zip(rand)) {
                res.b = r1 ^ r2;
            }
            result
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

fn pack_row(dummy_flag: BitShare, x: XShare, y: YShare) -> BlockShare {
    BlockShare::new_ring(
        RingElement(
            Block::from(dummy_flag.a.0.convert())
                | (Block::from(x.a.0) << 32)
                | (Block::from(y.a.0) << 64),
        ),
        RingElement(
            Block::from(dummy_flag.b.0.convert())
                | (Block::from(x.b.0) << 32)
                | (Block::from(y.b.0) << 64),
        ),
    )
}

fn unpack_row(row: BlockShare) -> (BitShare, XShare, YShare) {
    (
        BitShare::new_ring(
            RingElement(Bit::new(row.a.0 & 1 != 0)),
            RingElement(Bit::new(row.b.0 & 1 != 0)),
        ),
        XShare::new_ring(
            RingElement(((row.a.0 >> 32) & Block::from(X::MAX)) as X),
            RingElement(((row.b.0 >> 32) & Block::from(X::MAX)) as X),
        ),
        YShare::new_ring(
            RingElement((row.a.0 >> 64) as Y),
            RingElement((row.b.0 >> 64) as Y),
        ),
    )
}
