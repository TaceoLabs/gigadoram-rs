use mpc_core::protocols::{
    rep3::Rep3State,
    rep3_ring::{Rep3RingShare, binary, ring::ring_impl::RingElement},
};
use mpc_net::Network;
use primitives::BlockShare;

pub const BLOCK_SIZE: usize = 128;
pub const N_ROUNDS: usize = 9;
pub const N_SBOXES: usize = 42;
pub const M4R_WINDOW_SIZE: usize = 4;
pub const ROUND_KEYS: usize = N_ROUNDS + 1;

type BitShare = Rep3RingShare<u128>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LowMc {
    round_constants: Vec<[bool; BLOCK_SIZE]>,
    m4r_masks: Vec<Vec<[u8; BLOCK_SIZE]>>,
}

impl LowMc {
    pub fn new(seed: u64) -> Self {
        let mut rng = TinyRng::new(seed);

        let round_constants = (0..N_ROUNDS)
            .map(|_| std::array::from_fn(|_| rng.next_bit()))
            .collect();

        let m4r_masks = (0..N_ROUNDS)
            .map(|_| {
                (0..BLOCK_SIZE / M4R_WINDOW_SIZE)
                    .map(|_| std::array::from_fn(|_| rng.next_mask()))
                    .collect()
            })
            .collect();

        Self {
            round_constants,
            m4r_masks,
        }
    }

    pub fn encrypt<N: Network>(
        &self,
        expanded_key: &[BlockShare],
        input: BlockShare,
        net: &N,
        state: &mut Rep3State,
    ) -> eyre::Result<BlockShare> {
        assert_eq!(expanded_key.len(), ROUND_KEYS);

        let expanded_key = expanded_key
            .iter()
            .map(|round_key| unpack_block(*round_key))
            .collect::<Vec<_>>();
        let mut state_bits = unpack_block(input);

        self.add_round_key(&mut state_bits, &expanded_key[0]);

        for round in 0..N_ROUNDS {
            state_bits = self.sbox_layer(&state_bits, net, state)?;
            state_bits = self.four_russians_matrix_mult(round, &state_bits);
            self.xor_constants(round, &mut state_bits, state);
            self.add_round_key(&mut state_bits, &expanded_key[round + 1]);
        }

        Ok(pack_block(&state_bits))
    }

    fn add_round_key(&self, state: &mut [BitShare], round_key: &[BitShare]) {
        assert_eq!(state.len(), BLOCK_SIZE);
        assert_eq!(round_key.len(), BLOCK_SIZE);

        for (state_bit, key_bit) in state.iter_mut().zip(round_key) {
            *state_bit = binary::xor(state_bit, key_bit);
        }
    }

    fn sbox_layer<N: Network>(
        &self,
        input: &[BitShare],
        net: &N,
        state: &mut Rep3State,
    ) -> eyre::Result<Vec<BitShare>> {
        assert_eq!(input.len(), BLOCK_SIZE);

        let mut and_lhs = Vec::with_capacity(3 * N_SBOXES);
        let mut and_rhs = Vec::with_capacity(3 * N_SBOXES);

        for i in 0..N_SBOXES {
            let a = input[3 * i];
            let b = input[3 * i + 1];
            let c = input[3 * i + 2];

            // BC + A
            and_lhs.push(b);
            and_rhs.push(c);
            // CA + A + B
            and_lhs.push(c);
            and_rhs.push(a);
            // AB + A + B + C
            and_lhs.push(a);
            and_rhs.push(b);
        }

        let ands = binary::and_vec(&and_lhs, &and_rhs, net, state)?;
        let mut output = vec![BitShare::zero_share(); BLOCK_SIZE];

        for i in 0..N_SBOXES {
            let a = input[3 * i];
            let b = input[3 * i + 1];
            let c = input[3 * i + 2];

            let d = ands[3 * i];
            let e = ands[3 * i + 1];
            let f = ands[3 * i + 2];

            output[3 * i] = binary::xor(&d, &a);
            output[3 * i + 1] = xor3(&e, &a, &b);
            output[3 * i + 2] = xor4(&f, &a, &b, &c);
        }

        output[(3 * N_SBOXES)..BLOCK_SIZE].copy_from_slice(&input[(3 * N_SBOXES)..BLOCK_SIZE]);

        Ok(output)
    }

    fn four_russians_matrix_mult(&self, round: usize, input: &[BitShare]) -> Vec<BitShare> {
        assert_eq!(input.len(), BLOCK_SIZE);
        assert_eq!(BLOCK_SIZE % M4R_WINDOW_SIZE, 0);

        let mut output = vec![BitShare::zero_share(); BLOCK_SIZE];

        for window in 0..(BLOCK_SIZE / M4R_WINDOW_SIZE) {
            let lut =
                fill_out_lut(&input[(window * M4R_WINDOW_SIZE)..((window + 1) * M4R_WINDOW_SIZE)]);

            for output_wire in 0..BLOCK_SIZE {
                let mask = self.m4r_masks[round][window][output_wire] as usize;
                let selected = lut[mask];
                output[output_wire] = if window == 0 {
                    selected
                } else {
                    binary::xor(&output[output_wire], &selected)
                };
            }
        }

        output
    }

    fn xor_constants(&self, round: usize, state_bits: &mut [BitShare], state: &Rep3State) {
        assert_eq!(state_bits.len(), BLOCK_SIZE);

        for (bit, constant) in state_bits
            .iter_mut()
            .zip(self.round_constants[round].iter().copied())
        {
            if constant {
                *bit = binary::xor_public(bit, &RingElement(1u128), state.id);
            }
        }
    }
}

impl Default for LowMc {
    fn default() -> Self {
        Self::new(0x414c_4f57_4d43_0001)
    }
}

fn fill_out_lut(input: &[BitShare]) -> [BitShare; 1 << M4R_WINDOW_SIZE] {
    assert_eq!(input.len(), M4R_WINDOW_SIZE);

    let mut lut = [BitShare::zero_share(); 1 << M4R_WINDOW_SIZE];
    for i in 1..(1 << M4R_WINDOW_SIZE) {
        lut[i] = binary::xor(&lut[i - 1], &input[ctz(i)]);
    }
    lut
}

fn ctz(value: usize) -> usize {
    value.trailing_zeros() as usize
}

fn unpack_block(block: BlockShare) -> Vec<BitShare> {
    (0..BLOCK_SIZE)
        .map(|bit| {
            BitShare::new_ring(
                RingElement((block.a.0 >> bit) & 1),
                RingElement((block.b.0 >> bit) & 1),
            )
        })
        .collect()
}

fn pack_block(bits: &[BitShare]) -> BlockShare {
    assert_eq!(bits.len(), BLOCK_SIZE);

    bits.iter()
        .enumerate()
        .fold(BlockShare::zero_share(), |mut block, (bit_index, bit)| {
            block.a ^= RingElement(bit.a.0 << bit_index);
            block.b ^= RingElement(bit.b.0 << bit_index);
            block
        })
}

fn xor3(a: &BitShare, b: &BitShare, c: &BitShare) -> BitShare {
    binary::xor(&binary::xor(a, b), c)
}

fn xor4(a: &BitShare, b: &BitShare, c: &BitShare, d: &BitShare) -> BitShare {
    binary::xor(&xor3(a, b, c), d)
}

#[derive(Clone, Copy, Debug)]
struct TinyRng {
    state: u64,
}

impl TinyRng {
    fn new(seed: u64) -> Self {
        Self { state: seed.max(1) }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    fn next_bit(&mut self) -> bool {
        self.next_u64() & 1 == 1
    }

    fn next_mask(&mut self) -> u8 {
        (self.next_u64() & ((1 << M4R_WINDOW_SIZE) - 1)) as u8
    }
}
