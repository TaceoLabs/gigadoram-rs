use eyre::{Context, Result, ensure, eyre};
use mpc_core::protocols::{
    rep3::Rep3State,
    rep3_ring::{self, Rep3RingShare, ring::ring_impl::RingElement},
};
use mpc_net::Network;

#[derive(Clone, Debug)]
pub struct GigadoramLowMc {
    circuit: BooleanCircuit,
}

impl GigadoramLowMc {
    pub const BLOCK_BITS: usize = 128;
    pub const ROUNDS: usize = 9;
    pub const ROUND_KEYS: usize = Self::ROUNDS + 1;
    pub const EXPANDED_KEY_BITS: usize = Self::ROUND_KEYS * Self::BLOCK_BITS;

    pub fn from_bristol(circuit: &str) -> Result<Self> {
        let circuit = BooleanCircuit::parse(circuit)?;
        ensure!(
            circuit.input_sizes == [Self::EXPANDED_KEY_BITS, Self::BLOCK_BITS],
            "expected GigaDORAM LowMC inputs to be expanded key then block"
        );
        ensure!(
            circuit.output_sizes == [Self::BLOCK_BITS],
            "expected GigaDORAM LowMC to have one 128-bit output"
        );
        Ok(Self { circuit })
    }

    pub fn encrypt(
        &self,
        expanded_key: &[bool],
        input: &[bool],
    ) -> Result<[bool; Self::BLOCK_BITS]> {
        ensure!(
            expanded_key.len() == Self::EXPANDED_KEY_BITS,
            "expanded key must contain {} bits",
            Self::EXPANDED_KEY_BITS
        );
        ensure!(
            input.len() == Self::BLOCK_BITS,
            "input must contain {} bits",
            Self::BLOCK_BITS
        );

        let output = self.circuit.evaluate(&[expanded_key, input])?;
        output
            .try_into()
            .map_err(|_| eyre!("GigaDORAM LowMC output had unexpected length"))
    }

    pub fn encrypt_u128_chunks(
        &self,
        expanded_key: &[u128; Self::ROUND_KEYS],
        input: u128,
    ) -> Result<u128> {
        let expanded_key_bits = expanded_key
            .iter()
            .flat_map(|chunk| u128_to_bits(*chunk))
            .collect::<Vec<_>>();
        let input_bits = u128_to_bits(input);

        let output = self.encrypt(&expanded_key_bits, &input_bits)?;
        Ok(bits_to_u128(&output))
    }

    pub fn mpc_encrypt_bin<N: Network>(
        &self,
        expanded_key: &[Rep3RingShare<u128>; Self::ROUND_KEYS],
        input: Rep3RingShare<u128>,
        net: &N,
        state: &mut Rep3State,
    ) -> Result<Rep3RingShare<u128>> {
        let mut expanded_key_bits = Vec::with_capacity(Self::EXPANDED_KEY_BITS);
        for round_key in expanded_key {
            expanded_key_bits.extend(unpack_shared_u128(*round_key));
        }
        let input_bits = unpack_shared_u128(input);

        let output = self
            .circuit
            .evaluate_mpc(&[&expanded_key_bits, &input_bits], net, state)?;

        Ok(pack_shared_u128(&output))
    }
}

#[derive(Clone, Debug)]
struct BooleanCircuit {
    num_wires: usize,
    input_sizes: Vec<usize>,
    output_sizes: Vec<usize>,
    gates: Vec<Gate>,
}

impl BooleanCircuit {
    fn parse(circuit: &str) -> Result<Self> {
        let mut lines = circuit.lines().filter(|line| !line.trim().is_empty());

        let (num_gates, num_wires) = parse_pair(
            lines
                .next()
                .ok_or_else(|| eyre!("missing circuit size header"))?,
        )
        .wrap_err("invalid circuit size header")?;

        let input_sizes = parse_io_sizes(
            lines
                .next()
                .ok_or_else(|| eyre!("missing circuit input header"))?,
        )
        .wrap_err("invalid circuit input header")?;
        let output_sizes = parse_io_sizes(
            lines
                .next()
                .ok_or_else(|| eyre!("missing circuit output header"))?,
        )
        .wrap_err("invalid circuit output header")?;

        let gates = lines
            .map(parse_gate)
            .collect::<Result<Vec<_>>>()
            .wrap_err("invalid circuit gate")?;

        ensure!(
            gates.len() == num_gates,
            "gate count mismatch: header says {num_gates}, parsed {}",
            gates.len()
        );

        Ok(Self {
            num_wires,
            input_sizes,
            output_sizes,
            gates,
        })
    }

    fn evaluate(&self, inputs: &[&[bool]]) -> Result<Vec<bool>> {
        ensure!(
            inputs.len() == self.input_sizes.len(),
            "expected {} input blocks, got {}",
            self.input_sizes.len(),
            inputs.len()
        );

        let mut wires = vec![false; self.num_wires];
        let mut input_offset = 0;
        for (input, expected_size) in inputs.iter().zip(&self.input_sizes) {
            ensure!(
                input.len() == *expected_size,
                "input block has {} bits, expected {expected_size}",
                input.len()
            );
            wires[input_offset..input_offset + expected_size].copy_from_slice(input);
            input_offset += expected_size;
        }

        for gate in &self.gates {
            gate.evaluate(&mut wires)?;
        }

        let output_len = self.output_sizes.iter().sum::<usize>();
        ensure!(
            output_len <= self.num_wires,
            "circuit output is larger than wire array"
        );
        Ok(wires[self.num_wires - output_len..].to_vec())
    }

    fn evaluate_mpc<N: Network>(
        &self,
        inputs: &[&[Rep3RingShare<u128>]],
        net: &N,
        state: &mut Rep3State,
    ) -> Result<Vec<Rep3RingShare<u128>>> {
        ensure!(
            inputs.len() == self.input_sizes.len(),
            "expected {} input blocks, got {}",
            self.input_sizes.len(),
            inputs.len()
        );

        let mut wires = vec![Rep3RingShare::zero_share(); self.num_wires];
        let mut input_offset = 0;
        for (input, expected_size) in inputs.iter().zip(&self.input_sizes) {
            ensure!(
                input.len() == *expected_size,
                "input block has {} bits, expected {expected_size}",
                input.len()
            );
            wires[input_offset..input_offset + expected_size].copy_from_slice(input);
            input_offset += expected_size;
        }

        for gate in &self.gates {
            gate.evaluate_mpc(&mut wires, net, state)?;
        }

        let output_len = self.output_sizes.iter().sum::<usize>();
        ensure!(
            output_len <= self.num_wires,
            "circuit output is larger than wire array"
        );
        Ok(wires[self.num_wires - output_len..].to_vec())
    }
}

#[derive(Clone, Debug)]
enum Gate {
    Xor {
        lhs: usize,
        rhs: usize,
        output: usize,
    },
    And {
        lhs: usize,
        rhs: usize,
        output: usize,
    },
    Inv {
        input: usize,
        output: usize,
    },
    Mand {
        lhs: Vec<usize>,
        rhs: Vec<usize>,
        outputs: Vec<usize>,
    },
}

impl Gate {
    fn evaluate(&self, wires: &mut [bool]) -> Result<()> {
        match self {
            Self::Xor { lhs, rhs, output } => {
                let value = wire(wires, *lhs)? ^ wire(wires, *rhs)?;
                set_wire(wires, *output, value)?;
            }
            Self::And { lhs, rhs, output } => {
                let value = wire(wires, *lhs)? & wire(wires, *rhs)?;
                set_wire(wires, *output, value)?;
            }
            Self::Inv { input, output } => {
                let value = !wire(wires, *input)?;
                set_wire(wires, *output, value)?;
            }
            Self::Mand { lhs, rhs, outputs } => {
                let values = lhs
                    .iter()
                    .zip(rhs)
                    .map(|(lhs, rhs)| Ok(wire(wires, *lhs)? & wire(wires, *rhs)?))
                    .collect::<Result<Vec<_>>>()?;
                for (output, value) in outputs.iter().zip(values) {
                    set_wire(wires, *output, value)?;
                }
            }
        }
        Ok(())
    }

    fn evaluate_mpc<N: Network>(
        &self,
        wires: &mut [Rep3RingShare<u128>],
        net: &N,
        state: &mut Rep3State,
    ) -> Result<()> {
        match self {
            Self::Xor { lhs, rhs, output } => {
                let value =
                    rep3_ring::binary::xor(&shared_wire(wires, *lhs)?, &shared_wire(wires, *rhs)?);
                set_shared_wire(wires, *output, value)?;
            }
            Self::And { lhs, rhs, output } => {
                let value = rep3_ring::binary::and(
                    &shared_wire(wires, *lhs)?,
                    &shared_wire(wires, *rhs)?,
                    net,
                    state,
                )?;
                set_shared_wire(wires, *output, value)?;
            }
            Self::Inv { input, output } => {
                let value = rep3_ring::binary::xor_public(
                    &shared_wire(wires, *input)?,
                    &RingElement(1),
                    state.id,
                );
                set_shared_wire(wires, *output, value)?;
            }
            Self::Mand { lhs, rhs, outputs } => {
                let lhs = lhs
                    .iter()
                    .map(|wire| shared_wire(wires, *wire))
                    .collect::<Result<Vec<_>>>()?;
                let rhs = rhs
                    .iter()
                    .map(|wire| shared_wire(wires, *wire))
                    .collect::<Result<Vec<_>>>()?;
                let values = rep3_ring::binary::and_vec(&lhs, &rhs, net, state)?;

                for (output, value) in outputs.iter().zip(values) {
                    set_shared_wire(wires, *output, value)?;
                }
            }
        }
        Ok(())
    }
}

fn wire(wires: &[bool], index: usize) -> Result<bool> {
    wires
        .get(index)
        .copied()
        .ok_or_else(|| eyre!("wire index {index} out of bounds"))
}

fn set_wire(wires: &mut [bool], index: usize, value: bool) -> Result<()> {
    let wire = wires
        .get_mut(index)
        .ok_or_else(|| eyre!("wire index {index} out of bounds"))?;
    *wire = value;
    Ok(())
}

fn shared_wire(wires: &[Rep3RingShare<u128>], index: usize) -> Result<Rep3RingShare<u128>> {
    wires
        .get(index)
        .copied()
        .ok_or_else(|| eyre!("wire index {index} out of bounds"))
}

fn set_shared_wire(
    wires: &mut [Rep3RingShare<u128>],
    index: usize,
    value: Rep3RingShare<u128>,
) -> Result<()> {
    let wire = wires
        .get_mut(index)
        .ok_or_else(|| eyre!("wire index {index} out of bounds"))?;
    *wire = value;
    Ok(())
}

fn parse_pair(line: &str) -> Result<(usize, usize)> {
    let nums = parse_usizes(line)?;
    ensure!(nums.len() == 2, "expected exactly two values");
    Ok((nums[0], nums[1]))
}

fn parse_io_sizes(line: &str) -> Result<Vec<usize>> {
    let nums = parse_usizes(line)?;
    ensure!(!nums.is_empty(), "missing IO block count");
    ensure!(
        nums.len() == nums[0] + 1,
        "IO header says {} blocks but contains {} sizes",
        nums[0],
        nums.len().saturating_sub(1)
    );
    Ok(nums[1..].to_vec())
}

fn parse_gate(line: &str) -> Result<Gate> {
    let mut parts = line.split_whitespace().collect::<Vec<_>>();
    let kind = parts
        .pop()
        .ok_or_else(|| eyre!("gate is missing operation kind"))?;
    let nums = parts
        .into_iter()
        .map(|part| {
            part.parse::<usize>()
                .wrap_err_with(|| format!("invalid integer {part:?}"))
        })
        .collect::<Result<Vec<_>>>()?;

    match kind {
        "XOR" => {
            ensure!(nums.len() == 5, "XOR gate must have five numeric fields");
            ensure!(nums[0] == 2 && nums[1] == 1, "invalid XOR arity");
            Ok(Gate::Xor {
                lhs: nums[2],
                rhs: nums[3],
                output: nums[4],
            })
        }
        "AND" => {
            ensure!(nums.len() == 5, "AND gate must have five numeric fields");
            ensure!(nums[0] == 2 && nums[1] == 1, "invalid AND arity");
            Ok(Gate::And {
                lhs: nums[2],
                rhs: nums[3],
                output: nums[4],
            })
        }
        "INV" => {
            ensure!(nums.len() == 4, "INV gate must have four numeric fields");
            ensure!(nums[0] == 1 && nums[1] == 1, "invalid INV arity");
            Ok(Gate::Inv {
                input: nums[2],
                output: nums[3],
            })
        }
        "MAND" => {
            ensure!(nums.len() >= 2, "MAND gate is missing arity fields");
            let output_count = nums[1];
            ensure!(
                nums[0] == output_count * 2,
                "MAND input count must be twice output count"
            );
            ensure!(
                nums.len() == 2 + output_count * 3,
                "MAND gate has wrong number of wires"
            );
            let lhs = nums[2..2 + output_count].to_vec();
            let rhs = nums[2 + output_count..2 + output_count * 2].to_vec();
            let outputs = nums[2 + output_count * 2..].to_vec();
            Ok(Gate::Mand { lhs, rhs, outputs })
        }
        _ => Err(eyre!("unsupported gate kind {kind}")),
    }
}

fn parse_usizes(line: &str) -> Result<Vec<usize>> {
    line.split_whitespace()
        .map(|part| {
            part.parse::<usize>()
                .wrap_err_with(|| format!("invalid integer {part:?}"))
        })
        .collect()
}

fn u128_to_bits(value: u128) -> [bool; GigadoramLowMc::BLOCK_BITS] {
    let mut bits = [false; GigadoramLowMc::BLOCK_BITS];
    for (i, bit) in bits.iter_mut().enumerate() {
        *bit = (value >> i) & 1 == 1;
    }
    bits
}

fn bits_to_u128(bits: &[bool; GigadoramLowMc::BLOCK_BITS]) -> u128 {
    bits.iter()
        .enumerate()
        .fold(0, |value, (i, bit)| value | (u128::from(*bit) << i))
}

fn unpack_shared_u128(
    share: Rep3RingShare<u128>,
) -> [Rep3RingShare<u128>; GigadoramLowMc::BLOCK_BITS] {
    std::array::from_fn(|bit| {
        Rep3RingShare::new_ring(
            RingElement((share.a.0 >> bit) & 1),
            RingElement((share.b.0 >> bit) & 1),
        )
    })
}

fn pack_shared_u128(bits: &[Rep3RingShare<u128>]) -> Rep3RingShare<u128> {
    debug_assert_eq!(bits.len(), GigadoramLowMc::BLOCK_BITS);

    bits.iter()
        .enumerate()
        .fold(Rep3RingShare::zero_share(), |mut output, (bit, share)| {
            output.a |= RingElement(share.a.0 << bit);
            output.b |= RingElement(share.b.0 << bit);
            output
        })
}
