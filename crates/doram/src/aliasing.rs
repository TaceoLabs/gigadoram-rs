//! Oblivious de-duplication of a batch chunk whose addresses may repeat.
//!
//! A chunk runs against one snapshot, so a repeated address would be consumed
//! twice and would miss the earlier operation's write. The chunk's `k(k-1)/2`
//! pairwise equality bits fix that in `O(k^2)` AND gates and `O(log k)` rounds,
//! for any aliasing pattern rather than just isolated pairs.

use eyre::Result;
use mpc_core::protocols::{
    rep3::{Rep3State, id::PartyID},
    rep3_ring::{
        binary,
        ring::{bit::Bit, ring_impl::RingElement},
    },
};
use mpc_net::Network;
use primitives::{BitShare, DoramValue, XShare, is_zero_many, promote_public, select_values};

pub(crate) struct AliasPlan {
    /// An earlier operation of the chunk targets the same address.
    pub duplicate: Vec<BitShare>,
    /// A later operation of the chunk targets the same address.
    pub superseded: Vec<BitShare>,
    /// One-hot row over `j <= i` picking what determines `i`'s result: the
    /// latest write before `i` to its address, else that address's first use.
    sources: Vec<Vec<BitShare>>,
}

/// Builds the plan for `addrs`, where `is_write[i]` is public.
pub(crate) fn plan<N: Network>(
    addrs: &[XShare],
    is_write: &[bool],
    net: &N,
    state: &mut Rep3State,
) -> Result<AliasPlan> {
    let count = addrs.len();
    let id = state.id;

    let mut diffs = Vec::new();
    for i in 0..count {
        for j in 0..i {
            diffs.push(addrs[j] ^ addrs[i]);
        }
    }
    let eq = is_zero_many(&diffs, net, state)?;
    let eq = |j: usize, i: usize| eq[i * (i - 1) / 2 + j];
    let eq_write = |j: usize, i: usize| {
        if is_write[j] {
            eq(j, i)
        } else {
            BitShare::zero_share()
        }
    };

    // Suffix ANDs of "does not match i": all operations, writes only, and those
    // after i. All three scan in the same rounds.
    let mut rows = Vec::with_capacity(3 * count);
    rows.extend((0..count).map(|i| (0..i).map(|j| not(eq(j, i), id)).collect()));
    rows.extend((0..count).map(|i| (0..i).map(|j| not(eq_write(j, i), id)).collect()));
    rows.extend((0..count).map(|i| ((i + 1)..count).map(|m| not(eq(i, m), id)).collect()));
    let scans = suffix_ands(rows, id, net, state)?;
    let (all, rest) = scans.split_at(count);
    let (writes, after) = rest.split_at(count);

    let first = |i: usize| all[i][0];
    let no_prior_write = |i: usize| writes[i][0];

    // Row i: "j is the latest write before i", then "j is the first use".
    let round = and_rows(
        (0..count)
            .map(|i| {
                let latest = (0..i).map(|j| (eq_write(j, i), writes[i][j + 1]));
                let occurrence = (0..i).map(|j| (first(j), eq(j, i)));
                latest.chain(occurrence).collect()
            })
            .collect(),
        net,
        state,
    )?;

    // Gating the second half on "no earlier write" makes the halves disjoint,
    // so XOR merges them into one selector.
    let gated = and_rows(
        round
            .iter()
            .enumerate()
            .map(|(i, row)| {
                (0..=i)
                    .map(|j| (no_prior_write(i), if j < i { row[i + j] } else { first(i) }))
                    .collect()
            })
            .collect(),
        net,
        state,
    )?;

    let sources = round
        .iter()
        .zip(&gated)
        .enumerate()
        .map(|(i, (row, gated))| {
            (0..=i)
                .map(|j| if j < i { row[j] ^ gated[j] } else { gated[j] })
                .collect()
        })
        .collect();

    Ok(AliasPlan {
        duplicate: (0..count).map(|i| not(first(i), id)).collect(),
        superseded: (0..count).map(|i| not(after[i][0], id)).collect(),
        sources,
    })
}

impl AliasPlan {
    /// What each address held just before its operation.
    pub(crate) fn resolve_outputs<V: DoramValue, N: Network>(
        &self,
        fetched: &[V::Share],
        written: &[Option<V::Share>],
        net: &N,
        state: &mut Rep3State,
    ) -> Result<Vec<V::Share>> {
        let bits = self.sources.concat();
        let values = self
            .sources
            .iter()
            .enumerate()
            .flat_map(|(i, row)| {
                (0..row.len()).map(move |j| match written[j] {
                    Some(value) if j < i => value,
                    _ => fetched[j],
                })
            })
            .collect::<Vec<_>>();

        // Each row is one-hot, so XOR-folding it picks that row's value.
        let mut selected = select_values::<V, _>(&bits, &values, net, state)?.into_iter();
        Ok(self
            .sources
            .iter()
            .map(|row| {
                selected
                    .by_ref()
                    .take(row.len())
                    .fold(V::zero_share(), |acc, value| acc ^ value)
            })
            .collect())
    }
}

fn not(bit: BitShare, id: PartyID) -> BitShare {
    binary::xor_public(&bit, &RingElement(Bit::new(true)), id)
}

/// One batched AND round over ragged rows of operand pairs.
fn and_rows<N: Network>(
    rows: Vec<Vec<(BitShare, BitShare)>>,
    net: &N,
    state: &mut Rep3State,
) -> Result<Vec<Vec<BitShare>>> {
    let lhs = rows.iter().flatten().map(|pair| pair.0).collect::<Vec<_>>();
    let rhs = rows.iter().flatten().map(|pair| pair.1).collect::<Vec<_>>();
    if lhs.is_empty() {
        return Ok(rows.iter().map(|_| Vec::new()).collect());
    }
    let mut out = binary::and_vec(&lhs, &rhs, net, state)?.into_iter();
    Ok(rows
        .iter()
        .map(|row| out.by_ref().take(row.len()).collect())
        .collect())
}

/// `out[j] = AND(row[j..])` for every row, with `out[row.len()] = 1`. All rows
/// scan together in `ceil(log2(longest row))` rounds.
fn suffix_ands<N: Network>(
    mut rows: Vec<Vec<BitShare>>,
    id: PartyID,
    net: &N,
    state: &mut Rep3State,
) -> Result<Vec<Vec<BitShare>>> {
    let longest = rows.iter().map(Vec::len).max().unwrap_or(0);
    let mut stride = 1;
    while stride < longest {
        let pairs = rows
            .iter()
            .map(|row| {
                (0..row.len().saturating_sub(stride))
                    .map(|j| (row[j], row[j + stride]))
                    .collect()
            })
            .collect();
        for (row, combined) in rows.iter_mut().zip(and_rows(pairs, net, state)?) {
            row[..combined.len()].copy_from_slice(&combined);
        }
        stride <<= 1;
    }
    for row in &mut rows {
        row.push(promote_public(id, Bit::new(true)));
    }
    Ok(rows)
}
