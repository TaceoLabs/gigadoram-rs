use circuits::cht_lookup::lookup_circuit;
use mpc_core::protocols::{
    rep3::{id::PartyID, network::Rep3NetworkExt, Rep3State},
    rep3_ring::ring::ring_impl::RingElement,
};
use mpc_net::Network;
use primitives::{from_2_shares, types::BitShare, Block, XShare};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirectedEdge {
    pub edge: usize,
    pub vertex: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StashState {
    None,
    Root,
    Unvisited,
    Stashed,
    Vertex(usize),
}

impl StashState {
    pub fn unwrap_regular(&self) -> usize {
        match self {
            StashState::Vertex(v) => *v,
            _ => panic!("called unwrap_regular on a non-regular StashState"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChtLookupResult {
    pub index: usize,
    pub found: BitShare,
}

pub fn build(
    stash_size: usize,
    log_single_col_len: u32,
    input_array: &[Block],
) -> (Vec<Block>, Vec<usize>) {
    let num_edges = input_array.len();
    let num_vertices = 2usize << log_single_col_len;
    let mut table = vec![0; 2usize << log_single_col_len];

    // Algorithm: DFS through the graph of locations, with edges formed by elements.
    let mut edges = vec![Vec::<DirectedEdge>::new(); num_vertices];
    for edge in 0..num_edges {
        let left_vertex = h0(input_array[edge], log_single_col_len);
        let right_vertex = h1(input_array[edge], log_single_col_len);
        edges[left_vertex].push(DirectedEdge {
            edge,
            vertex: right_vertex,
        });
        edges[right_vertex].push(DirectedEdge {
            edge,
            vertex: left_vertex,
        });
    }

    let mut state = vec![StashState::Unvisited; num_edges];
    let mut parent_vertex = vec![StashState::None; num_vertices];
    let mut parent_edge = vec![StashState::None; num_vertices];
    let mut dfs = Vec::new();

    for starting_vertex in 0..num_vertices {
        if parent_vertex[starting_vertex] != StashState::None {
            continue;
        }

        let mut extra_edge = StashState::None;
        // Build DFS tree. It is easier to think about vertices as locations.
        let mut component = Vec::new();
        parent_vertex[starting_vertex] = StashState::Root;
        parent_edge[starting_vertex] = StashState::Root;
        dfs.push(starting_vertex);

        while let Some(curr_vertex) = dfs.pop() {
            component.push(curr_vertex);
            for directed_edge in edges[curr_vertex].clone() {
                if state[directed_edge.edge] == StashState::Unvisited {
                    if parent_vertex[directed_edge.vertex] == StashState::None {
                        parent_vertex[directed_edge.vertex] = StashState::Vertex(curr_vertex);
                        parent_edge[directed_edge.vertex] = StashState::Vertex(directed_edge.edge);
                        state[directed_edge.edge] = StashState::Vertex(directed_edge.vertex);
                        dfs.push(directed_edge.vertex);
                    } else if extra_edge == StashState::None {
                        extra_edge = StashState::Vertex(directed_edge.edge);
                        state[directed_edge.edge] = StashState::Vertex(directed_edge.vertex);
                    } else {
                        state[directed_edge.edge] = StashState::Stashed;
                    }
                }
            }
        }

        for c in component {
            assert_ne!(parent_edge[c], StashState::None);
        }

        if extra_edge != StashState::None {
            let value = extra_edge.unwrap_regular();
            let mut vertex_to_reorient_away_from = state[value].unwrap_regular();
            while parent_vertex[vertex_to_reorient_away_from] != StashState::Root {
                state[parent_edge[vertex_to_reorient_away_from].unwrap_regular()] =
                    parent_vertex[vertex_to_reorient_away_from];
                vertex_to_reorient_away_from =
                    parent_vertex[vertex_to_reorient_away_from].unwrap_regular();
            }
        }
    }

    let mut num_marked_stashed = 0;
    for edge_state in state.iter().take(num_edges) {
        num_marked_stashed += usize::from(*edge_state == StashState::Stashed);
    }

    let stash_length = stash_size;
    assert!(num_marked_stashed <= stash_length);
    let mut stash_deficit = stash_length - num_marked_stashed;

    let mut stash_indices = vec![0; stash_size];
    let mut num_stashed = 0;
    for edge in 0..num_edges {
        if state[edge] == StashState::Stashed {
            // The input block's low 32 bits contain the builder-order index.
            stash_indices[num_stashed] = low_u32(input_array[edge]) as usize;
            num_stashed += 1;
        } else {
            assert_ne!(state[edge], StashState::Unvisited);
            if stash_deficit > 0 {
                stash_indices[num_stashed] = low_u32(input_array[edge]) as usize;
                num_stashed += 1;
                stash_deficit -= 1;
            } else {
                let value = state[edge].unwrap_regular();
                table[value] = input_array[edge];
            }
        }
    }
    assert_eq!(stash_deficit, 0);

    (table, stash_indices)
}

pub fn dummy(stash_size: usize, log_single_col_len: u32) -> (Vec<Block>, Vec<usize>) {
    (vec![0; 2usize << log_single_col_len], vec![0; stash_size])
}

pub fn lookup_from_2shares<N: Network>(
    log_single_col_len: u32,
    table: &[Block],
    key: Block,
    dummy_index: XShare,
    builder: PartyID,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<ChtLookupResult> {
    let mut lookup_values = vec![RingElement(0); 3];
    if state.id != builder {
        if state.id == builder.prev() {
            lookup_values[0] = RingElement(key);
        }
        lookup_values[1] = RingElement(table[h0(key, log_single_col_len)]);
        lookup_values[2] = RingElement(table[h1(key, log_single_col_len)]);
    }

    let [key_share, b0, b1] =
        from_2_shares(lookup_values, builder.prev(), builder.next(), net, state)?
            .try_into()
            .unwrap();
    let (index, found) = lookup_circuit(key_share, b0, b1, dummy_index, net, state)?;
    let index = reveal_index_to_receivers(&index, builder, net, state)?;

    Ok(ChtLookupResult { index, found })
}

pub fn h0(block: Block, log_single_col_len: u32) -> usize {
    let hash_mask = (1usize << log_single_col_len) - 1;
    ((block >> 64) as usize) & hash_mask
}

pub fn h1(block: Block, log_single_col_len: u32) -> usize {
    let hash_mask = (1usize << log_single_col_len) - 1;
    (((block >> 96) as usize) & hash_mask) | (1usize << log_single_col_len)
}

fn low_u32(block: Block) -> u32 {
    block as u32
}

fn reveal_index_to_receivers<N: Network>(
    index: &XShare,
    builder: PartyID,
    net: &N,
    state: &Rep3State,
) -> eyre::Result<usize> {
    if state.id == builder {
        net.send_to(builder.next(), index.b)?;
        return Ok(0);
    }

    if state.id == builder.next() {
        net.send_to(builder.prev(), index.b)?;
        let c = net.recv_from::<RingElement<u32>>(builder)?;
        return Ok((index.a ^ index.b ^ c).0 as usize);
    }

    let c = net.recv_from::<RingElement<u32>>(builder.next())?;
    Ok((index.a ^ index.b ^ c).0 as usize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mpc_core::protocols::{
        rep3::{conversion::A2BType, id::PartyID},
        rep3_ring::binary,
    };
    use mpc_net::local::LocalNetwork;
    use rand::{seq::SliceRandom, thread_rng, RngCore};
    use std::collections::HashSet;

    const LOG_SINGLE_COL_LEN: u32 = 4;
    const STASH_SIZE: usize = 2;
    const INPUT_COUNT: usize = 12;

    #[derive(Clone, Copy, Debug)]
    struct LookupCase {
        key: Block,
        dummy_index: u32,
        expected_index: usize,
        expected_found: bool,
    }

    #[test]
    fn test_no_duplicate_placements() {
        let (input, table, _) = setup();
        let input_indices = input
            .iter()
            .map(|entry| low_u32(*entry) as usize)
            .collect::<HashSet<_>>();
        let mut seen = HashSet::new();

        for entry in table.iter().copied().filter(|entry| *entry != 0) {
            let index = low_u32(entry) as usize;
            assert!(
                input_indices.contains(&index),
                "placed builder index {index} was not in the input"
            );
            assert!(
                seen.insert(index),
                "placed builder index {index} appeared twice"
            );
        }
    }

    #[test]
    fn test_fixed_stash_size() {
        let (input, table, stash_indices) = setup();
        let placed_count = table.iter().filter(|entry| **entry != 0).count();

        assert_eq!(stash_indices.len(), STASH_SIZE);
        assert_eq!(placed_count + STASH_SIZE, input.len());
    }

    #[test]
    fn test_stash_indices() {
        let (input, _, stash_indices) = setup();
        let input_indices = input
            .iter()
            .map(|entry| low_u32(*entry) as usize)
            .collect::<HashSet<_>>();
        let mut seen = HashSet::new();

        for index in stash_indices {
            assert!(
                input_indices.contains(&index),
                "stash index {index} was not in the input"
            );
            assert!(seen.insert(index), "stash index {index} appeared twice");
        }
    }

    #[test]
    fn test_lookup_round_trip() {
        let (input, table, stash_indices) = setup();
        let stash_indices = stash_indices.into_iter().collect::<HashSet<_>>();
        let dummy_index = 99u32;
        let mut cases = Vec::new();

        for entry in input {
            let builder_index = low_u32(entry) as usize;
            let key = entry & !0xffff_ffffu128;

            let (expected_index, found) = if stash_indices.contains(&builder_index) {
                assert_ne!(table[h0(key, LOG_SINGLE_COL_LEN)], entry);
                assert_ne!(table[h1(key, LOG_SINGLE_COL_LEN)], entry);
                (dummy_index as usize, false)
            } else {
                assert!(
                    table[h0(key, LOG_SINGLE_COL_LEN)] == entry
                        || table[h1(key, LOG_SINGLE_COL_LEN)] == entry,
                    "placed entry {builder_index} was not at either hash location"
                );
                (builder_index, true)
            };

            cases.push(LookupCase {
                key,
                dummy_index,
                expected_index,
                expected_found: found,
            });
        }

        run_lookup(table, cases);
    }

    #[test]
    fn test_lookup_missing_key() {
        let (_, table, _) = setup();
        let dummy_index = 123u32;
        let mask = (1usize << LOG_SINGLE_COL_LEN) - 1;
        let mut rng = thread_rng();
        let missing_key = loop {
            let left = rng.next_u32() as usize & mask;
            let right = rng.next_u32() as usize & mask;
            let entry = random_entry(&mut rng, left, right, 42);
            let key = entry & !0xffff_ffffu128;
            let tag = key >> 32;

            if table[h0(key, LOG_SINGLE_COL_LEN)] >> 32 != tag
                && table[h1(key, LOG_SINGLE_COL_LEN)] >> 32 != tag
            {
                break key;
            }
        };

        run_lookup(
            table,
            vec![LookupCase {
                key: missing_key,
                dummy_index,
                expected_index: dummy_index as usize,
                expected_found: false,
            }],
        );
    }

    fn setup() -> (Vec<Block>, Vec<Block>, Vec<usize>) {
        let input = random_entries();
        let (table, stash_indices) = build(STASH_SIZE, LOG_SINGLE_COL_LEN, &input);
        (input, table, stash_indices)
    }

    fn run_lookup(table: Vec<Block>, cases: Vec<LookupCase>) {
        let builder = PartyID::ID0;
        let networks = LocalNetwork::new_3_parties();

        std::thread::scope(|scope| {
            let handles = networks.map(|network| {
                let clear_table = table.clone();
                let cases = cases.clone();
                scope.spawn(move || {
                    let mut state = Rep3State::new(&network, A2BType::Direct).unwrap();
                    let party = state.id;
                    let table = if party == builder.prev() {
                        clear_table
                    } else {
                        vec![0; clear_table.len()]
                    };
                    cases
                        .iter()
                        .map(|case| {
                            let dummy_index = binary::promote_to_trivial_share(
                                state.id,
                                &RingElement(case.dummy_index),
                            );
                            let result = lookup_from_2shares(
                                LOG_SINGLE_COL_LEN,
                                &table,
                                case.key,
                                dummy_index,
                                builder,
                                &network,
                                &mut state,
                            )
                            .unwrap();
                            let found: bool =
                                binary::open(&result.found, &network).unwrap().0.convert();

                            (party, result.index, found)
                        })
                        .collect::<Vec<_>>()
                })
            });

            for party_results in handles.map(|handle| handle.join().unwrap()) {
                for (result, case) in party_results.iter().zip(cases.iter()) {
                    let (party, index, found) = *result;
                    assert_eq!(found, case.expected_found);
                    if party == builder {
                        assert_eq!(index, 0);
                    } else {
                        assert_eq!(index, case.expected_index);
                    }
                }
            }
        });
    }

    fn random_entries() -> Vec<Block> {
        let mut rng = thread_rng();
        let column_len = 1usize << LOG_SINGLE_COL_LEN;
        let mut left = (0..column_len).collect::<Vec<_>>();
        let mut right = (0..column_len).collect::<Vec<_>>();

        left.shuffle(&mut rng);
        right.shuffle(&mut rng);

        (0..INPUT_COUNT)
            .map(|i| random_entry(&mut rng, left[i], right[i], (i + 1) as u32))
            .collect()
    }

    fn random_entry(
        rng: &mut impl RngCore,
        left_vertex: usize,
        right_vertex: usize,
        builder_index: u32,
    ) -> Block {
        let mask = (1u64 << LOG_SINGLE_COL_LEN) - 1;
        let mut high = rng.next_u64();
        high = (high & !mask) | left_vertex as u64;
        high = (high & !(mask << 32)) | ((right_vertex as u64) << 32);

        ((high as Block) << 64) | ((rng.next_u32() as Block) << 32) | builder_index as Block
    }
}
