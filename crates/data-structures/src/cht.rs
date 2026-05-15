use circuits::cht_lookup::lookup_circuit;
use mpc_core::protocols::{
    rep3::{Rep3State, id::PartyID, network::Rep3NetworkExt},
    rep3_ring::ring::ring_impl::RingElement,
};
use mpc_net::Network;
use primitives::{Block, XShare, from_2_shares, low_u32, types::BitShare};
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
        if state.id == builder.next() {
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
