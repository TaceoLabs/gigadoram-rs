mod common;

use common::{
    low_u32, random_indexed_block as random_block, random_indexed_blocks as random_blocks,
    run_parties,
};
use data_structures::cht::{build, h0, h1, lookup_from_2shares};
use mpc_core::protocols::{
    rep3::{Rep3State, conversion::A2BType, id::PartyID},
    rep3_ring::{binary, ring::ring_impl::RingElement},
};
use primitives::Block;
use rand::{RngCore, thread_rng};
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
        let entry = random_block(LOG_SINGLE_COL_LEN, left, right, 42);
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
    let input = random_blocks(LOG_SINGLE_COL_LEN, INPUT_COUNT);
    let (table, stash_indices) = build(STASH_SIZE, LOG_SINGLE_COL_LEN, &input);
    (input, table, stash_indices)
}

fn run_lookup(table: Vec<Block>, cases: Vec<LookupCase>) {
    let builder = PartyID::ID0;

    let party_results = run_parties(|net| {
        let mut state = Rep3State::new(&net, A2BType::Direct).unwrap();
        let party = state.id;
        let table = if party == builder.prev() {
            table.clone()
        } else {
            vec![0; table.len()]
        };

        cases
            .iter()
            .map(|case| {
                let dummy_index =
                    binary::promote_to_trivial_share(state.id, &RingElement(case.dummy_index));
                let result = lookup_from_2shares(
                    LOG_SINGLE_COL_LEN,
                    &table,
                    case.key,
                    dummy_index,
                    builder,
                    &net,
                    &mut state,
                )
                .unwrap();
                let found: bool = binary::open(&result.found, &net).unwrap().0.convert();

                (party, result.index, found)
            })
            .collect::<Vec<_>>()
    });

    for results in party_results {
        for (result, case) in results.iter().zip(cases.iter()) {
            let (party, index, found) = *result;
            assert_eq!(found, case.expected_found);
            if party == builder {
                assert_eq!(index, 0);
            } else {
                assert_eq!(index, case.expected_index);
            }
        }
    }
}
