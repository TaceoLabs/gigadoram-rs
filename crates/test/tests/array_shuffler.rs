use mpc_core::protocols::{
    rep3::{Rep3State, conversion::A2BType},
    rep3_ring::{self, Rep3RingShare, binary, ring::ring_impl::RingElement},
};
use mpc_net::local::LocalNetwork;
use primitives::{ArrayShuffler, LocalPermutation};
use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
struct ArrayShufflerFixture {
    n: usize,
    input: Vec<u64>,
    after_forward_shuffle: Vec<u64>,
    indices_output: Vec<usize>,
    prev_shared_perm: PermutationFixture,
    next_shared_perm: PermutationFixture,
}

#[derive(Clone, Debug, Deserialize)]
struct PermutationFixture {
    fisher_yates: Vec<usize>,
}

const PARTY1: &str = include_str!("fixtures/array_shuffler/array_shuffler_party1.json");
const PARTY2: &str = include_str!("fixtures/array_shuffler/array_shuffler_party2.json");
const PARTY3: &str = include_str!("fixtures/array_shuffler/array_shuffler_party3.json");

#[test]
fn array_shuffler_rep3_matches_party_fixtures() {
    let fixtures = load_fixtures();

    let expected_forward = fixtures[0].after_forward_shuffle.clone();
    let expected_indices = fixtures[0].indices_output.clone();
    let networks = LocalNetwork::new_3_parties();

    std::thread::scope(|scope| {
        let handles = networks
            .into_iter()
            .zip(fixtures)
            .map(|(network, fixture)| {
                scope.spawn(move || {
                    let mut state = Rep3State::new(&network, A2BType::Direct).unwrap();
                    let shuffler = fixture.shuffler();

                    let mut values = promote_public_values(&fixture.input, state.id);
                    shuffler
                        .forward_rep3(&mut values, &network, &mut state)
                        .unwrap();

                    let indices_input = (0..fixture.n as u64).collect::<Vec<_>>();
                    let mut indices = promote_public_values(&indices_input, state.id);
                    shuffler
                        .inverse_rep3(&mut indices, &network, &mut state)
                        .unwrap();

                    (values, indices)
                })
            })
            .collect::<Vec<_>>();

        let [
            (values0, indices0),
            (values1, indices1),
            (values2, indices2),
        ] = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>()
            .try_into()
            .expect("three party outputs");

        let opened_forward = combine_binary_u64(&values0, &values1, &values2);
        assert_eq!(opened_forward, expected_forward);

        let opened_indices = combine_binary_u64(&indices0, &indices1, &indices2)
            .into_iter()
            .map(|index| usize::try_from(index).expect("fixture indices fit usize"))
            .collect::<Vec<_>>();
        assert_eq!(opened_indices, expected_indices);
    });
}

impl ArrayShufflerFixture {
    fn shuffler(&self) -> ArrayShuffler {
        ArrayShuffler::from_permutations(
            LocalPermutation::from_fisher_yates(self.prev_shared_perm.fisher_yates.clone()),
            LocalPermutation::from_fisher_yates(self.next_shared_perm.fisher_yates.clone()),
        )
    }
}

fn load_fixtures() -> [ArrayShufflerFixture; 3] {
    [
        serde_json::from_str(PARTY1).expect("party 1 fixture parses"),
        serde_json::from_str(PARTY2).expect("party 2 fixture parses"),
        serde_json::from_str(PARTY3).expect("party 3 fixture parses"),
    ]
}

fn promote_public_values(
    values: &[u64],
    id: mpc_core::protocols::rep3::id::PartyID,
) -> Vec<Rep3RingShare<u64>> {
    values
        .iter()
        .map(|&value| binary::promote_to_trivial_share(id, &RingElement(value)))
        .collect()
}

fn combine_binary_u64(
    party0: &[Rep3RingShare<u64>],
    party1: &[Rep3RingShare<u64>],
    party2: &[Rep3RingShare<u64>],
) -> Vec<u64> {
    party0
        .iter()
        .zip(party1)
        .zip(party2)
        .map(|((share0, share1), share2)| {
            rep3_ring::combine_ring_element_binary(*share0, *share1, *share2).0
        })
        .collect()
}
