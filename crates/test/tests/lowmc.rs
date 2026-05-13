use circuits::lowmc::{LowMc, ROUND_KEYS};
use mpc_core::protocols::{
    rep3::{Rep3State, conversion::A2BType, id::PartyID},
    rep3_ring::{self, binary, ring::ring_impl::RingElement},
};
use mpc_net::local::LocalNetwork;
use primitives::BlockShare;
use serde::Deserialize;

const FIXTURE: &str = include_str!("fixtures/lowmc/lowmc_cpp_fixture.json");

#[derive(Clone, Debug, Deserialize)]
struct LowMcFixture {
    expanded_key: Vec<String>,
    input: String,
    output: String,
}

#[test]
fn lowmc_rep3_matches_cpp_bristol_fixture() {
    let fixture: LowMcFixture = serde_json::from_str(FIXTURE).expect("LowMC fixture parses");
    let expanded_key = fixture
        .expanded_key
        .iter()
        .map(|value| parse_u128(value))
        .collect::<Vec<_>>();
    assert_eq!(expanded_key.len(), ROUND_KEYS);

    let input = parse_u128(&fixture.input);
    let expected_output = parse_u128(&fixture.output);
    let networks = LocalNetwork::new_3_parties();

    std::thread::scope(|scope| {
        let handles = networks
            .into_iter()
            .map(|network| {
                let expanded_key = expanded_key.clone();
                scope.spawn(move || {
                    let mut state = Rep3State::new(&network, A2BType::Direct).unwrap();
                    let lowmc = LowMc::gigadoram();
                    let key_shares = expanded_key
                        .into_iter()
                        .map(|value| public_block_share(state.id, value))
                        .collect::<Vec<_>>();
                    let input_share = public_block_share(state.id, input);

                    lowmc
                        .encrypt(&key_shares, input_share, &network, &mut state)
                        .unwrap()
                })
            })
            .collect::<Vec<_>>();

        let [output0, output1, output2] = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>()
            .try_into()
            .expect("three party outputs");

        let opened = rep3_ring::combine_ring_element_binary(output0, output1, output2).0;
        assert_eq!(opened, expected_output);
    });
}

fn public_block_share(id: PartyID, value: u128) -> BlockShare {
    binary::promote_to_trivial_share(id, &RingElement(value))
}

fn parse_u128(value: &str) -> u128 {
    u128::from_str_radix(
        value
            .strip_prefix("0x")
            .expect("fixture values use 0x prefix"),
        16,
    )
    .expect("fixture value fits u128")
}
