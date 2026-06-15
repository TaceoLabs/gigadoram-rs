use circuits::lowmc::{self, common::ROUND_KEYS};
use mpc_core::protocols::rep3::{Rep3State, conversion::A2BType};
use primitives::{Block, open_many, promote_public_values, run_parties};

#[test]
fn packed_lowmc_matches_bit_sliced_lowmc() {
    let inputs = vec![
        0,
        1,
        0xffff,
        0x1234_5678_9abc_def0,
        0xfedc_ba98_7654_3210_0123_4567_89ab_cdef,
    ];
    let keys = expanded_keys(inputs.len());

    let outputs = run_parties(|net| {
        let mut state = Rep3State::new(&net, A2BType::Direct).unwrap();
        let input_shares = promote_public_values(state.id, &inputs);
        let key_shares = keys
            .iter()
            .map(|key| promote_public_values(state.id, key))
            .collect::<Vec<_>>();
        let key_refs = key_shares.iter().map(Vec::as_slice).collect::<Vec<_>>();

        let expected =
            lowmc::bit_sliced::encrypt_many(&key_refs, &input_shares, &net, &mut state).unwrap();
        let actual =
            lowmc::packed_u64::encrypt_many(&key_refs, &input_shares, &net, &mut state).unwrap();

        (open_many(&expected, &net), open_many(&actual, &net))
    })
    .unwrap();

    for (expected, actual) in outputs {
        assert_eq!(actual, expected);
    }
}

#[test]
fn packed_lowmc_matches_bit_sliced_lowmc_with_same_key() {
    let inputs = vec![3, 5, 8, 13, 21, 34, 55, 89];
    let key = expanded_keys(1).remove(0);

    let outputs = run_parties(|net| {
        let mut state = Rep3State::new(&net, A2BType::Direct).unwrap();
        let input_shares = promote_public_values(state.id, &inputs);
        let key_share = promote_public_values(state.id, &key);

        let expected = lowmc::bit_sliced::encrypt_many_with_same_key(
            &key_share,
            &input_shares,
            &net,
            &mut state,
        )
        .unwrap();
        let actual = lowmc::packed_u64::encrypt_many_with_same_key(
            &key_share,
            &input_shares,
            &net,
            &mut state,
        )
        .unwrap();

        (open_many(&expected, &net), open_many(&actual, &net))
    })
    .unwrap();

    for (expected, actual) in outputs {
        assert_eq!(actual, expected);
    }
}

#[test]
fn packed_u8_lowmc_matches_bit_sliced_lowmc_with_repeated_input() {
    let input = 0x1234_5678_9abc_def0_fedc_ba98_7654_3210;
    let keys = expanded_keys(17);

    let outputs = run_parties(|net| {
        let mut state = Rep3State::new(&net, A2BType::Direct).unwrap();
        let input_share = promote_public_values(state.id, &[input]).remove(0);
        let key_shares = keys
            .iter()
            .map(|key| promote_public_values(state.id, key))
            .collect::<Vec<_>>();
        let key_refs = key_shares.iter().map(Vec::as_slice).collect::<Vec<_>>();

        (0..=keys.len())
            .map(|len| {
                let repeated_inputs = vec![input_share; len];
                let expected = lowmc::bit_sliced::encrypt_many(
                    &key_refs[..len],
                    &repeated_inputs,
                    &net,
                    &mut state,
                )
                .unwrap();
                let actual = lowmc::packed_u8_lanes::encrypt_many_with_repeated_input(
                    &key_refs[..len],
                    input_share,
                    &net,
                    &mut state,
                )
                .unwrap();

                (open_many(&expected, &net), open_many(&actual, &net))
            })
            .collect::<Vec<_>>()
    })
    .unwrap();

    for party_outputs in outputs {
        for (expected, actual) in party_outputs {
            assert_eq!(actual, expected);
        }
    }
}

fn expanded_keys(num_keys: usize) -> Vec<Vec<Block>> {
    (0..num_keys)
        .map(|key| {
            (0..ROUND_KEYS)
                .map(|round| {
                    let high = (key as Block + 1) << 96;
                    let mid = (round as Block + 1) << 64;
                    high | mid | ((key as Block) << 8) | round as Block
                })
                .collect()
        })
        .collect()
}
