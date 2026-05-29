use circuits::lowmc;
use mpc_core::protocols::rep3::{Rep3State, conversion::A2BType};
use mpc_net::Network;
use primitives::{
    BitShare, Block, XShare, YShare, bit_to_binary_mask, cmux_many_custom, downcast_many,
    is_zero_many, open_many, promote_public, promote_public_values, run_parties,
};

#[test]
fn encrypt_few_repeated_input_matches_encrypt_many() {
    let keys = (1..=9)
        .map(|i| i as Block)
        .map(|i| {
            (0..lowmc::ROUND_KEYS)
                .map(|r| (i << 64) | r as Block)
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    let outputs = run_parties(|net| {
        let mut state = Rep3State::new(&net, A2BType::Direct).unwrap();
        let keys = keys
            .iter()
            .map(|key| promote_public_values(state.id, key))
            .collect::<Vec<_>>();
        let key_refs = keys.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let repeated_key_refs = keys
            .iter()
            .map(|key| lowmc::precompute_few_round_keys(key))
            .collect::<Vec<_>>();
        let repeated_key_refs = repeated_key_refs.iter().collect::<Vec<_>>();
        let repeated_input = promote_public(state.id, 7);
        let zero_inputs = promote_public_values(state.id, &[0u32, 1, 2, 0, 5, 0, 7, 8, 0]);
        let cmux_xs = promote_public_values(state.id, &[9u32, 8, 7, 6, 5, 4, 3, 2, 1]);
        let cmux_ys = promote_public_values(state.id, &[10u64, 11, 12, 13, 14, 15, 16, 17, 18]);

        for len in 1..=8 {
            let repeated_inputs = vec![repeated_input; len];
            let expected =
                lowmc::encrypt_many(&key_refs[..len], &repeated_inputs, &net, &mut state).unwrap();
            let expected_found = is_zero_many(&zero_inputs[..len], &net, &mut state).unwrap();
            let (expected_selected_x, expected_selected_y) = selected_cache(
                &expected_found,
                &cmux_xs[..len],
                &cmux_ys[..len],
                &net,
                &mut state,
            );
            let (actual, actual_found, actual_x, actual_y) =
                lowmc::encrypt_few_with_repeated_input_is_zero_and_cmux(
                    &repeated_key_refs[..len],
                    repeated_input,
                    &zero_inputs[..len],
                    &cmux_xs[..len],
                    &cmux_ys[..len],
                    &net,
                    &mut state,
                )
                .unwrap();
            assert_eq!(open_many(&actual, &net), open_many(&expected, &net));
            assert_eq!(
                open_many(&actual_found, &net),
                open_many(&expected_found, &net)
            );
            assert_eq!(
                open_many(&actual_x, &net),
                open_many(&expected_selected_x, &net)
            );
            assert_eq!(
                open_many(&actual_y, &net),
                open_many(&expected_selected_y, &net)
            );
        }

        let len = 9;
        let repeated_inputs = vec![repeated_input; len];
        let expected =
            lowmc::encrypt_many(&key_refs[..len], &repeated_inputs, &net, &mut state).unwrap();
        let expected_found = is_zero_many(&zero_inputs[..len], &net, &mut state).unwrap();
        let (expected_selected_x, expected_selected_y) = selected_cache(
            &expected_found,
            &cmux_xs[..len],
            &cmux_ys[..len],
            &net,
            &mut state,
        );
        let (actual, actual_found, actual_x, actual_y) =
            lowmc::encrypt_many_with_repeated_input_is_zero_and_cmux(
                &key_refs[..len],
                repeated_input,
                &zero_inputs[..len],
                &cmux_xs[..len],
                &cmux_ys[..len],
                &net,
                &mut state,
            )
            .unwrap();
        assert_eq!(open_many(&actual, &net), open_many(&expected, &net));
        assert_eq!(
            open_many(&actual_found, &net),
            open_many(&expected_found, &net)
        );
        assert_eq!(
            open_many(&actual_x, &net),
            open_many(&expected_selected_x, &net)
        );
        assert_eq!(
            open_many(&actual_y, &net),
            open_many(&expected_selected_y, &net)
        );
    });

    outputs.unwrap();
}

fn selected_cache<N: Network>(
    found: &[BitShare],
    xs: &[XShare],
    ys: &[YShare],
    net: &N,
    state: &mut Rep3State,
) -> (Vec<XShare>, Vec<YShare>) {
    let masks = found.iter().map(bit_to_binary_mask).collect::<Vec<_>>();
    let selected = cmux_many_custom(&masks, xs, ys, net, state).unwrap();
    (
        downcast_many(selected[..xs.len()].to_vec()),
        selected[xs.len()..].to_vec(),
    )
}
