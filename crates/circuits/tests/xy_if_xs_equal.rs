use circuits::xy_if_xs_equal::xy_if_xs_equal_circuit;
use mpc_core::protocols::rep3::{Rep3State, conversion::A2BType};
use primitives::{
    Y, YField, open_many, open_many_y, promote_public_values, promote_public_y_values,
    random_bigints, run_parties,
};
use rand::thread_rng;

#[test]
fn test_xy_if_xs_equal_circuit() {
    let xs = vec![7u32, 8, 7];
    let query = vec![7u32; xs.len()];
    let mut rng = thread_rng();
    let ys = random_bigints::<YField, _>(&mut rng, 3);
    let expected_x = vec![7, 0, 7];
    let expected_y = vec![ys[0], Y::default(), ys[2]];
    let expected_found = vec![true, false, true];

    let outputs = run_parties(|net| {
        let mut state = Rep3State::new(&net, A2BType::Direct).unwrap();
        let x_shares = promote_public_values(state.id, &xs);
        let query_shares = promote_public_values(state.id, &query);
        let y_shares = promote_public_y_values(state.id, &ys);
        let alibi_shares = vec![primitives::AlibiShare::zero_share(); xs.len()];

        let (x_out, y_out, _alibi_out, found) =
            xy_if_xs_equal_circuit::<primitives::FieldValue<primitives::YField>>(
                &x_shares,
                &query_shares,
                &y_shares,
                &alibi_shares,
                &net,
                &mut state,
            )
            .unwrap();

        (
            open_many(&x_out, &net),
            open_many_y(&y_out, &net),
            open_many(&found, &net)
                .into_iter()
                .map(|bit| bit.convert())
                .collect::<Vec<_>>(),
        )
    })
    .unwrap();

    for (x, y, found) in outputs {
        assert_eq!(x, expected_x);
        assert_eq!(y, expected_y);
        assert_eq!(found, expected_found);
    }
}
