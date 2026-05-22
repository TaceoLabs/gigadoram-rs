use circuits::xy_if_xs_equal::xy_if_xs_equal_circuit;
use mpc_core::protocols::rep3::{Rep3State, conversion::A2BType};
use primitives::{open_many, promote_public_values, run_parties};

#[test]
fn test_xy_if_xs_equal_circuit() {
    let xs = vec![7u32, 8, 7];
    let query = vec![7u32; xs.len()];
    let ys = vec![70u64, 80, 72];
    let expected_x = vec![7, 0, 7];
    let expected_y = vec![70, 0, 72];
    let expected_found = vec![true, false, true];

    let outputs = run_parties(|net| {
        let mut state = Rep3State::new(&net, A2BType::Direct).unwrap();
        let x_shares = promote_public_values(state.id, &xs);
        let query_shares = promote_public_values(state.id, &query);
        let y_shares = promote_public_values(state.id, &ys);

        let (x_out, y_out, found) =
            xy_if_xs_equal_circuit(&x_shares, &query_shares, &y_shares, &net, &mut state).unwrap();

        (
            open_many(&x_out, &net),
            open_many(&y_out, &net),
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
