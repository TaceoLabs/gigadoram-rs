use circuits::oblivious_sort::ObliviousSort;
use mpc_core::protocols::{
    rep3::{Rep3State, conversion::A2BType},
    rep3_ring::ring::bit::Bit,
};
use primitives::{
    YField, open_many, open_many_y, promote_public_values, promote_public_y_values, random_bigints,
    run_parties,
};
use rand::thread_rng;

#[test]
fn test_sorts_dummies_to_end() {
    assert_sort(
        vec![true, false, true, false, false, true, false, true],
        vec![10u32, 11, 12, 13, 14, 15, 16, 17],
        vec![11, 13, 14, 16],
        vec![10, 12, 15, 17],
    );
}

#[test]
fn test_sorts_non_power_of_two_length() {
    assert_sort(
        vec![true, false, true, false, false, true],
        vec![20u32, 21, 22, 23, 24, 25],
        vec![21, 23, 24],
        vec![20, 22, 25],
    );
}

fn assert_sort(
    flags: Vec<bool>,
    xs: Vec<u32>,
    expected_real_xs: Vec<u32>,
    expected_dummy_xs: Vec<u32>,
) {
    let flags = flags.into_iter().map(Bit::new).collect::<Vec<_>>();
    let mut rng = thread_rng();
    let ys = random_bigints::<YField, _>(&mut rng, xs.len());

    let outputs = run_parties(|net| {
        let mut state = Rep3State::new(&net, A2BType::Direct).unwrap();
        let mut flag_shares = promote_public_values(state.id, &flags);
        let mut x_shares = promote_public_values(state.id, &xs);
        let mut y_shares = promote_public_y_values(state.id, &ys);
        let mut alibi_shares = vec![primitives::AlibiShare::zero_share(); xs.len()];

        ObliviousSort::sort::<primitives::FieldValue<primitives::YField>, _>(
            &mut flag_shares,
            &mut x_shares,
            &mut y_shares,
            &mut alibi_shares,
            &net,
            &mut state,
        )
        .unwrap();

        let num_real = expected_real_xs.len();
        (
            open_many(&flag_shares, &net)
                .into_iter()
                .map(|bit| bit.convert())
                .collect::<Vec<_>>(),
            open_many(&x_shares, &net),
            open_many_y(&y_shares, &net),
            num_real,
        )
    })
    .unwrap();

    for (opened_flags, opened_xs, opened_ys, num_real) in outputs {
        assert!(opened_flags[..num_real].iter().all(|flag| !flag));
        assert!(opened_flags[num_real..].iter().all(|flag| *flag));

        let mut real_xs = opened_xs[..num_real].to_vec();
        real_xs.sort_unstable();
        assert_eq!(real_xs, expected_real_xs);

        let mut dummy_xs = opened_xs[num_real..].to_vec();
        dummy_xs.sort_unstable();
        assert_eq!(dummy_xs, expected_dummy_xs);

        for (x, y) in opened_xs.iter().zip(opened_ys) {
            let expected = ys[xs.iter().position(|old_x| old_x == x).unwrap()];
            assert_eq!(expected, y);
        }
    }
}
