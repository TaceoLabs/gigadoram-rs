use circuits::batcher::Batcher;
use mpc_core::protocols::{
    rep3::{Rep3State, conversion::A2BType},
    rep3_ring::ring::bit::Bit,
};
use primitives::{open_many, promote_public_values, run_parties};

#[test]
fn test_batcher_sorts_dummies_to_end() {
    assert_batcher_sort(
        vec![true, false, true, false, false, true, false, true],
        vec![10u32, 11, 12, 13, 14, 15, 16, 17],
        vec![110u64, 111, 112, 113, 114, 115, 116, 117],
        vec![11, 13, 14, 16],
        vec![10, 12, 15, 17],
    );
}

#[test]
fn test_batcher_sorts_non_power_of_two_length() {
    assert_batcher_sort(
        vec![true, false, true, false, false, true],
        vec![20u32, 21, 22, 23, 24, 25],
        vec![120u64, 121, 122, 123, 124, 125],
        vec![21, 23, 24],
        vec![20, 22, 25],
    );
}

fn assert_batcher_sort(
    flags: Vec<bool>,
    xs: Vec<u32>,
    ys: Vec<u64>,
    expected_real_xs: Vec<u32>,
    expected_dummy_xs: Vec<u32>,
) {
    let flags = flags.into_iter().map(Bit::new).collect::<Vec<_>>();

    let outputs = run_parties(|net| {
        let mut state = Rep3State::new(&net, A2BType::Direct).unwrap();
        let mut flag_shares = promote_public_values(state.id, &flags);
        let mut x_shares = promote_public_values(state.id, &xs);
        let mut y_shares = promote_public_values(state.id, &ys);

        Batcher::sort(
            &mut flag_shares,
            &mut x_shares,
            &mut y_shares,
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
            open_many(&y_shares, &net),
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
            assert_eq!(u64::from(*x) + 100, y);
        }
    }
}
