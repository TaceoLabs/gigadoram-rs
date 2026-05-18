use circuits::{dummy_check::dummy_check_circuit, replace_if_dummy::replace_if_dummy_circuit};
use mpc_core::protocols::{
    rep3::{Rep3State, conversion::A2BType},
    rep3_ring::binary,
};
use primitives::{open_many, promote_public_values, run_parties};

#[test]
fn test_dummy_check_circuit() {
    let log_n = 3;
    let xs = vec![0u32, 1, 7, 8, 9, 15];
    let expected = vec![true, false, false, true, true, true];

    let outputs = run_parties(|net| {
        let mut state = Rep3State::new(&net, A2BType::Direct).unwrap();
        let x_shares = promote_public_values(state.id, &xs);
        let is_dummy = dummy_check_circuit(&x_shares, log_n, &net, &mut state).unwrap();

        is_dummy
            .iter()
            .map(|share| binary::open(share, &net).unwrap().0.convert())
            .collect::<Vec<_>>()
    });

    for opened in outputs {
        assert_eq!(opened, expected);
    }
}

#[test]
fn test_replace_if_dummy_circuit() {
    let log_n = 3;
    let xs = vec![0u32, 1, 7, 8, 9, 15];
    let replacements = vec![8u32, 9, 10, 11, 12, 13];
    let expected = vec![8u32, 1, 7, 11, 12, 13];

    let outputs = run_parties(|net| {
        let mut state = Rep3State::new(&net, A2BType::Direct).unwrap();
        let x_shares = promote_public_values(state.id, &xs);
        let replacement_shares = promote_public_values(state.id, &replacements);
        let replaced =
            replace_if_dummy_circuit(&x_shares, &replacement_shares, log_n, &net, &mut state)
                .unwrap();

        open_many(&replaced, &net)
    });

    for opened in outputs {
        assert_eq!(opened, expected);
    }
}
