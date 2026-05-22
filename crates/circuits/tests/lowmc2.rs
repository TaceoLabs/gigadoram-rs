use circuits::{lowmc, lowmc2};
use mpc_core::protocols::rep3::{Rep3State, conversion::A2BType};
use primitives::{Block, open_many, promote_public_values, run_parties};

#[test]
fn lowmc2_matches_lowmc() {
    let inputs = vec![1, 2, 3, 4, 5, 6, 7, 8];
    let keys = inputs
        .iter()
        .map(|i| {
            (0..lowmc::ROUND_KEYS)
                .map(|r| ((*i as Block) << 64) | r as Block)
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    let outputs = run_parties(|net| {
        let mut state = Rep3State::new(&net, A2BType::Direct).unwrap();
        let inputs = promote_public_values(state.id, &inputs);
        let keys = keys
            .iter()
            .map(|key| promote_public_values(state.id, key))
            .collect::<Vec<_>>();
        let key_refs = keys.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let a = lowmc::encrypt_many(&key_refs, &inputs, &net, &mut state).unwrap();
        let b = lowmc2::encrypt_many(&key_refs, &inputs, &net, &mut state).unwrap();
        (open_many(&a, &net), open_many(&b, &net))
    });

    for (a, b) in outputs {
        assert_eq!(a, b);
    }
}
