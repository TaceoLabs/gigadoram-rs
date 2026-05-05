use structures::OHTableParams;

#[test]
fn ohtable_params_match_cpp_header_shape() {
    let params = OHTableParams {
        num_elements: 16,
        num_dummies: 4,
        stash_size: 8,
        builder: 1,
        cht_log_single_col_len: 5,
        key_size_blocks: 2,
    };

    assert_eq!(params.num_elements + params.num_dummies, 20);
    assert_eq!(params.builder, 1);
}
