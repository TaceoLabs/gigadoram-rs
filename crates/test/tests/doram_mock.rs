use core::GigaDoramConfig;

#[test]
fn doram_config_matches_cpp_constructor_shape() {
    let config = GigaDoramConfig {
        log_address_space_size: 20,
        num_levels: 3,
        log_amp_factor: 4,
        use_proven_cht_bounds: false,
        empirical_stash_size: 8,
        proven_stash_size: 50,
    };

    assert_eq!(config.log_address_space_size, 20);
    assert_eq!(config.num_levels, 3);
}
