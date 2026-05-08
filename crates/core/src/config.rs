#[derive(Clone, Debug, PartialEq)]
pub struct GigaDoramConfig {
    pub log_address_space_size: u32,
    pub num_levels: usize,
    pub log_amp_factor: u32,
    pub use_proven_cht_bounds: bool,
    pub empirical_stash_size: usize,
    pub proven_stash_size: usize,
}

impl GigaDoramConfig {
    pub fn new(_log_address_space_size: u32, _num_levels: usize, _log_amp_factor: u32) -> Self {
        todo!("construct DORAM config from C++ constructor arguments")
    }

    pub fn stash_size(&self) -> usize {
        todo!("choose empirical or proven stash size")
    }
}

impl Default for GigaDoramConfig {
    fn default() -> Self {
        todo!("construct default DORAM config")
    }
}
