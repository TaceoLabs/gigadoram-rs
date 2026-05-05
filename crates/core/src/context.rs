use primitives::CircuitBlock;
use structures::{OhTable, SpeedCache};

use crate::config::GigaDoramConfig;

#[derive(Clone, Debug, PartialEq)]
pub struct DoramParams {
    pub log_sls: u32,
    pub stupid_fill_time: usize,
    pub stash_size: usize,
    pub amp_factor: usize,
    pub d: f64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct GigaDoramContext {
    pub config: GigaDoramConfig,
    pub params: DoramParams,
    pub prf_keys: Vec<CircuitBlock>,
    pub ohtables: Vec<Option<OhTable>>,
    pub stupid_level: SpeedCache,
    pub base_b_state_vec: Vec<usize>,
    pub had_initial_bottom_level: bool,
}

impl GigaDoramContext {
    pub fn new(
        _config: GigaDoramConfig,
        _ys_no_dummy_room: Option<Vec<structures::Share>>,
    ) -> Self {
        todo!("initialize DORAM state, levels, PRF keys, and optional bottom level")
    }

    pub fn decide_params(_config: &GigaDoramConfig) -> DoramParams {
        todo!("derive log_sls, stash size, fill time, amp factor, and CHT ratio")
    }

    pub fn get_num_alive_levels(&self) -> usize {
        todo!("count non-empty OHTable levels")
    }
}
