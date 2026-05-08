use primitives::CircuitBlock;
use structures::Share;

use crate::{GigaDoramConfig, GigaDoramContext};

#[derive(Clone, Debug, PartialEq)]
pub struct Doram {
    context: GigaDoramContext,
}

impl Doram {
    pub fn new(_config: GigaDoramConfig, _ys_no_dummy_room: Option<Vec<Share>>) -> Self {
        todo!("construct DORAM from optional initial bottom-level data")
    }

    pub fn context(&self) -> &GigaDoramContext {
        todo!("return immutable DORAM context")
    }

    pub fn get_num_levels(&self) -> usize {
        todo!("return configured number of OHTable levels")
    }

    pub fn read_and_write(
        &mut self,
        _qry_x: Vec<Share>,
        _qry_y: Vec<Share>,
        _is_write: Vec<Share>,
    ) -> Vec<Share> {
        todo!("run one DORAM read/write query")
    }

    pub fn rebuild(&mut self) {
        todo!("rebuild the hierarchy when the SpeedCache is full")
    }

    pub fn clear_doram(&mut self) {
        todo!("delete all OHTables and reset hierarchy state")
    }

    #[allow(dead_code)]
    fn new_ohtable_of_level(&mut self, _level_num: usize, _xs: Vec<Share>, _ys: Vec<Share>) {
        todo!("build a new OHTable at the requested level")
    }

    #[allow(dead_code)]
    fn delete_ohtable(&mut self, _level_num: usize) {
        todo!("drop an OHTable and update base-b state")
    }

    #[allow(dead_code)]
    fn generate_prf_key(&mut self, _level_num: usize) -> Vec<CircuitBlock> {
        todo!("generate and store a PRF key for a level")
    }

    #[allow(dead_code)]
    fn get_log_col_len(&self, _level_num: usize, _state_override: Option<usize>) -> u32 {
        todo!("compute the CHT column length exponent")
    }

    #[allow(dead_code)]
    fn get_num_dummies(&self, _level_num: usize) -> usize {
        todo!("compute number of dummy queries for a level")
    }

    #[allow(dead_code)]
    fn num_elements_at(&self, _level_num: usize, _state_override: Option<usize>) -> usize {
        todo!("compute number of real elements at a level")
    }

    #[allow(dead_code)]
    fn total_num_els_and_dummies(
        &self,
        _level_num: usize,
        _state_override: Option<usize>,
    ) -> usize {
        todo!("compute total OHTable size for a level")
    }

    #[allow(dead_code)]
    fn cleanse_bottom_level(
        &self,
        _extracted_list_xs: Vec<Share>,
        _extracted_list_ys: Vec<Share>,
        _log_n: u32,
    ) -> (Vec<Share>, Vec<Share>) {
        todo!("remove dummies and prepare the bottom level")
    }

    #[allow(dead_code)]
    fn relabel_dummies(_extracted_list_xs: &mut Vec<Share>, _log_n: u32) {
        todo!("replace dummy labels with fresh dummy address labels")
    }

    #[allow(dead_code)]
    fn insert_stash(&mut self, _level_num: usize) {
        todo!("move an OHTable stash into the SpeedCache with alibi bits")
    }

    #[allow(dead_code)]
    fn extract_alibi_bits(&self, _y_accum: &[Share], _alibi_mask: &mut Vec<Share>) {
        todo!("extract level alibi bits from the accumulated value")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DoramError {
    RebuildRequired,
    MissingShare,
    InvalidLevel,
    NotWriteable,
}
