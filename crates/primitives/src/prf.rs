use crate::{CircuitBlock, XType};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrfKey {
    blocks: Vec<CircuitBlock>,
}

impl PrfKey {
    pub fn new(_blocks: Vec<CircuitBlock>) -> Self {
        todo!("construct a PRF key from circuit blocks")
    }

    pub fn random(_key_size_blocks: usize) -> Self {
        todo!("generate a shared LowMC/SISO-PRF key")
    }

    pub fn blocks(&self) -> &[CircuitBlock] {
        todo!("return the PRF key blocks")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrfInput {
    pub key: PrfKey,
    pub x: XType,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrfOutput {
    pub q: CircuitBlock,
}

pub trait SisoPrf {
    fn key_size_blocks(&self) -> usize;

    fn evaluate(&self, input: PrfInput) -> PrfOutput;

    fn evaluate_many(&self, _inputs: Vec<PrfInput>) -> Vec<PrfOutput> {
        todo!("batch-evaluate the SISO PRF circuit")
    }
}
