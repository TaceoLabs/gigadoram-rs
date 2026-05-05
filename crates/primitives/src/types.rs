pub type Address = XType;
pub type BlockId = XType;
pub type CircuitBlock = [u8; 16];
pub type LevelIndex = usize;
pub type Value = Vec<u8>;
pub type XType = u32;
pub type YType = u64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    pub id: BlockId,
    pub value: Value,
}

impl Block {
    pub fn new(id: BlockId, value: impl Into<Value>) -> Self {
        Self {
            id,
            value: value.into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Shared<T> {
    pub left: T,
    pub right: T,
}

impl<T> Shared<T> {
    pub fn new(left: T, right: T) -> Self {
        Self { left, right }
    }
}
