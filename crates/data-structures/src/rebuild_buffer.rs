use crate::ohtable::Share;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RebuildBuffer {
    xs: Vec<Share>,
    ys: Vec<Share>,
}

impl RebuildBuffer {
    pub fn new() -> Self {
        todo!("construct an empty rebuild buffer")
    }

    pub fn with_capacity(_capacity: usize) -> Self {
        todo!("construct a rebuild buffer with capacity")
    }

    pub fn push(&mut self, _x: Share, _y: Share) {
        todo!("append one address/value share pair")
    }

    pub fn extend(&mut self, _xs: Vec<Share>, _ys: Vec<Share>) {
        todo!("append many address/value share pairs")
    }

    pub fn split(self) -> (Vec<Share>, Vec<Share>) {
        todo!("split the buffer into address and value lists")
    }

    pub fn len(&self) -> usize {
        todo!("return rebuild buffer length")
    }

    pub fn is_empty(&self) -> bool {
        todo!("return whether rebuild buffer is empty")
    }

    pub fn clear(&mut self) {
        todo!("clear rebuild buffer contents")
    }
}
