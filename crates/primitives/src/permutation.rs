#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalPermutation {
    n: usize,
    fisher_yates: Vec<usize>,
    inverse: Option<Vec<usize>>,
}

impl LocalPermutation {
    pub fn new(_n: usize) -> Self {
        todo!("sample Fisher-Yates choices from the local PRG")
    }

    pub fn from_fisher_yates(_fisher_yates: Vec<usize>) -> Self {
        todo!("construct LocalPermutation from Fisher-Yates choices")
    }

    pub fn len(&self) -> usize {
        todo!("return permutation domain size")
    }

    pub fn is_empty(&self) -> bool {
        todo!("return whether the permutation is empty")
    }

    pub fn shuffle<T>(&self, _values: &mut [T]) {
        todo!("apply the forward Fisher-Yates shuffle")
    }

    pub fn bit_shuffle(&self, _values: &mut [u8]) {
        todo!("apply the forward Fisher-Yates shuffle to packed bits")
    }

    pub fn inverse_shuffle<T>(&self, _values: &mut [T]) {
        todo!("apply the inverse Fisher-Yates shuffle")
    }

    pub fn evaluate_at(&mut self, _input: usize) -> usize {
        todo!("materialize and evaluate the index permutation")
    }
}
