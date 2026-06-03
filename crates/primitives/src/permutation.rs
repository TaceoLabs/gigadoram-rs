use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha12Rng;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalPermutation {
    pub n: usize,
    pub fy: Vec<usize>,
    pub pi: Option<Vec<usize>>,
}

impl LocalPermutation {
    pub fn new(n: usize, seed: Option<u64>) -> Self {
        let mut rng = match seed {
            Some(s) => ChaCha12Rng::seed_from_u64(s),
            None => ChaCha12Rng::from_entropy(),
        };
        Self::sample_from_rng(n, &mut rng)
    }

    pub fn sample_from_rng<R: Rng + ?Sized>(n: usize, rng: &mut R) -> Self {
        let mut fy = vec![0; n];
        for (i, choice) in fy.iter_mut().enumerate().skip(1) {
            *choice = rng.gen_range(0..=i);
        }

        Self { n, fy, pi: None }
    }

    pub fn from_fisher_yates(fy: Vec<usize>) -> Self {
        Self {
            n: fy.len(),
            fy,
            pi: None,
        }
    }

    pub fn shuffle<T>(&self, values: &mut [T]) {
        assert_eq!(values.len(), self.n);
        for i in (1..self.n).rev() {
            values.swap(i, self.fy[i]);
        }
    }

    pub fn inverse_shuffle<T>(&self, values: &mut [T]) {
        assert_eq!(values.len(), self.n);
        for i in 1..self.n {
            values.swap(i, self.fy[i]);
        }
    }

    pub fn evaluate_at(&mut self, input: usize) -> usize {
        assert!(input < self.n);
        if self.pi.is_none() {
            let mut pi: Vec<usize> = (0..self.n).collect();
            self.inverse_shuffle(&mut pi);
            self.pi = Some(pi);
        }

        self.pi.as_ref().expect("pi initialized")[input]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shuffle_matches_cpp_backward_fisher_yates_order() {
        let permutation = LocalPermutation::from_fisher_yates(vec![0, 0, 1, 1]);
        let mut values = vec![0, 1, 2, 3];

        permutation.shuffle(&mut values);

        assert_eq!(values, vec![2, 0, 3, 1]);
    }

    #[test]
    fn inverse_shuffle_undoes_shuffle() {
        let permutation = LocalPermutation::from_fisher_yates(vec![0, 0, 1, 1, 4]);
        let original = vec![10, 11, 12, 13, 14];
        let mut values = original.clone();

        permutation.shuffle(&mut values);
        permutation.inverse_shuffle(&mut values);

        assert_eq!(values, original);
    }

    #[test]
    fn evaluate_at_matches_inverse_shuffled_identity() {
        let mut permutation = LocalPermutation::from_fisher_yates(vec![0, 0, 1, 1]);

        let evaluated = (0..permutation.n)
            .map(|i| permutation.evaluate_at(i))
            .collect::<Vec<_>>();

        assert_eq!(evaluated, vec![1, 3, 0, 2]);
    }
}
