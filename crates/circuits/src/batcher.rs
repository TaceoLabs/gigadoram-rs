use eyre::Result;
use mpc_core::protocols::{
    rep3::Rep3State,
    rep3_ring::{
        binary,
        ring::{bit::Bit, ring_impl::RingElement},
    },
};
use mpc_net::Network;
use primitives::{BitShare, Block, BlockShare, X, XShare, Y, YShare, bit_to_binary_mask};

pub struct Batcher;

impl Batcher {
    pub fn sort_dummies_to_end<N: Network>(
        dummy_flags: &mut [BitShare],
        xs: &mut [XShare],
        ys: &mut [YShare],
        net: &N,
        state: &mut Rep3State,
    ) -> Result<()> {
        let n = dummy_flags.len();
        debug_assert_eq!(xs.len(), n);
        debug_assert_eq!(ys.len(), n);

        Self::sort(dummy_flags, xs, ys, net, state)
    }

    pub fn sort<N: Network>(
        dummy_flags: &mut [BitShare],
        xs: &mut [XShare],
        ys: &mut [YShare],
        net: &N,
        state: &mut Rep3State,
    ) -> Result<()> {
        debug_assert_eq!(xs.len(), dummy_flags.len());
        debug_assert_eq!(ys.len(), dummy_flags.len());

        let chunk_size = Self::least_power_of_2_greater_than_or_equal_to(dummy_flags.len());
        Self::sort_internal(dummy_flags, xs, ys, chunk_size, net, state)
    }

    // Sort consecutive chunks of length `chunk_size`, as in the C++ batcher.
    fn sort_internal<N: Network>(
        dummy_flags: &mut [BitShare],
        xs: &mut [XShare],
        ys: &mut [YShare],
        chunk_size: usize,
        net: &N,
        state: &mut Rep3State,
    ) -> Result<()> {
        assert!(
            chunk_size.is_power_of_two(),
            "batcher chunk size must be a power of two"
        );
        if chunk_size == 1 {
            return Ok(());
        }

        Self::sort_internal(dummy_flags, xs, ys, chunk_size / 2, net, state)?;
        Self::butterfly(dummy_flags, xs, ys, chunk_size, net, state)
    }

    fn butterfly<N: Network>(
        dummy_flags: &mut [BitShare],
        xs: &mut [XShare],
        ys: &mut [YShare],
        chunk_size: usize,
        net: &N,
        state: &mut Rep3State,
    ) -> Result<()> {
        if chunk_size == 1 {
            return Ok(());
        }

        Self::butterfly_head(dummy_flags, xs, ys, chunk_size, net, state)?;
        Self::butterfly_body(dummy_flags, xs, ys, chunk_size / 2, net, state)
    }

    fn butterfly_head<N: Network>(
        dummy_flags: &mut [BitShare],
        xs: &mut [XShare],
        ys: &mut [YShare],
        chunk_size: usize,
        net: &N,
        state: &mut Rep3State,
    ) -> Result<()> {
        Self::swap_pairs(dummy_flags, xs, ys, chunk_size, true, net, state)
    }

    fn butterfly_body<N: Network>(
        dummy_flags: &mut [BitShare],
        xs: &mut [XShare],
        ys: &mut [YShare],
        chunk_size: usize,
        net: &N,
        state: &mut Rep3State,
    ) -> Result<()> {
        if chunk_size == 1 {
            return Ok(());
        }

        Self::swap_pairs(dummy_flags, xs, ys, chunk_size, false, net, state)?;
        Self::butterfly_body(dummy_flags, xs, ys, chunk_size / 2, net, state)
    }

    fn swap_pairs<N: Network>(
        dummy_flags: &mut [BitShare],
        xs: &mut [XShare],
        ys: &mut [YShare],
        chunk_size: usize,
        invert: bool,
        net: &N,
        state: &mut Rep3State,
    ) -> Result<()> {
        assert!(
            chunk_size.is_power_of_two(),
            "batcher chunk size must be a power of two"
        );
        assert!(chunk_size > 1);

        let mut pairs = Vec::new();
        let mut chunk_start = 0;
        while chunk_start + chunk_size / 2 < dummy_flags.len() {
            let second_half_index_upper_bound = usize::min(
                chunk_size / 2,
                dummy_flags.len() - chunk_start - chunk_size / 2,
            );

            for i in 0..second_half_index_upper_bound {
                let second_half_index = chunk_start + chunk_size / 2 + i;
                let first_half_index = if invert {
                    chunk_start + chunk_size / 2 - 1 - i
                } else {
                    chunk_start + i
                };
                pairs.push((first_half_index, second_half_index));
            }

            chunk_start += chunk_size;
        }

        Self::compare_swap_dummy_pairs(&pairs, dummy_flags, xs, ys, net, state)
    }

    fn least_power_of_2_greater_than_or_equal_to(len: usize) -> usize {
        assert!(len > 0, "batcher sort does not support empty arrays");
        len.next_power_of_two()
    }

    fn compare_swap_dummy_pairs<N: Network>(
        pairs: &[(usize, usize)],
        dummy_flags: &mut [BitShare],
        xs: &mut [XShare],
        ys: &mut [YShare],
        net: &N,
        state: &mut Rep3State,
    ) -> Result<()> {
        if pairs.is_empty() {
            return Ok(());
        }

        let row_masks = pairs
            .iter()
            .map(|&(left, _)| bit_to_binary_mask(&dummy_flags[left]))
            .collect::<Vec<BlockShare>>();
        let row_deltas = pairs
            .iter()
            .map(|&(left, right)| {
                pack_row(
                    binary::xor(&dummy_flags[left], &dummy_flags[right]),
                    xs[left] ^ xs[right],
                    ys[left] ^ ys[right],
                )
            })
            .collect::<Vec<_>>();

        let selected_row_deltas = binary::and_vec(&row_masks, &row_deltas, net, state)?;

        for (index, &(left, right)) in pairs.iter().enumerate() {
            let (flag_delta, x_delta, y_delta) = unpack_row(selected_row_deltas[index]);
            xs[left] ^= x_delta;
            xs[right] ^= x_delta;
            ys[left] ^= y_delta;
            ys[right] ^= y_delta;
            dummy_flags[left] ^= flag_delta;
            dummy_flags[right] ^= flag_delta;
        }

        Ok(())
    }
}

fn pack_row(dummy_flag: BitShare, x: XShare, y: YShare) -> BlockShare {
    BlockShare::new_ring(
        RingElement(pack_row_share(dummy_flag.a.0, x.a.0, y.a.0)),
        RingElement(pack_row_share(dummy_flag.b.0, x.b.0, y.b.0)),
    )
}

fn pack_row_share(dummy_flag: Bit, x: X, y: Y) -> Block {
    Block::from(dummy_flag.convert()) | (Block::from(x) << 32) | (Block::from(y) << 64)
}

fn unpack_row(row: BlockShare) -> (BitShare, XShare, YShare) {
    (
        BitShare::new_ring(
            RingElement(Bit::new(row.a.0 & 1 != 0)),
            RingElement(Bit::new(row.b.0 & 1 != 0)),
        ),
        XShare::new_ring(
            RingElement(((row.a.0 >> 32) & Block::from(X::MAX)) as X),
            RingElement(((row.b.0 >> 32) & Block::from(X::MAX)) as X),
        ),
        YShare::new_ring(
            RingElement((row.a.0 >> 64) as Y),
            RingElement((row.b.0 >> 64) as Y),
        ),
    )
}
