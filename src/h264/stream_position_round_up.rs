//! H.264 stream-position block rounding.
//!
//! `h264_stream_position_round_up_to_block` — original: `FUN_08368784` @
//! 0x08368784 (112 bytes; three recovered direct `bl` call sites: two plain
//! and one `blne`). The raw body is exactly 0x08368784..0x083687f4; the next
//! independently linked function begins at 0x083687f4.
//!
//! It reads the signed 64-bit stream position at `state+0x98`. A zero position
//! remains zero; otherwise it calculates `((position - 1) / block_size + 1) *
//! block_size`, using signed division truncating toward zero, then overwrites
//! that position. The block size is the signed word at `state+0xc0`.
//!
//! Deliberate deviations: the retail sequence explicitly computes the 64-bit
//! product with `umull`/`mla`; Rust uses wrapping target-width arithmetic. The
//! observable 64-bit result is identical. Division by zero retains the existing
//! `__aeabi_ldivmod` seam's documented behavior.

use crate::runtime::aeabi_64div::__aeabi_ldivmod;

const STREAM_POSITION_LOW_WORD: usize = 0x98 / 4;
const STREAM_POSITION_HIGH_WORD: usize = 0x9c / 4;
const BLOCK_SIZE_WORD: usize = 0xc0 / 4;

/// Rounds `state`'s signed 64-bit stream position up to a block boundary.
///
/// `state` must point to the retail decoder state object. Its position is the
/// two target-width words at `+0x98` and `+0x9c`; block size is the signed word
/// at `+0xc0`. No pointer or divisor validation is added.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn h264_stream_position_round_up_to_block(state: *mut u32) {
    let position_low = state.add(STREAM_POSITION_LOW_WORD).read();
    let position_high = state.add(STREAM_POSITION_HIGH_WORD).read();
    let position = ((position_high as u64) << 32 | position_low as u64) as i64;

    let rounded_position = if position == 0 {
        0
    } else {
        let block_size = state.add(BLOCK_SIZE_WORD).read() as i32 as i64;
        let quotient = __aeabi_ldivmod(position.wrapping_sub(1), block_size);
        quotient.wrapping_add(1).wrapping_mul(block_size)
    };

    state.add(STREAM_POSITION_LOW_WORD).write(rounded_position as u64 as u32);
    state.add(STREAM_POSITION_HIGH_WORD).write((rounded_position as u64 >> 32) as u32);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(align(4))]
    struct DecoderState([u32; 0x40]);

    fn round_position(position: i64, block_size: i32) -> i64 {
        let mut state = DecoderState([0xa5a5_a5a5; 0x40]);
        state.0[STREAM_POSITION_LOW_WORD] = position as u64 as u32;
        state.0[STREAM_POSITION_HIGH_WORD] = (position as u64 >> 32) as u32;
        state.0[BLOCK_SIZE_WORD] = block_size as u32;

        unsafe { h264_stream_position_round_up_to_block(state.0.as_mut_ptr()) };

        ((state.0[STREAM_POSITION_HIGH_WORD] as u64) << 32
            | state.0[STREAM_POSITION_LOW_WORD] as u64) as i64
    }

    #[test]
    fn preserves_zero_and_rounds_positive_boundaries() {
        assert_eq!(round_position(0, 16), 0);
        assert_eq!(round_position(1, 16), 16);
        assert_eq!(round_position(16, 16), 16);
        assert_eq!(round_position(17, 16), 32);
    }

    #[test]
    fn retains_signed_truncation_for_negative_positions() {
        assert_eq!(round_position(-1, 16), 16);
        assert_eq!(round_position(-16, 16), 0);
        assert_eq!(round_position(-32, 16), -16);
    }

    #[test]
    fn preserves_full_width_position_and_signed_block_size() {
        assert_eq!(round_position((1i64 << 32) + 1, 1024), (1i64 << 32) + 1024);
        assert_eq!(round_position(17, -16), 0);
    }
}
