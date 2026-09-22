//! Alignment padding — `FUN_082142d8` @ 0x082142d8 (20 bytes; 3 inbound
//! plain `bl` call sites, 0 predicated `bl` call sites).
//!
//! Returns the bytes required to advance `value` to the next `alignment`
//! boundary: `(alignment - (value & (alignment - 1))) & (alignment - 1)`.
//! All arithmetic wraps modulo 2^32, exactly as the five-instruction ARM
//! leaf. This yields zero for an already aligned value; for power-of-two
//! alignments it is the usual alignment padding. Deliberate deviation:
//! `#[inline(never)]` preserves this exported BL target but adds a nonsemantic
//! LLVM frame; the arithmetic and ABI result are unchanged.

/// Returns the wrapping alignment padding required after `value`.
///
/// The caller supplies an alignment, normally a power of two. The literal ARM
/// arithmetic is retained, including its results for zero and non-power-of-two
/// alignments.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn alignment_padding(value: u32, alignment: u32) -> u32 {
    let alignment_mask = alignment.wrapping_sub(1);
    alignment.wrapping_sub(value & alignment_mask) & alignment_mask
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference(value: u32, alignment: u32) -> u32 {
        let mask = alignment.wrapping_sub(1);
        alignment.wrapping_sub(value & mask) & mask
    }

    #[test]
    fn returns_zero_when_value_is_aligned() {
        for &alignment in &[1u32, 2, 4, 8, 0x1000, 0x8000_0000] {
            for multiplier in 0..=4u32 {
                let value = alignment.wrapping_mul(multiplier);
                assert_eq!(alignment_padding(value, alignment), 0,
                    "value {value:#x}, alignment {alignment:#x}");
            }
        }
    }

    #[test]
    fn rounds_each_unaligned_offset_to_the_next_boundary() {
        for &alignment in &[2u32, 4, 8, 16, 0x1000] {
            for value in 0..=64u32 {
                assert_eq!(alignment_padding(value, alignment), reference(value, alignment),
                    "value {value}, alignment {alignment}");
            }
        }
        assert_eq!(alignment_padding(0xffff_ffff, 4), 1);
        assert_eq!(alignment_padding(0xffff_ffff, 0x8000_0000), 1);
    }

    #[test]
    fn preserves_degenerate_alignment_arithmetic() {
        for &(value, alignment) in &[
            (0, 0),
            (1, 0),
            (0xffff_ffff, 0),
            (0, 3),
            (1, 3),
            (0xffff_ffff, 3),
            (0x1234_5678, 0x8000_0001),
        ] {
            assert_eq!(alignment_padding(value, alignment), reference(value, alignment),
                "value {value:#x}, alignment {alignment:#x}");
        }
    }
}
