//! Video-frame data-layout helpers.

use crate::runtime::rt_div::__rt_sdiv;

/// `video_frame_data_offset` — original: `FUN_082a1f6c` @ `0x082a1f6c`
/// (84 bytes, binary-verified against `osos.dec`: 21 ARM instructions,
/// ending at `0x082a1fc0`, the next real function boundary).
///
/// The body has two plain unconditional outbound `bl` calls (`0x082a1fc0`
/// and `__rt_sdiv` @ `0x08031568`) and no predicated `bl`; three plain
/// direct inbound `bl` call sites are at `0x080c76e4`, `0x080c770c`, and
/// `0x080c7ee8`.
///
/// Computes the byte offset of frame data following its first plane. The
/// first contribution is `words[6] * words[8] / 8`, with the ARM signed
/// divide-by-eight rounding-toward-zero sequence. The second is
/// `words[7] * words[4]`, divided through ADS signed division by one when
/// `words[1]` is null and two otherwise. All multiplies and the final add
/// wrap at 32 bits as on ARM.
///
/// Deliberate deviation: the unported 16-byte helper at `0x082a1fc0` is
/// represented by its verified operation, testing word 1 for zero, rather
/// than introducing an unnamed call seam. Word indices preserve the target's
/// four-byte field layout on 64-bit host tests.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn video_frame_data_offset(words: *const u32) -> i32 {
    let first_plane_bits = (*words.add(6) as i32).wrapping_mul(*words.add(8) as i32);
    let first_plane_bytes = first_plane_bits
        .wrapping_add(((first_plane_bits >> 31) as u32 >> 29) as i32)
        >> 3;
    let divisor = if *words.add(1) == 0 { 1 } else { 2 };
    let second_plane_bytes = __rt_sdiv(
        (*words.add(7) as i32).wrapping_mul(*words.add(4) as i32),
        divisor,
    );

    first_plane_bytes.wrapping_add(second_plane_bytes)
}

#[cfg(test)]
mod tests {
    use super::video_frame_data_offset;

    #[test]
    fn offsets_the_second_plane_after_an_unflagged_first_plane() {
        let mut words = [0_u32; 9];
        words[4] = 40;
        words[6] = 3;
        words[7] = 5;
        words[8] = 10;

        assert_eq!(unsafe { video_frame_data_offset(words.as_ptr()) }, 203);
    }

    #[test]
    fn halves_the_second_plane_when_the_layout_has_a_first_plane() {
        let mut words = [0_u32; 9];
        words[1] = 1;
        words[4] = 40;
        words[6] = 3;
        words[7] = 5;
        words[8] = 10;

        assert_eq!(unsafe { video_frame_data_offset(words.as_ptr()) }, 103);
    }

    #[test]
    fn preserves_signed_truncation_and_wrapping_arithmetic() {
        let mut words = [0_u32; 9];
        words[4] = 3;
        words[6] = (-7_i32) as u32;
        words[7] = (-1_i32) as u32;
        words[8] = 1;

        assert_eq!(unsafe { video_frame_data_offset(words.as_ptr()) }, -3);
    }
}
