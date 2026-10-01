//! `draw_state_get_foreground_color` — retailOS `FUN_082a1d6c` at
//! `0x082a1d6c` (8 bytes; two unconditional plain BL callers, zero predicated).
//!
//! Raw words `e2811011 eaff40cd` decode as `add r1,r1,#0x11;
//! b 0x082720ac`. The next real function starts at `0x082a1d74`.
//! Callers at `0x08128b18` and `0x081b3454` copy the foreground RGBA
//! bytes into stack storage. Copies `record + 0x11` to `dst` in ascending
//! byte order, allowing unaligned pointers and propagating forward overlap.
//! Deliberate deviation: Rust calls the existing `color_copy_unaligned`
//! port rather than explicitly tail-branching; volatile accesses preserve
//! the original load/store ordering. No NULL, bounds, or alignment checks.

use crate::cxx::color_copy::color_copy_unaligned;
use crate::cxx::draw_state_color::DRAW_STATE_FOREGROUND_COLOR_OFFSET;

/// Copies the draw-state foreground colour's four bytes to `dst`.
///
/// Original: `0x082a1d6c`, 8 bytes, two plain BL callers, no predicated BL.
/// Both pointers must permit the four ordered byte loads/stores; `record`
/// must permit addressing its foreground field at offset `0x11`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn draw_state_get_foreground_color(dst: *mut u8, record: *const u8) {
    unsafe { color_copy_unaligned(dst, record.add(DRAW_STATE_FOREGROUND_COLOR_OFFSET)) };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::draw_state::DRAW_STATE_SIZE;

    #[test]
    fn copies_opaque_bytes_at_every_alignment_and_preserves_neighbors() {
        for source_alignment in 0..4 {
            for destination_alignment in 0..4 {
                let mut record = [0xa5_u8; DRAW_STATE_SIZE + 3];
                let field = source_alignment + DRAW_STATE_FOREGROUND_COLOR_OFFSET;
                record[field..field + 4].copy_from_slice(&[0x00, 0x80, 0xff, 0x34]);
                let original = record;
                let mut destination = [0x5a_u8; 9];
                let start = 1 + destination_alignment;
                unsafe {
                    draw_state_get_foreground_color(
                        destination.as_mut_ptr().add(start),
                        record.as_ptr().add(source_alignment),
                    );
                }
                let mut expected = [0x5a_u8; 9];
                expected[start..start + 4].copy_from_slice(&[0x00, 0x80, 0xff, 0x34]);
                assert_eq!(destination, expected);
                assert_eq!(record, original);
            }
        }
    }

    #[test]
    fn overlapping_destinations_follow_ordered_byte_copy() {
        for displacement in -3_isize..=3 {
            let mut bytes = [0xa5_u8; DRAW_STATE_SIZE];
            let source = DRAW_STATE_FOREGROUND_COLOR_OFFSET;
            bytes[source..source + 4].copy_from_slice(&[0x10, 0x20, 0x30, 0x40]);
            let destination = (source as isize + displacement) as usize;
            let mut expected = bytes;
            for index in 0..4 {
                expected[destination + index] = expected[source + index];
            }
            unsafe {
                draw_state_get_foreground_color(bytes.as_mut_ptr().add(destination), bytes.as_ptr());
            }
            assert_eq!(bytes, expected, "displacement {displacement}");
        }
    }
}
