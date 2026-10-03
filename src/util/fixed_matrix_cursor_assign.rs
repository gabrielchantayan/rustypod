//! Assignment to the current entry of a fixed-matrix cursor.

use super::fixed_matrix_copy::fixed_matrix_copy;
use super::fixed_matrix_cursor::{fixed_matrix_cursor_current, FixedMatrixCursor};
use super::fixed_matrix_identity::FixedMatrix4x4;

/// fixed_matrix_cursor_assign — original: `FUN_08242d90` @ **0x08242d90**.
/// True extent: 20 bytes, `0x08242d90..0x08242da4`; the next function starts
/// with `push {r0,r1,r4-r11,lr}` at `0x08242da4`. Full-image A32 decoding
/// finds two inbound plain BLs (`0x08242e5c`, `0x0824f2a8`), zero predicated
/// BLs. The body has zero outbound BLs and one unconditional tail B to
/// `fixed_matrix_copy` at `0x082572c0`.
///
/// Loads the target-width base and index, computes base + index * 0x44 with
/// wrapping 32-bit arithmetic, and copies sixteen aligned matrix words and
/// the marker byte at +0x40 to that entry. Padding at +0x41..+0x43 remains
/// unchanged. Neither the index nor the marker is normalized or validated.
///
/// Deliberate deviations: reuses the existing cursor-address and matrix-copy
/// ports instead of duplicating their logic. LLVM may emit calls and a return
/// rather than the original tail branch; memory effects and target arithmetic
/// are unchanged, including the copy helper's ascending-word overlap behavior.
///
/// # Safety
/// `cursor` must be aligned and readable; its computed entry must be aligned
/// and writable for 0x44 bytes. `source` must be aligned and readable for
/// 0x44 bytes. No NULL or bounds checks are performed.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn fixed_matrix_cursor_assign(
    cursor: *const FixedMatrixCursor,
    source: *const FixedMatrix4x4,
) {
    fixed_matrix_copy(fixed_matrix_cursor_current(cursor), source);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    #[test]
    fn assigns_selected_entry_preserving_padding_neighbors_and_cursor() {
        let Some(slab) = try_map_u32_slab(hints::FIXED_MATRIX_CURSOR_ASSIGN, 0x1000) else {
            note_missing_u32_fixture("util::fixed_matrix_cursor_assign");
            return;
        };
        unsafe {
            let base = slab.add(0x100);
            let source = slab.add(0x500).cast::<FixedMatrix4x4>();
            let cursor = slab.cast::<FixedMatrixCursor>();
            for index in [0u32, 3, 7] {
                core::ptr::write_bytes(base, 0xa5, 8 * 0x44);
                core::ptr::write_bytes(source.cast::<u8>(), 0x5a, 0x44);
                for word in 0..16 {
                    (*source).elements[word] = (0x8123_4567u32.wrapping_mul(word as u32 + 1)) as i32;
                }
                (*source).is_identity = [0, 1, 0xff][(index % 3) as usize];
                cursor.write(FixedMatrixCursor { matrix_base: base as usize as u32, index });
                let mut expected = [0xa5u8; 8 * 0x44];
                let source_bytes = core::slice::from_raw_parts(source.cast::<u8>(), 0x44);
                let offset = index as usize * 0x44;
                expected[offset..offset + 0x41].copy_from_slice(&source_bytes[..0x41]);
                fixed_matrix_cursor_assign(cursor, source);
                assert_eq!(core::slice::from_raw_parts(base, expected.len()), &expected);
                assert_eq!((*cursor).matrix_base, base as usize as u32);
                assert_eq!((*cursor).index, index);

                // Self-assignment must preserve every byte, including padding.
                fixed_matrix_cursor_assign(cursor, base.add(offset).cast());
                assert_eq!(core::slice::from_raw_parts(base, expected.len()), &expected);
            }

            // A huge index wraps to the same valid base instead of using host
            // usize arithmetic: 0x40000000 * 0x44 == 0 modulo 2^32.
            (*cursor).index = 0x4000_0000;
            fixed_matrix_cursor_assign(cursor, source);
            assert_eq!((*base.cast::<FixedMatrix4x4>()).elements, (*source).elements);
            assert_eq!(*base.add(0x40), (*source).is_identity);
            assert_eq!(core::slice::from_raw_parts(base.add(0x41), 3), &[0xa5; 3]);
        }
    }
}
