//! Input-sequence item geometry reset — `FUN_08128948` @ **0x08128948**.
//!
//! Raw extent: **128 bytes**, `0x08128948..0x081289c8`; the next function
//! begins with an independent PUSH. Whole-image aligned A32 decoding finds
//! two inbound calls: BLNE at 0x081294a4 and BL at 0x0812a0fc. The body has
//! one plain BL to `prid_checked_word_c0` and zero predicated BL instructions.
//!
//! Clear item words +0x14/+0x18, set +0x20 to owner[+0xc4]*32 plus twice
//! owner[+0xcc], +0x1c to owner[+0xc8] plus twice owner[+0xcc], and +0x24
//! to owner[+0xbc] minus owner[+0xcc]. With owner byte +0xda clear, set
//! +0x28 to the checked +0xc0 base plus owner[+0xc8] times the signed item
//! index byte at +0x10, minus owner[+0xcc], then clear +0x2c. A nonzero
//! gate preserves both final words. All arithmetic wraps at 32 bits.
//!
//! Deliberate deviations: omit scratch-register effects. Pointer fields
//! remain four-byte target words; reuse the existing checked-base port,
//! reached only with its gate clear, without adding a firmware seam.

use crate::app::prid_checked_word_c0::{prid_checked_word_c0, PridCheckedWordState};

/// Reset geometry without changing the item's index or lifecycle state.
///
/// # Safety
/// `item` must be writable for twelve aligned words and its first word must
/// point to an aligned readable owner through byte +0xda. The regions must
/// not overlap.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn input_sequence_item_reset_geometry(item: *mut u32) {
    item.add(5).write(0);
    item.add(6).write(0);
    let owner = item.read() as *const u32;
    item.add(8).write(owner.add(0xc4 / 4).read().wrapping_shl(5)
        .wrapping_add(owner.add(0xcc / 4).read().wrapping_shl(1)));
    item.add(7).write(owner.add(0xc8 / 4).read()
        .wrapping_add(owner.add(0xcc / 4).read().wrapping_shl(1)));
    item.add(9).write(owner.add(0xbc / 4).read()
        .wrapping_sub(owner.add(0xcc / 4).read()));
    if owner.cast::<u8>().add(0xda).read() != 0 {
        return;
    }
    let base = prid_checked_word_c0(owner.cast::<PridCheckedWordState>()) as u32;
    // The stock code reloads both the owner and signed index after the BL.
    let owner = item.read() as *const u32;
    let index = item.cast::<u8>().add(0x10).read() as i8 as i32 as u32;
    item.add(10).write(owner.add(0xc8 / 4).read().wrapping_mul(index)
        .wrapping_add(base).wrapping_sub(owner.add(0xcc / 4).read()));
    item.add(11).write(0);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    #[test]
    fn signed_indices_wrapping_geometry_and_gate_preservation() {
        let Some(slab) = try_map_u32_slab(hints::INPUT_SEQUENCE_ITEM_RESET_GEOMETRY, 0x1000) else {
            assert!(note_missing_u32_fixture(module_path!()));
            return;
        };
        unsafe {
            let item = slab.cast::<u32>();
            let owner = slab.add(0x100).cast::<u32>();
            for gate in [0u8, 1, 128, 255] {
                for index in [0u8, 1, 127, 128, 255] {
                    for (origin, base, scale, stride, inset) in [
                        (100u32, 30u32, 3u32, 7u32, 20u32),
                        (0, u32::MAX, 0x8000_0001, 0x8000_0001, u32::MAX),
                        (u32::MAX, 0x8000_0000, u32::MAX, 0, 1),
                    ] {
                        owner.write_bytes(0, 56);
                        owner.add(0xbc / 4).write(origin);
                        owner.add(0xc0 / 4).write(base);
                        owner.add(0xc4 / 4).write(scale);
                        owner.add(0xc8 / 4).write(stride);
                        owner.add(0xcc / 4).write(inset);
                        owner.cast::<u8>().add(0xda).write(gate);
                        let mut expected = [0xa5a5_a5a5u32; 12];
                        expected[0] = owner as usize as u32;
                        expected[4] = 0xa5a5_a500 | index as u32;
                        core::ptr::copy_nonoverlapping(expected.as_ptr(), item, 12);
                        expected[5] = 0;
                        expected[6] = 0;
                        expected[8] = (scale as u64 * 32 + inset as u64 * 2) as u32;
                        expected[7] = (stride as u64 + inset as u64 * 2) as u32;
                        expected[9] = (origin as i64 - inset as i64) as u32;
                        if gate == 0 {
                            expected[10] = (base as i64 + stride as i64 * index as i8 as i64
                                - inset as i64) as u32;
                            expected[11] = 0;
                        }
                        input_sequence_item_reset_geometry(item);
                        assert_eq!(core::slice::from_raw_parts(item, 12), &expected,
                            "gate={gate}, index={index:#x}");
                    }
                }
            }
        }
    }
}
