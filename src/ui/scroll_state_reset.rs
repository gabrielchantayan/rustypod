//! `scroll_state_reset` — original `FUN_081a0e44` at `0x081a0e44`.
//! True size: 20 bytes; next real function begins at `0x081a0e58` with
//! `stmdb sp!,{r4,r5,r6,r7,r8,r9,lr}`. Raw words:
//! `e3a01000 e5c01150 e3e01003 e580114c e12fff1e`.
//! Whole-image aligned A32 decoding finds zero plain inbound BLs and two
//! predicated BLNEs (0x0821d854, 0x0821ea5c); zero outbound BLs of either kind.
//!
//! Clears the end-reached byte at +0x150, then resets the signed scroll
//! position at +0x14c to -4. The adjacent scroll handler at 0x081a0e58
//! increments/clamps this position and sets the byte when reaching the end;
//! caller 0x0821e914 checks that byte before its Genius action and resets
//! after dispatch. Preserves the owner pointer in r0 and all other bytes.
//! No behavioral deviations. Opaque storage uses target-width word indices;
//! volatile stores preserve the original byte/word widths and store order.

const SCROLL_POSITION_WORD: usize = 0x14c / 4;
const END_REACHED_OFFSET: usize = 0x150;

/// # Safety
/// `owner` must be non-NULL, word-aligned, and writable through byte +0x150.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn scroll_state_reset(owner: *mut u32) -> *mut u32 {
    owner.cast::<u8>().add(END_REACHED_OFFSET).write_volatile(0);
    owner.add(SCROLL_POSITION_WORD).write_volatile((-4i32) as u32);
    owner
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resets_extreme_positions_and_flags_preserving_neighbor_bytes() {
        for position in [i32::MIN, -4, -1, 0, 4, i32::MAX] {
            for flag in [0u8, 1, 0x80, 0xff] {
                let mut owner = [0xa5b6_c7d8u32; END_REACHED_OFFSET / 4 + 2];
                owner[SCROLL_POSITION_WORD] = position as u32;
                let pointer = owner.as_mut_ptr();
                let bytes = unsafe {
                    core::slice::from_raw_parts_mut(pointer.cast::<u8>(), owner.len() * 4)
                };
                bytes[END_REACHED_OFFSET] = flag;
                let mut expected = [0u8; (END_REACHED_OFFSET / 4 + 2) * 4];
                expected.copy_from_slice(bytes);
                expected[0x14c..0x150].copy_from_slice(&(-4i32).to_ne_bytes());
                expected[END_REACHED_OFFSET] = 0;
                assert_eq!(unsafe { scroll_state_reset(pointer) }, pointer);
                let actual = unsafe {
                    core::slice::from_raw_parts(pointer.cast::<u8>(), expected.len())
                };
                assert_eq!(actual, expected);
                assert_eq!(unsafe { scroll_state_reset(pointer) }, pointer);
                let actual = unsafe {
                    core::slice::from_raw_parts(pointer.cast::<u8>(), expected.len())
                };
                assert_eq!(actual, expected);
            }
        }
    }
}
