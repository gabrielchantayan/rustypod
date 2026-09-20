//! Set the B-tree auto-vacuum mode when its first page is absent.
//!
//! `btree_set_auto_vacuum` — retailOS `FUN_0837e1b0` at `0x0837e1b0`
//! (24 bytes, `0x0837e1b0..0x0837e1c7`; the next independent `stmdb` at
//! `0x0837e1c8` begins a distinct function). Decoding the raw ARM words finds
//! three inbound direct `bl` call sites, all plain and no predicated `bl`.
//!
//! The ARM body ignores a negative requested mode. For a non-negative mode it
//! tests byte `bt + 0x0f` and stores the low byte at `bt + 0x17` only when that
//! guard byte is zero. It always returns the stored byte.
//!
//! Deliberate deviations: none.

/// Apply `requested_mode` to the target-layout B-tree auto-vacuum byte.
///
/// # Safety
/// `bt` must reference at least 24 readable bytes; it must be writable through
/// `bt + 0x17` when `requested_mode >= 0` and `bt + 0x0f` is zero.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn btree_set_auto_vacuum(bt: *mut u8, requested_mode: i32) -> u8 {
    if requested_mode >= 0 && core::ptr::read_volatile(bt.add(15)) == 0 {
        core::ptr::write_volatile(bt.add(23), requested_mode as u8);
    }
    core::ptr::read_volatile(bt.add(23))
}

#[cfg(test)]
mod tests {
    use super::btree_set_auto_vacuum;



    unsafe fn reference(bt: *mut u8, requested_mode: i32) -> u8 {
        if requested_mode >= 0 && *bt.add(15) == 0 {
            *bt.add(23) = requested_mode as u8;
        }
        *bt.add(23)
    }

    #[test]
    fn changes_only_when_guard_byte_is_clear_for_nonnegative_modes() {
        for &(guard, mode, initial) in &[
            (0u8, 0i32, 0x5au8),
            (0, 2, 0x5a),
            (0, 0x123, 0x5a),
            (1, 2, 0x5a),
            (0, -1, 0x5a),
            (0, i32::MIN, 0x5a),
        ] {
            let mut actual = [0u8; 24];
            let mut expected = [0u8; 24];
            actual[12..15].fill(0xff);
            actual[15] = guard;
            expected.copy_from_slice(&actual);
            actual[23] = initial;
            expected[23] = initial;

            let actual_result = unsafe { btree_set_auto_vacuum(actual.as_mut_ptr(), mode) };
            let expected_result = unsafe { reference(expected.as_mut_ptr(), mode) };

            assert_eq!(actual_result, expected_result, "guard={guard:#x}, mode={mode}");
            assert_eq!(actual, expected, "guard={guard:#x}, mode={mode}");
        }
    }
}
