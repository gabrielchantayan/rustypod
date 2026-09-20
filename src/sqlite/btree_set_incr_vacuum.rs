//! Set the B-tree incremental-vacuum flag.
//!
//! `btree_set_incr_vacuum` — retailOS `FUN_0837e1a0` at `0x0837e1a0`
//! (16 bytes, `0x0837e1a0..0x0837e1af`; the next independent `cmp r1,#0`
//! at `0x0837e1b0` begins `btree_set_auto_vacuum`). Decoding the raw ARM
//! words finds three inbound direct plain `bl` call sites and no predicated
//! `bl` call sites.
//!
//! The ARM body ignores a negative requested value. For a non-negative value
//! it stores the low byte at `bt + 0x18`, then always returns that byte.
//!
//! Deliberate deviations: none.

/// Apply `requested_flag` to the target-layout B-tree incremental-vacuum byte.
///
/// # Safety
/// `bt` must reference at least 25 readable bytes; it must be writable through
/// `bt + 0x18` when `requested_flag >= 0`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn btree_set_incr_vacuum(bt: *mut u8, requested_flag: i32) -> u8 {
    if requested_flag >= 0 {
        core::ptr::write_volatile(bt.add(24), requested_flag as u8);
    }
    core::ptr::read_volatile(bt.add(24))
}

#[cfg(test)]
mod tests {
    use super::btree_set_incr_vacuum;

    unsafe fn reference(bt: *mut u8, requested_flag: i32) -> u8 {
        if requested_flag >= 0 {
            *bt.add(24) = requested_flag as u8;
        }
        *bt.add(24)
    }

    #[test]
    fn changes_only_for_nonnegative_values_and_returns_stored_byte() {
        for &(flag, initial) in &[
            (0i32, 0x5au8),
            (1, 0x5a),
            (0x123, 0x5a),
            (-1, 0x5a),
            (i32::MIN, 0x5a),
            (i32::MAX, 0x5a),
        ] {
            let mut actual = [0u8; 25];
            let mut expected = [0u8; 25];
            actual[24] = initial;
            expected[24] = initial;

            let actual_result = unsafe { btree_set_incr_vacuum(actual.as_mut_ptr(), flag) };
            let expected_result = unsafe { reference(expected.as_mut_ptr(), flag) };

            assert_eq!(actual_result, expected_result, "flag={flag}");
            assert_eq!(actual, expected, "flag={flag}");
        }
    }
}
