//! Screen byte setter — `FUN_0817470c` @ 0x0817470c, 8 bytes.
//! Verified whole-image inbound calls: two plain BLs, zero predicated BLs;
//! the leaf itself makes no calls. Raw words are `e5c01028 e12fff1e`
//! (`strb r1,[r0,#0x28]; bx lr`); the next function starts at 0x08174714.
//!
//! Store the supplied byte at screen offset 0x28. Both callers obtain the
//! screen from `app_screen_get` (0x08173848), then supply zero or one, but
//! the field's meaning is not established. Do not normalize other values.
//! Deliberate deviations: none; no null guard or other field changes.

/// Set the screen's byte at offset 0x28.
///
/// # Safety
/// `screen` must point to an allocation with writable storage at offset 0x28.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn app_screen_set_byte_0x28(screen: *mut u8, value: u8) {
    screen.add(0x28).write(value);
}

#[cfg(test)]
mod tests {
    use super::app_screen_set_byte_0x28;

    #[test]
    fn preserves_all_other_bytes_for_every_value_and_alignment() {
        for alignment in 0..4 {
            let mut storage = [0xa5u8; 0x30];
            for value in 0..=u8::MAX {
                let mut expected = storage;
                expected[alignment + 0x28] = value;
                unsafe {
                    app_screen_set_byte_0x28(storage.as_mut_ptr().add(alignment), value);
                }
                assert_eq!(storage, expected);
            }
        }
    }
}
