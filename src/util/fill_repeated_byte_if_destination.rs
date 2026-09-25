//! A conditional repeated-byte fill helper.

/// fill_repeated_byte_if_destination — original: `thunk_FUN_083e96dc` @
/// **0x083e96c4** (**36 bytes exactly**, `0x083e96c4..0x083e96e8`; the next
/// distinct function starts at `0x083e96e8`).
///
/// Raw firmware establishes that the four-byte entry branches to the loop test
/// at 0x083e96dc, whose back-edge reaches the byte transfer at 0x083e96c8.
/// Two direct inbound `bl` calls target the entry, both unconditional; there
/// are no predicated `bl` calls. Until `count` is zero, the loop loads the byte
/// at `value`, stores it at `destination` only when that iteration's
/// `destination` is non-null, and advances `destination`; it returns the
/// advanced destination.
///
/// Deliberate deviations: the Rust export incorporates the entry branch so it
/// directly replaces both callers. `wrapping_add` expresses the firmware's
/// null-destination address arithmetic without Rust pointer-arithmetic UB.
/// Volatile byte accesses preserve the ordered predicated `ldrb`/`strb` loop
/// and prevent LLVM from substituting a libc fill routine.
///
/// # Safety
///
/// When `destination` is non-null on any iteration and `count` is nonzero,
/// `value` must point to a readable byte and the corresponding destination
/// byte must be valid for writing.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn fill_repeated_byte_if_destination(
    mut destination: *mut u8,
    mut count: u32,
    value: *const u8,
) -> *mut u8 {
    while count != 0 {
        if !destination.is_null() {
            destination.write_volatile(value.read_volatile());
        }
        destination = destination.wrapping_add(1);
        count -= 1;
    }
    destination
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::fill_repeated_byte_if_destination;

    #[test]
    fn fills_each_count_and_destination_alignment() {
        for count in 0..=64usize {
            for offset in 0..4usize {
                let value = 0xa5;
                let mut bytes = [0x3c; 72];
                let result = unsafe {
                    fill_repeated_byte_if_destination(
                        bytes.as_mut_ptr().wrapping_add(offset),
                        count as u32,
                        &value,
                    )
                };

                assert_eq!(&bytes[..offset], &[0x3c; 3][..offset]);
                assert!(bytes[offset..offset + count].iter().all(|&byte| byte == value));
                assert!(bytes[offset + count..].iter().all(|&byte| byte == 0x3c));
                assert_eq!(result, bytes.as_mut_ptr().wrapping_add(offset + count));
            }
        }
    }

    #[test]
    fn initially_null_destination_skips_one_value_access() {
        let result = unsafe {
            fill_repeated_byte_if_destination(core::ptr::null_mut(), 1, 1usize as *const u8)
        };

        assert_eq!(result, 1usize as *mut u8);
    }
}
