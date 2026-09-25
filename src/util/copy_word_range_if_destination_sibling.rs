//! A conditional forward word-range copy helper.

/// copy_word_range_if_destination_sibling — original: `thunk_FUN_083e92b8` @
/// **0x083e92a0** (**40 bytes exactly**, `0x083e92a0..0x083e92c8`; the next
/// real function begins at `0x083e92c8`).
///
/// Raw firmware establishes that the four-byte entry branches to the loop test
/// at `0x083e92b8`, whose back-edge reaches the word transfer at `0x083e92a4`.
/// Two direct inbound `bl` calls target the entry (0x083e524c and 0x083e5288),
/// both unconditional; there are no predicated inbound `bl` calls. The
/// function advances `source` and `destination` together until `source == end`,
/// copying each 32-bit word only when `destination` is non-null (both the load
/// and store are predicated on `destination != 0`), then returns the advanced
/// destination.
///
/// Deliberate deviations: the Rust export incorporates the entry branch, so it
/// remains a direct replacement for both callers. `wrapping_add` expresses the
/// firmware's address arithmetic for a null destination without Rust pointer
/// arithmetic UB. Volatile word accesses preserve the ordered `ldr`/`str` loop
/// and prevent LLVM from substituting a libc copy routine.
///
/// # Safety
///
/// The dedicated ARM text section prevents LLVM from folding this byte-identical
/// sibling with the preceding helper, preserving the distinct hook target.
///
/// When `destination` is non-null, `[source, end)` must be a valid forward word
/// range and `[destination, destination + (end - source))` must be valid for
/// writes. Overlap follows the original forward load/store order.
#[cfg_attr(target_os = "none", link_section = ".text.copy_word_range_if_destination_sibling")]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn copy_word_range_if_destination_sibling(
    mut source: *const u32,
    end: *const u32,
    mut destination: *mut u32,
) -> *mut u32 {
    while source != end {
        if !destination.is_null() {
            destination.write_volatile(source.read_volatile());
        }
        source = source.wrapping_add(1);
        destination = destination.wrapping_add(1);
    }
    destination
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::copy_word_range_if_destination_sibling;

    #[test]
    fn copies_words_and_returns_advanced_destination() {
        let source = [0x11223344, 0x55667788, 0xa5a5a5a5];
        let mut destination = [0; 3];

        let result = unsafe {
            copy_word_range_if_destination_sibling(
                source.as_ptr(),
                source.as_ptr().wrapping_add(source.len()),
                destination.as_mut_ptr(),
            )
        };

        assert_eq!(destination, source);
        assert_eq!(result, destination.as_mut_ptr().wrapping_add(3));
    }

    #[test]
    fn preserves_forward_load_store_order_for_overlap() {
        let mut words = [1u32, 2, 3, 4, 5, 6];

        let result = unsafe {
            copy_word_range_if_destination_sibling(
                words.as_ptr(),
                words.as_ptr().wrapping_add(3),
                words.as_mut_ptr().wrapping_add(1),
            )
        };

        assert_eq!(words, [1, 1, 1, 1, 5, 6]);
        assert_eq!(result, words.as_mut_ptr().wrapping_add(4));
    }

    #[test]
    fn null_destination_skips_source_access_and_advances_numerically() {
        let result = unsafe {
            copy_word_range_if_destination_sibling(
                core::ptr::null(),
                4usize as *const u32,
                core::ptr::null_mut(),
            )
        };

        assert_eq!(result, 4usize as *mut u32);
    }
}
