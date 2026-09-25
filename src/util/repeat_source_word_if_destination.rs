//! A conditional repeated-source word fill helper.

/// repeat_source_word_if_destination — retailOS `thunk_FUN_083e96b8` @
/// **0x083e96a0** (**36 bytes exactly**, `0x083e96a0..0x083e96c4`; the next
/// distinct function begins at `0x083e96c4`). Raw words establish that the
/// four-byte entry branches to the loop test at `0x083e96b8`. The loop copies
/// `*source` into consecutive 32-bit destination words `count` times only
/// when `destination` is non-null, then returns the advanced destination.
/// There are two verified inbound plain `bl` calls and no predicated inbound
/// `bl` calls; the leaf makes no calls.
///
/// Deliberate deviations: Rust incorporates the entry branch and exposes the
/// advanced destination left in r0 despite Ghidra's `void` signature.
/// `wrapping_add` represents the firmware's null-destination address
/// arithmetic without Rust pointer-arithmetic UB. Volatile accesses retain
/// the firmware's per-iteration source load and ordered store.
///
/// # Safety
///
/// When `destination` is non-null, `source` must be valid for a `u32` read and
/// `destination..destination + count` must be valid for `u32` writes.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn repeat_source_word_if_destination(
    mut destination: *mut u32,
    mut count: u32,
    source: *const u32,
) -> *mut u32 {
    while count != 0 {
        if !destination.is_null() {
            destination.write_volatile(source.read_volatile());
        }
        count = count.wrapping_sub(1);
        destination = destination.wrapping_add(1);
    }
    destination
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::repeat_source_word_if_destination;

    #[test]
    fn repeats_source_word_and_returns_advanced_destination() {
        let source = 0xa5a5_5a5au32;
        let mut destination = [0xdead_beef; 4];

        let result = unsafe {
            repeat_source_word_if_destination(destination.as_mut_ptr(), 4, &source)
        };

        assert_eq!(destination, [source; 4]);
        assert_eq!(result, destination.as_mut_ptr().wrapping_add(4));
    }

    #[test]
    fn zero_count_preserves_destination_and_returns_it() {
        let source = 0x1122_3344u32;
        let mut destination = [0xdead_beef; 1];

        let result = unsafe {
            repeat_source_word_if_destination(destination.as_mut_ptr(), 0, &source)
        };

        assert_eq!(destination, [0xdead_beef]);
        assert_eq!(result, destination.as_mut_ptr());
    }

    #[test]
    fn reloads_source_each_iteration() {
        let mut words = [1u32, 2, 3];

        unsafe {
            repeat_source_word_if_destination(words.as_mut_ptr().add(1), 2, words.as_ptr());
        }

        assert_eq!(words, [1, 1, 1]);
    }

    #[test]
    fn null_destination_skips_source_access_and_advances_numerically() {
        let result = unsafe {
            repeat_source_word_if_destination(
                core::ptr::null_mut(),
                1,
                4usize as *const u32,
            )
        };

        assert_eq!(result, 4usize as *mut u32);
    }
}
