//! Conditional two-word copy helper.

/// copy_u32_pair_if_destination — retailOS `FUN_083d7dd0` @ 0x083d7dd0
/// (16 bytes exactly, bounded by the distinct next function at 0x083d7de0).
///
/// Decoding the four words from `osos.dec` gives `movs r0,r1; ldmne r2,
/// {r1,r2}; stmne r0,{r1,r2}; bx lr`. Therefore the ignored first argument
/// is replaced in `r0` by `destination`; when that pointer is non-NULL, the
/// function loads both aligned source words before either destination store.
/// Raw branch decoding verifies four unconditional direct `bl` call sites and
/// no predicated direct `bl` call sites. No deliberate deviations: volatile
/// accesses preserve the grouped load-before-store ordering against LLVM.
///
/// # Safety
/// When `destination` is non-NULL, `source` must be valid for two aligned
/// `u32` reads and `destination` for two aligned `u32` writes. The ranges may
/// overlap.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.copy_u32_pair_if_destination")]
#[inline(never)]
pub unsafe extern "C" fn copy_u32_pair_if_destination(
    _owner: *mut u8,
    destination: *mut u32,
    source: *const u32,
) -> *mut u32 {
    if !destination.is_null() {
        let first = source.read_volatile();
        let second = source.add(1).read_volatile();
        destination.write_volatile(first);
        destination.add(1).write_volatile(second);
    }
    destination
}

#[cfg(test)]
mod tests {
    use super::copy_u32_pair_if_destination;

    fn reference_grouped_pair_copy(words: &mut [u32], destination: usize, source: usize) {
        let first = words[source];
        let second = words[source + 1];
        words[destination] = first;
        words[destination + 1] = second;
    }

    #[test]
    fn copies_both_words_before_storing_and_returns_destination() {
        let initial = [0x1111_1111, 0x2222_2222, 0x3333_3333, 0x4444_4444];
        for destination in 0..=2 {
            for source in 0..=2 {
                let mut expected = initial;
                let mut actual = initial;
                reference_grouped_pair_copy(&mut expected, destination, source);
                let destination_pointer = unsafe { actual.as_mut_ptr().add(destination) };
                let returned = unsafe {
                    copy_u32_pair_if_destination(
                        core::ptr::null_mut(),
                        destination_pointer,
                        actual.as_ptr().add(source),
                    )
                };
                assert_eq!(actual, expected, "destination={destination}, source={source}");
                assert_eq!(returned, destination_pointer);
            }
        }
    }

    #[test]
    fn null_destination_neither_reads_source_nor_writes() {
        let returned = unsafe {
            copy_u32_pair_if_destination(
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null(),
            )
        };
        assert!(returned.is_null());
    }
}
