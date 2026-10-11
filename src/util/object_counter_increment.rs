//! Object counter increment — `FUN_0805c1a4` @ 0x0805c1a4 (16 bytes).
//! Verified inbound calls: 2 plain BLs (0x0804881c, 0x08048910), zero
//! predicated BLs. No outgoing calls. The next function starts at 0x0805c1b4.
//!
//! Raw words `e5901014 e2811001 e5801014 e12fff1e` load the word at +0x14,
//! add one modulo 2^32, store it, and return. Both callers increment before
//! indexed traversal and invoke positive_counter_decrement afterward; the
//! field's higher-level identity is unresolved. No deliberate deviations:
//! no NULL guard, saturation, validation, or synchronization is added.

const COUNTER_WORD: usize = 0x14 / core::mem::size_of::<u32>();

/// Increment the object's +0x14 counter, including wraparound.
///
/// # Safety
/// `object` must be non-NULL, word aligned, and valid for an exclusive read
/// and write of the word at +0x14.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.object_counter_increment")]
#[inline(never)]
pub unsafe extern "C" fn object_counter_increment(object: *mut u8) {
    let counter = object.cast::<u32>().add(COUNTER_WORD);
    counter.write(counter.read().wrapping_add(1));
}

#[cfg(test)]
mod tests {
    use super::object_counter_increment;

    #[test]
    fn increments_all_counter_bit_patterns_without_changing_neighbors() {
        for (initial, expected) in [
            (0, 1),
            (1, 2),
            (0x7fff_ffff, 0x8000_0000),
            (0x8000_0000, 0x8000_0001),
            (0xffff_fffe, 0xffff_ffff),
            (0xffff_ffff, 0),
        ] {
            let mut object = [0x5a5a_5a5au32; 7];
            object[5] = initial;
            unsafe { object_counter_increment(object.as_mut_ptr().cast()) };
            assert_eq!(object[5], expected, "initial {initial:#x}");
            assert_eq!(object[..5], [0x5a5a_5a5a; 5]);
            assert_eq!(object[6], 0x5a5a_5a5a);
        }
    }

    #[test]
    fn repeated_calls_reload_the_wrapped_counter() {
        let mut object = [0u32; 6];
        object[5] = u32::MAX - 1;
        for expected in [u32::MAX, 0, 1] {
            unsafe { object_counter_increment(object.as_mut_ptr().cast()) };
            assert_eq!(object[5], expected);
        }
    }
}
