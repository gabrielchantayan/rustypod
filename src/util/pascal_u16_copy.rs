//! Forward copy of a halfword-counted Pascal string.

/// pascal_u16_copy — original: `FUN_08046b60` @ 0x08046b60 (52 bytes).
///
/// Verified calls: 0 plain BL and 0 predicated BL. The original returns when
/// either pointer is null. Otherwise it loads the unsigned halfword count at
/// `source[0]`, copies that count word, then copies exactly that many payload
/// halfwords through ordered forward `ldrh`/`strh` pairs. Each payload load
/// follows the preceding store, so overlapping ranges retain the original
/// forward-copy behavior rather than memcpy or memmove semantics. Deliberate
/// deviations: none; volatile accesses preserve the ARM memory-access order.
///
/// # Safety
/// When non-null, `source` must be valid for `source[0] + 1` aligned `u16`
/// reads and `destination` for the corresponding aligned writes. The ranges
/// may overlap.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn pascal_u16_copy(source: *const u16, destination: *mut u16) {
    if source.is_null() || destination.is_null() {
        return;
    }

    let count = source.read_volatile();
    destination.write_volatile(count);
    let mut offset = 1;
    while offset <= usize::from(count) {
        destination.add(offset).write_volatile(source.add(offset).read_volatile());
        offset += 1;
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::pascal_u16_copy;

    fn reference_pascal_u16_copy(words: &mut [u16], destination: usize, source: usize) {
        let count = words[source];
        words[destination] = count;
        for offset in 1..=usize::from(count) {
            words[destination + offset] = words[source + offset];
        }
    }

    #[test]
    fn null_pointer_is_a_no_op() {
        unsafe {
            pascal_u16_copy(core::ptr::null(), core::ptr::null_mut());
        }
    }

    #[test]
    fn zero_count_copies_only_the_count_word() {
        let source = [0, 0x1234];
        let mut destination = [0xdead, 0xbeef];

        unsafe {
            pascal_u16_copy(source.as_ptr(), destination.as_mut_ptr());
        }

        assert_eq!(destination, [0, 0xbeef]);
    }

    #[test]
    fn copies_count_and_full_payload() {
        let source = [3, 0x1111, 0x2222, 0x3333];
        let mut destination = [0; 4];

        unsafe {
            pascal_u16_copy(source.as_ptr(), destination.as_mut_ptr());
        }

        assert_eq!(destination, source);
    }

    #[test]
    fn overlapping_ranges_match_the_ordered_arm_transfers() {
        for destination in 0..=4 {
            let source = 2;
            let initial = [0xaaaa, 0xbbbb, 3, 0x1111, 0x2222, 0x3333, 0xeeee, 0xffff];
            let mut expected = initial;
            let mut actual = initial;

            reference_pascal_u16_copy(&mut expected, destination, source);
            unsafe {
                pascal_u16_copy(actual.as_ptr().add(source), actual.as_mut_ptr().add(destination));
            }

            assert_eq!(actual, expected, "destination={destination}");
        }
    }
}
