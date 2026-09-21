//! Four-byte nonzero flag expansion.

/// four_byte_nonzero_to_ff_mask — original: `FUN_0829f9b4` @ **0x0829f9b4**
/// (**68 bytes exactly**, `0x0829f9b4..0x0829f9f8`; the next separately linked
/// function begins at `0x0829f9f8`).
///
/// Decoding every ARM B/BL word in `osos.dec` verifies **3 direct inbound
/// `bl` call sites**, all unconditional; there are no predicated BL forms.
///
/// The function reads four flag bytes at `source+0x7c..0x7f` and writes one
/// byte per flag to `destination`: zero remains zero, and every nonzero value
/// becomes `0xff`. Reads precede all writes, so a destination overlapping the
/// source flag bytes observes the original four-byte input.
/// Deliberate deviations: volatile stores preserve the original's byte-store
/// order in ARM code; for ordinary memory their values are identical.
///
/// # Safety
/// `source` must be valid for reads through offset `0x7f`; `destination` must
/// be valid for four byte writes.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn four_byte_nonzero_to_ff_mask(destination: *mut u8, source: *const u8) {
    let first = source.add(0x7c).read();
    let second = source.add(0x7d).read();
    let third = source.add(0x7e).read();
    let fourth = source.add(0x7f).read();

    core::ptr::write_volatile(destination, if first == 0 { 0 } else { 0xff });
    core::ptr::write_volatile(destination.add(1), if second == 0 { 0 } else { 0xff });
    core::ptr::write_volatile(destination.add(2), if third == 0 { 0 } else { 0xff });
    core::ptr::write_volatile(destination.add(3), if fourth == 0 { 0 } else { 0xff });
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::four_byte_nonzero_to_ff_mask;

    fn reference(flags: [u8; 4]) -> [u8; 4] {
        flags.map(|flag| if flag == 0 { 0 } else { 0xff })
    }

    #[test]
    fn expands_zero_and_nonzero_flag_values() {
        for flags in [[0, 0, 0, 0], [1, 0x80, 0xfe, 0xff], [0, 0xff, 0, 7]] {
            let mut source = [0xa5; 0x80];
            source[0x7c..].copy_from_slice(&flags);
            let mut destination = [0x5a; 6];

            unsafe { four_byte_nonzero_to_ff_mask(destination.as_mut_ptr().add(1), source.as_ptr()) };

            assert_eq!(&destination[1..5], &reference(flags));
            assert_eq!(destination[0], 0x5a);
            assert_eq!(destination[5], 0x5a);
        }
    }

    #[test]
    fn reads_all_flags_before_overlapping_writes() {
        let mut storage = [0u8; 0x80];
        storage[0x7c..].copy_from_slice(&[0, 1, 2, 0]);
        let source = storage.as_ptr();

        unsafe { four_byte_nonzero_to_ff_mask(storage.as_mut_ptr().add(0x7d), source) };

        assert_eq!(&storage[0x7d..], &[0, 0xff, 0xff]);
    }
}
