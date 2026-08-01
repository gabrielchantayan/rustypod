//! Bounded conversion from a one-byte-length Pascal string to a C string.

/// pascal_u8_to_cstr_bounded — original: `FUN_08046a50` @ 0x08046a50
/// (56 bytes).
///
/// Treats `source[0]` as an unsigned one-byte count, clamps it to the `u32`
/// `maximum`, then performs that many ordered forward byte transfers from
/// `source[1..]` to `destination`. It writes a trailing NUL at
/// `destination[copied]` and returns `copied`. Volatile accesses preserve the
/// original load/store ordering when the ranges alias: each next source byte
/// is read after the preceding destination store.
///
/// # Safety
/// `source` must be valid for reading its count plus every selected payload
/// byte; `destination` must be valid for `copied + 1` byte writes. The ranges
/// may overlap.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn pascal_u8_to_cstr_bounded(
    source: *const u8,
    destination: *mut u8,
    maximum: u32,
) -> u32 {
    let copied = u32::from(source.read_volatile()).min(maximum);
    let mut offset = 0;
    while offset < copied {
        let byte = source.add(offset as usize + 1).read_volatile();
        destination.add(offset as usize).write_volatile(byte);
        offset += 1;
    }
    destination.add(copied as usize).write_volatile(0);
    copied
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::pascal_u8_to_cstr_bounded;

    /// Independent model of the ARM's initial count load followed by its
    /// ordered `ldrb` / `strb` loop.
    fn reference_pascal_u8_to_cstr_bounded(
        bytes: &mut [u8],
        destination: usize,
        source: usize,
        maximum: u32,
    ) -> u32 {
        let copied = u32::from(bytes[source]).min(maximum);
        for offset in 0..copied as usize {
            let byte = bytes[source + offset + 1];
            bytes[destination + offset] = byte;
        }
        bytes[destination + copied as usize] = 0;
        copied
    }

    #[test]
    fn zero_prefix_writes_only_the_terminator() {
        let source = [0, 0x41];
        let mut destination = [0xa5, 0x5a];

        let copied = unsafe {
            pascal_u8_to_cstr_bounded(source.as_ptr(), destination.as_mut_ptr(), u32::MAX)
        };

        assert_eq!(copied, 0);
        assert_eq!(destination, [0, 0x5a]);
    }

    #[test]
    fn clamps_the_unsigned_prefix_to_maximum() {
        let source = [5, b'a', b'b', b'c', b'd', b'e'];
        let mut destination = [0xa5; 7];

        let copied = unsafe {
            pascal_u8_to_cstr_bounded(source.as_ptr(), destination.as_mut_ptr(), 3)
        };

        assert_eq!(copied, 3);
        assert_eq!(&destination[..4], b"abc\0");
        assert_eq!(destination[4..], [0xa5; 3]);
    }

    #[test]
    fn copies_the_full_u8_prefix_for_wide_u32_maximums() {
        let mut source = [0u8; 256];
        source[0] = u8::MAX;
        for (index, byte) in source[1..].iter_mut().enumerate() {
            *byte = index as u8 ^ 0x5a;
        }
        let mut destination = [0xa5; 257];

        for maximum in [256, u32::MAX] {
            destination.fill(0xa5);
            let copied = unsafe {
                pascal_u8_to_cstr_bounded(source.as_ptr(), destination.as_mut_ptr(), maximum)
            };
            assert_eq!(copied, 255, "maximum={maximum:#x}");
            assert_eq!(&destination[..255], &source[1..]);
            assert_eq!(destination[255], 0, "maximum={maximum:#x}");
            assert_eq!(destination[256], 0xa5, "maximum={maximum:#x}");
        }
    }

    #[test]
    fn aliases_match_the_ordered_forward_transfer_reference() {
        // The ARM reads the count before any stores, then interleaves one
        // source read with one destination write. Every valid placement around
        // the source is tested, including destination = source + 2, which
        // overwrites a future source byte before the next iteration reads it.
        const SOURCE: usize = 6;
        for destination in 0..=11 {
            let initial = [
                0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 4, 0x31, 0x32, 0x33, 0x34, 0xed, 0xee,
                0xef, 0xf0, 0xf1,
            ];
            let mut expected = initial;
            let mut actual = initial;

            let expected_count =
                reference_pascal_u8_to_cstr_bounded(&mut expected, destination, SOURCE, 4);
            let actual_count = unsafe {
                pascal_u8_to_cstr_bounded(
                    actual.as_ptr().add(SOURCE),
                    actual.as_mut_ptr().add(destination),
                    4,
                )
            };

            assert_eq!(actual_count, expected_count, "destination={destination}");
            assert_eq!(actual, expected, "destination={destination}");
        }
    }
}
