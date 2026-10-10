//! Sixteen-byte uppercase hexadecimal formatting — 0x080a65cc.
//! True extent: 64 bytes, [0x080a65cc, 0x080a660c), including the literal
//! at 0x080a6608; instructions occupy 60 bytes. Verified direct calls:
//! two inbound plain BLs (0x0804b448, 0x0804b454), one outbound plain BL
//! to sprintf @ 0x0802f724, and no predicated BLs in either direction.
//! A null source leaves the destination untouched. Otherwise each of 16
//! source bytes is formatted with `%02X` at destination + 2 * index, then
//! destination[32] is cleared. Runtime format 0x08977f64 maps under the
//! 0xaed8 scatter skew to image 0x08982e3c (raw bytes 25 30 32 58 00).
//! Deliberate deviation: inline the verified fixed format instead of calling
//! variadic sprintf. Preserve its intermediate NUL writes and byte-read order
//! so overlapping source/destination buffers retain the stock behavior.

/// # Safety
/// Unless `source` is null, it must permit 16 byte reads and `destination`
/// must permit 33 byte writes. Buffers may overlap; no concurrent access.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn bytes16_to_upper_hex(source: *const u8, destination: *mut u8) {
    if source.is_null() {
        return;
    }
    const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    for index in 0..16 {
        let byte = source.add(index).read();
        let output = destination.add(index * 2);
        output.write(DIGITS[(byte >> 4) as usize]);
        output.add(1).write(DIGITS[(byte & 15) as usize]);
        output.add(2).write(0);
    }
    destination.add(32).write(0);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::bytes16_to_upper_hex;

    #[test]
    fn every_byte_and_destination_boundaries() {
        for first in (0..=255).step_by(16) {
            let source: [u8; 16] = core::array::from_fn(|i| (first + i) as u8);
            let mut output = [0xa5; 35];
            unsafe { bytes16_to_upper_hex(source.as_ptr(), output.as_mut_ptr().add(1)); }
            let expected: std::string::String = source.iter().map(|b| std::format!("{b:02X}")).collect();
            assert_eq!(&output[1..33], expected.as_bytes());
            assert_eq!(output[33], 0);
            assert_eq!(output[0], 0xa5);
            assert_eq!(output[34], 0xa5);
        }
    }

    #[test]
    fn null_source_does_not_access_destination() {
        let mut output = [0xa5; 33];
        unsafe {
            bytes16_to_upper_hex(core::ptr::null(), output.as_mut_ptr());
            bytes16_to_upper_hex(core::ptr::null(), core::ptr::null_mut());
        }
        assert_eq!(output, [0xa5; 33]);
    }

    #[test]
    fn overlap_matches_sequential_sprintf_writes() {
        for source_offset in 0..=34 {
            for destination_offset in 0..=17 {
                let mut actual: [u8; 50] = core::array::from_fn(|i| (i * 19 + 7) as u8);
                let mut expected = actual;
                for index in 0..16 {
                    let text = std::format!("{:02X}", expected[source_offset + index]);
                    let start = destination_offset + 2 * index;
                    expected[start..start + 2].copy_from_slice(text.as_bytes());
                    expected[start + 2] = 0;
                }
                unsafe {
                    bytes16_to_upper_hex(actual.as_ptr().add(source_offset), actual.as_mut_ptr().add(destination_offset));
                }
                assert_eq!(actual, expected, "source={source_offset}, destination={destination_offset}");
            }
        }
    }
}
