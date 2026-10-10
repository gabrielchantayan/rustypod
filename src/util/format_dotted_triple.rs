//! Packed 8/8/16-bit dotted decimal formatter — FUN_0806e0a4 @ 0x0806e0a4.
//! True extent: 60 bytes, [0x0806e0a4, 0x0806e0e0): 48 instruction bytes
//! plus "%d.%d.%d\0" and padding. Raw whole-image A32 decoding verifies two
//! inbound plain BLs (0x08052240, 0x08055f68), one outbound plain BL to
//! retail_sprintf @ 0x080edc2c, and zero predicated BLs in either direction.
//! Split the word into its high byte, middle byte and low halfword, emit
//! their decimal representations separated by dots, then NUL-terminate.
//! Return the character count: the original preserves sprintf's r0 result.
//! Deliberate deviation: inline the verified fixed format, as in
//! bytes16_to_upper_hex, rather than constructing a variadic argument list
//! and invoking the general formatter. No allocation or null guard.

/// # Safety
/// `destination` must be writable for the formatted text and terminator
/// (at most 14 bytes). No concurrent access to that storage.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn format_dotted_triple(word: u32, destination: *mut u8) -> i32 {
    let components = [word >> 24, (word >> 16) & 0xff, word & 0xffff];
    let mut cursor = destination;
    for (index, mut value) in components.into_iter().enumerate() {
        if index != 0 {
            cursor.write(b'.');
            cursor = cursor.add(1);
        }
        let mut divisor = 1;
        while value / divisor >= 10 {
            divisor *= 10;
        }
        loop {
            cursor.write(b'0' + (value / divisor) as u8);
            cursor = cursor.add(1);
            value %= divisor;
            if divisor == 1 {
                break;
            }
            divisor /= 10;
        }
    }
    cursor.write(0);
    cursor.offset_from(destination) as i32
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::format_dotted_triple;

    #[test]
    fn decimal_boundaries_and_unaligned_destination() {
        for high in [0, 1, 9, 10, 99, 100, 255] {
            for middle in [0, 1, 9, 10, 99, 100, 255] {
                for low in [0, 1, 9, 10, 99, 100, 255, 256, 999, 1000, 9999, 10000, 65535] {
                    let word = (high << 24) | (middle << 16) | low;
                    let expected = std::format!("{high}.{middle}.{low}");
                    for offset in 0..4 {
                        let mut buffer = [0xa5; 20];
                        let count = unsafe { format_dotted_triple(word, buffer.as_mut_ptr().add(offset)) };
                        assert_eq!(count as usize, expected.len());
                        assert_eq!(&buffer[offset..offset + expected.len()], expected.as_bytes());
                        assert_eq!(buffer[offset + expected.len()], 0);
                        assert!(buffer[..offset].iter().all(|&b| b == 0xa5));
                        assert!(buffer[offset + expected.len() + 1..].iter().all(|&b| b == 0xa5));
                    }
                }
            }
        }
    }
}
