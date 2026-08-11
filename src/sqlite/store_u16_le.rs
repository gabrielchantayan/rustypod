/// store_u16_le — original: `FUN_082cf348` @ 0x082cf348 (16 bytes).
///
/// Stores the low 16 bits of `value` into the two-byte destination range at
/// `p` in little-endian order. The retail routine stores the low byte with
/// `strb`, logically shifts `value` right by eight, then stores that byte at
/// `p + 1`; it does not validate `p` and writes exactly those two bytes.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn store_u16_le(p: *mut u8, value: u32) {
    p.write(value as u8);
    p.add(1).write((value >> 8) as u8);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_low_word_least_significant_byte_first() {
        let mut bytes = [0u8; 2];
        unsafe { store_u16_le(bytes.as_mut_ptr(), 0x89ab_cdef) };
        assert_eq!(bytes, [0xef, 0xcd]);
    }

    #[test]
    fn writes_exactly_two_bytes_at_each_valid_alignment_and_boundary() {
        for value in [0u32, 1, 0x0100, 0x8001, 0x89ab_cdef, u32::MAX] {
            for offset in 0..=10 {
                let mut actual = [0xa5u8; 12];
                let mut expected = actual;
                expected[offset..offset + 2].copy_from_slice(&(value as u16).to_le_bytes());

                unsafe { store_u16_le(actual.as_mut_ptr().add(offset), value) };

                assert_eq!(actual, expected, "value={value:#010x}, offset={offset}");
            }
        }
    }
}
