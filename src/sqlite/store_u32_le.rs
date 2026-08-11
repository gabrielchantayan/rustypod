/// store_u32_le — original: `FUN_082cf328` @ 0x082cf328 (32 bytes).
///
/// Stores `value` into the four-byte destination range at `p` in little-endian
/// order. The retail routine derives the three upper bytes with logical shifts
/// by 8, 16, and 24, then performs four alignment-free `strb` stores at
/// `p + 0` through `p + 3`; it does not validate `p`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn store_u32_le(p: *mut u8, value: u32) {
    p.write(value as u8);
    p.add(1).write((value >> 8) as u8);
    p.add(2).write((value >> 16) as u8);
    p.add(3).write((value >> 24) as u8);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_bytes_least_significant_first() {
        let mut bytes = [0u8; 4];
        unsafe { store_u32_le(bytes.as_mut_ptr(), 0x0123_4567) };
        assert_eq!(bytes, [0x67, 0x45, 0x23, 0x01]);
    }

    #[test]
    fn writes_exactly_four_bytes_at_each_valid_alignment_and_boundary() {
        for value in [0u32, 1, 0x0100, 0x8000_0001, 0x89ab_cdef, u32::MAX] {
            for offset in 0..=8 {
                let mut actual = [0xa5u8; 12];
                let mut expected = actual;
                expected[offset..offset + 4].copy_from_slice(&value.to_le_bytes());

                unsafe { store_u32_le(actual.as_mut_ptr().add(offset), value) };

                assert_eq!(actual, expected, "value={value:#010x}, offset={offset}");
            }
        }
    }
}
