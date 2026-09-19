//! XTEA counter big-endian u32 store @ 0x080b44a4.
//!
//! Raw ARM establishes the complete 40-byte extent from `lsr r2, r1, #24`
//! at 0x080b44a4 through `bx lr` at 0x080b44c8; the next function starts at
//! 0x080b44cc. It has four direct, unconditional `bl` call sites and no
//! predicated calls. The XTEA encryptor serializes counter and encrypted state
//! words through this entry.
//!
//! The routine stores a u32 as four big-endian bytes with four ordered `strb`
//! instructions, allowing every destination alignment. It has no NULL or
//! bounds guard. Rust uses volatile byte stores to preserve the firmware's
//! high-byte-to-low-byte store order under LLVM optimization. Deliberate
//! deviations: none.

/// xtea_store_u32_be — original: `FUN_080b44a4` @ 0x080b44a4 (40 bytes; four
/// direct unconditional `bl` call sites, binary-scanned).
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.xtea_store_u32_be")]
#[inline(never)]
pub unsafe extern "C" fn xtea_store_u32_be(destination: *mut u8, value: u32) {
    destination.write_volatile((value >> 24) as u8);
    destination.add(1).write_volatile((value >> 16) as u8);
    destination.add(2).write_volatile((value >> 8) as u8);
    destination.add(3).write_volatile(value as u8);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_xtea_words_in_big_endian_order() {
        let mut bytes = [0u8; 4];

        unsafe { xtea_store_u32_be(bytes.as_mut_ptr(), 0x89ab_cdef) };

        assert_eq!(bytes, [0x89, 0xab, 0xcd, 0xef]);
    }

    #[test]
    fn writes_only_four_bytes_at_each_alignment() {
        for value in [0u32, 1, 0x0100, 0x8000_0001, 0x89ab_cdef, u32::MAX] {
            for offset in 0..=8 {
                let mut actual = [0xa5u8; 12];
                let mut expected = actual;
                expected[offset..offset + 4].copy_from_slice(&value.to_be_bytes());

                unsafe { xtea_store_u32_be(actual.as_mut_ptr().add(offset), value) };

                assert_eq!(actual, expected, "value={value:#010x}, offset={offset}");
            }
        }
    }
}
