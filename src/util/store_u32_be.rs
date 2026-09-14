//! Ordered big-endian u32 store @ 0x080b447c.
//!
//! Raw ARM establishes the complete 40-byte extent from `lsr r2, r1, #24`
//! at 0x080b447c through `bx lr` at 0x080b44a0; the separately linked,
//! byte-identical sibling begins at 0x080b44a4. Decoding every immediate
//! `B`/`BL` word in osos.dec finds six direct, unconditional `bl` call sites
//! (0x080e7164, 0x080e7170, 0x080e717c, 0x080e7188, 0x080e71b0, and
//! 0x080e71dc), with no predicated calls or tail branches. The caller builds
//! an XTEA state record by writing four fixed words and two variable lists.
//! There are no aligned raw data-word references to this entry.
//!
//! The routine stores a u32 as four big-endian bytes with four ordered `strb`
//! instructions, allowing every destination alignment. It has no NULL or
//! bounds guard. Rust uses volatile byte stores to retain the firmware's
//! high-byte-to-low-byte store order under LLVM optimization. Deliberate
//! deviations: none.

/// store_u32_be — original: `FUN_080b447c` @ 0x080b447c (40 bytes; six direct
/// unconditional `bl` call sites, binary-scanned).
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.store_u32_be")]
#[inline(never)]
pub unsafe extern "C" fn store_u32_be(destination: *mut u8, value: u32) {
    destination.write_volatile((value >> 24) as u8);
    destination.add(1).write_volatile((value >> 16) as u8);
    destination.add(2).write_volatile((value >> 8) as u8);
    destination.add(3).write_volatile(value as u8);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_most_significant_byte_first() {
        let mut bytes = [0u8; 4];

        unsafe { store_u32_be(bytes.as_mut_ptr(), 0x0123_4567) };

        assert_eq!(bytes, [0x01, 0x23, 0x45, 0x67]);
    }

    #[test]
    fn writes_exactly_four_bytes_at_each_valid_alignment_and_boundary() {
        for value in [0u32, 1, 0x0100, 0x8000_0001, 0x89ab_cdef, u32::MAX] {
            for offset in 0..=8 {
                let mut actual = [0xa5u8; 12];
                let mut expected = actual;
                expected[offset..offset + 4].copy_from_slice(&value.to_be_bytes());

                unsafe { store_u32_be(actual.as_mut_ptr().add(offset), value) };

                assert_eq!(actual, expected, "value={value:#010x}, offset={offset}");
            }
        }
    }
}
