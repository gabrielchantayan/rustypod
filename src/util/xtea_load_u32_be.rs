//! XTEA counter big-endian u32 load @ 0x080bdb98.
//!
//! True size: 36 bytes, through `bx lr` at 0x080bdbb8; the next real
//! function begins at 0x080bdbbc. Raw ARM decoding verifies two incoming
//! plain BL sites (0x08056ebc and 0x08056ec8), zero predicated BL sites,
//! and no outgoing calls. The XTEA counter encryptor reads its two serialized
//! counter words here, paired with `xtea_store_u32_be` @ 0x080b44a4.
//!
//! Read four unsigned bytes in address order and combine them with shifts
//! 24, 16, 8, and 0. All source alignments are accepted; there are no NULL
//! or bounds guards. Volatile byte reads retain the original access width
//! and ordering. Deliberate deviations: none. Although the sibling reader
//! at 0x080bdb74 is byte-identical, this entry retains its own text section.

/// # Safety
/// `source` must be readable for exactly four bytes; no alignment is required.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.xtea_load_u32_be")]
#[inline(never)]
pub unsafe extern "C" fn xtea_load_u32_be(source: *const u8) -> u32 {
    let high = source.read_volatile() as u32;
    let second = source.add(1).read_volatile() as u32;
    let third = source.add(2).read_volatile() as u32;
    let low = source.add(3).read_volatile() as u32;
    (high << 24) | (second << 16) | (third << 8) | low
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_extreme_and_mixed_words_from_exact_four_byte_inputs() {
        for (bytes, expected) in [
            ([0, 0, 0, 0], 0),
            ([0xff, 0xff, 0xff, 0xff], u32::MAX),
            ([0x80, 0, 0, 1], 0x8000_0001),
            ([0x89, 0xab, 0xcd, 0xef], 0x89ab_cdef),
        ] {
            assert_eq!(unsafe { xtea_load_u32_be(bytes.as_ptr()) }, expected);
        }
    }

    #[test]
    fn preserves_every_unsigned_byte_at_each_position_and_alignment() {
        #[repr(align(4))]
        struct Buffer([u8; 8]);
        for offset in 0..4 {
            for position in 0..4 {
                for byte in 0..=255u8 {
                    let mut buffer = Buffer([0xa5; 8]);
                    buffer.0[offset..offset + 4].copy_from_slice(&[0x12, 0x34, 0x56, 0x78]);
                    buffer.0[offset + position] = byte;
                    let expected = buffer.0[offset..offset + 4].iter()
                        .fold(0u32, |word, &part| word * 256 + part as u32);
                    let before = buffer.0;
                    assert_eq!(unsafe { xtea_load_u32_be(buffer.0.as_ptr().add(offset)) }, expected,
                        "offset={offset}, position={position}, byte={byte}");
                    assert_eq!(buffer.0, before);
                }
            }
        }
    }
}
