//! Decode the cipher seed in a packed application record.
//!
//! Original: `FUN_08164b3c` @ `0x08164b3c`, true size 104 bytes
//! (`0x08164b3c..0x08164ba4`, next independent function). Raw A32 words
//! verify two inbound plain BLs (0x08163ef4, 0x08164cb8), zero predicated
//! inbound BLs, and zero outbound plain or predicated BLs.
//!
//! Header bits 0..1 give the preceding field's byte count. Zero means no
//! seed and returns zero without reading beyond the header. Otherwise skip
//! the header, that field, and one extra byte when bit 7 is set. Bits 2..3
//! encode seed width minus one; assemble 1..4 bytes little-endian. The
//! caller at 0x08164c98 uses the result to derive cipher feedback state.
//! Deliberate deviations: none in behavior; Rust matches width instead of
//! retaining the unreachable fallback after masking the header with 0x0c.

/// Read the variable-width cipher seed, or zero if its prefix is absent.
///
/// # Safety
/// `record` must point to a readable header. If its low two bits are
/// nonzero, the selected seed bytes after the prefix must also be readable.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn packed_record_cipher_seed(record: *const u8) -> u32 {
    let header = record.read();
    let prefix_bytes = header & 3;
    if prefix_bytes == 0 {
        return 0;
    }
    let seed = record.add(1 + prefix_bytes as usize + (header >> 7) as usize);
    let mut value = 0;
    match header & 0x0c {
        0x0c => {
            value |= (seed.add(3).read() as u32) << 24;
            value |= (seed.add(2).read() as u32) << 16;
            value |= (seed.add(1).read() as u32) << 8;
        }
        0x08 => {
            value |= (seed.add(2).read() as u32) << 16;
            value |= (seed.add(1).read() as u32) << 8;
        }
        0x04 => value |= (seed.add(1).read() as u32) << 8,
        _ => {}
    }
    value | seed.read() as u32
}

#[cfg(test)]
mod tests {
    use super::packed_record_cipher_seed;

    #[test]
    fn absent_prefix_requires_only_the_header() {
        for header in (0u8..=255).filter(|header| header & 3 == 0) {
            assert_eq!(unsafe { packed_record_cipher_seed(&header) }, 0);
        }
    }

    #[test]
    fn all_headers_alignments_and_seed_widths_match_reference() {
        let patterns = [0u32, 0xffff_ffff, 0x80ff_0182, 0x1234_5678];
        for header in 0u8..=255 {
            if header & 3 == 0 {
                continue;
            }
            let prefix = (header & 3) as usize;
            let offset = 1 + prefix + usize::from(header & 0x80 != 0);
            let width = 1 + ((header >> 2) & 3) as usize;
            for alignment in 0..4 {
                for pattern in patterns {
                    let mut buffer = [0xa5u8; 16];
                    let record = &mut buffer[alignment..alignment + offset + width];
                    record[0] = header;
                    record[offset..].copy_from_slice(&pattern.to_le_bytes()[..width]);
                    let expected = record[offset..].iter().enumerate().fold(
                        0u32, |value, (index, byte)| value | ((*byte as u32) << (index * 8)),
                    );
                    assert_eq!(unsafe { packed_record_cipher_seed(record.as_ptr()) }, expected,
                        "header={header:#x}, alignment={alignment}, pattern={pattern:#x}");
                    assert_eq!(buffer[alignment + offset + width], 0xa5);
                }
            }
        }
    }
}
