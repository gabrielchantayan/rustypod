//! String tag packing — `FUN_081625f4` @ **0x081625f4**.
//!
//! Raw extent: 116 bytes, ending at the next prologue @ 0x08162668.
//! Verified calls: one unconditional outbound BL to strlen @ 0x08392478,
//! zero predicated BL; two incoming BL sites @ 0x081624a8 and 0x08162694.
//! Packs the first four bytes in big-endian order before scanning for NUL.
//! Lengths 1, 2, and 3 OR in 0x00202020, 0x00002020, and 0x00000020;
//! length 4 returns the packed word, and every other length returns zero.
//! The trailing bytes are not replaced: bytes after NUL still contribute.
//! No algorithmic deviations. Volatile byte reads preserve the stock read
//! order and extent; the existing ported strlen is used without a new seam.

/// Packs a NUL-terminated tag of length 1..=4, retaining the unused r0 ABI slot.
///
/// # Safety
/// `text` must point to at least four readable bytes and a readable
/// NUL-terminated string. No NULL guard exists in the original.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn string_tag_pack(_context: *const u8, text: *const u8) -> u32 {
    let tag = ((text.read_volatile() as u32) << 24)
        | ((text.add(1).read_volatile() as u32) << 16)
        | ((text.add(2).read_volatile() as u32) << 8)
        | text.add(3).read_volatile() as u32;
    match crate::libc::strlen::strlen(text) {
        1 => tag | 0x0020_2020,
        2 => tag | 0x0000_2020,
        3 => tag | 0x0000_0020,
        4 => tag,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::string_tag_pack;

    fn reference(bytes: &[u8]) -> u32 {
        let length = bytes.iter().position(|&byte| byte == 0).unwrap();
        if !(1..=4).contains(&length) {
            return 0;
        }
        let mut tag = u32::from_be_bytes(bytes[..4].try_into().unwrap());
        for shift in 0..(4 - length) {
            tag |= 0x20 << (shift * 8);
        }
        tag
    }

    #[test]
    fn lengths_alignments_and_post_nul_bytes() {
        for alignment in 0..4 {
            for length in 0..=8 {
                let mut bytes = [0xd7u8; 16];
                for index in 0..length {
                    bytes[alignment + index] = 0x81 + index as u8;
                }
                bytes[alignment + length] = 0;
                let text = &bytes[alignment..];
                assert_eq!(unsafe { string_tag_pack(core::ptr::null(), text.as_ptr()) },
                    reference(text), "alignment={alignment}, length={length}");
            }
        }
    }

    #[test]
    fn padding_is_or_not_replacement() {
        let cases: [(&[u8], u32); 4] = [
            (b"A\0\x81\x04", 0x4120_a124),
            (b"AB\0\x04", 0x4142_2024),
            (b"ABC\0", 0x4142_4320),
            (b"ABCD\0", 0x4142_4344),
        ];
        for (bytes, expected) in cases {
            assert_eq!(unsafe { string_tag_pack(core::ptr::null(), bytes.as_ptr()) }, expected);
        }
    }
}
