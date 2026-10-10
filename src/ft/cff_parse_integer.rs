//! CFF DICT integer decoding (`cffparse.c`).
//!
//! `cff_parse_integer` — original `FUN_080a1b68` at load address
//! `0x080a1b68`, 188 bytes (`0x080a1b68..0x080a1c24`, next real function
//! starts with push at `0x080a1c24`). Raw A32 decoding verifies two plain
//! inbound BLs (`0x08090410`, `0x080d4044`), zero predicated inbound BLs,
//! and zero outgoing BLs of either kind.
//!
//! Read the initial byte unconditionally. Tokens 28 and 29 decode signed
//! big-endian 16-bit and 32-bit integers; tokens below 247 otherwise subtract
//! 139. Tokens 247..250 add a second byte to a positive base; 251..255 use
//! a negative base. Truncated multibyte encodings return zero. Preserve even
//! noncanonical tokens (0..27, 30..31 and 255), and do not advance the cursor.
//! Deliberate deviations: none; return signed values as their u32 ABI bits.

/// # Safety
/// `cursor` must be readable for one byte even when `limit <= cursor`.
/// Any payload accepted by the exclusive address limit must be readable.
/// Address additions must not wrap; `limit` is compared as an unsigned address.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cff_parse_integer(cursor: *const u8, limit: *const u8) -> u32 {
    let token = cursor.read();
    let needed = match token { 28 => 3, 29 => 5, 247..=255 => 2, _ => 1 };
    if needed > 1 && cursor.wrapping_add(needed) as usize > limit as usize {
        return 0;
    }
    match token {
        28 => u16::from_be_bytes([cursor.add(1).read(), cursor.add(2).read()]) as i16 as u32,
        29 => (cursor.add(1).read() as u32) << 24
            | (cursor.add(2).read() as u32) << 16
            | (cursor.add(3).read() as u32) << 8
            | cursor.add(4).read() as u32,
        0..=246 => (token as u32).wrapping_sub(139),
        247..=250 => cursor.add(1).read() as u32 + (token as u32 - 247) * 256 + 108,
        _ => 0xffff_ff94u32.wrapping_sub(cursor.add(1).read() as u32 + (token as u32 - 251) * 256),
    }
}

#[cfg(test)]
mod tests {
    use super::cff_parse_integer;

    fn decode(bytes: &[u8], available: usize) -> i32 {
        unsafe { cff_parse_integer(bytes.as_ptr(), bytes.as_ptr().add(available)) as i32 }
    }

    #[test]
    fn all_short_tokens_and_payloads_match_signed_ranges() {
        for token in 0u8..=255 {
            if token == 28 || token == 29 { continue; }
            for payload in 0u8..=255 {
                let expected = match token {
                    0..=246 => token as i32 - 139,
                    247..=250 => 108 + (token as i32 - 247) * 256 + payload as i32,
                    _ => -108 - (token as i32 - 251) * 256 - payload as i32,
                };
                assert_eq!(decode(&[token, payload], 2), expected);
            }
        }
    }

    #[test]
    fn big_endian_signed_boundaries_and_unaligned_inputs() {
        for value in [i16::MIN, -1, 0, 1, i16::MAX] {
            let b = value.to_be_bytes();
            for offset in 0..4 {
                let mut storage = [0u8; 8];
                storage[offset..offset + 3].copy_from_slice(&[28, b[0], b[1]]);
                assert_eq!(decode(&storage[offset..], 3), value as i32);
            }
        }
        for value in [i32::MIN, -1, 0, 1, i32::MAX, 0x1234_5678] {
            let b = value.to_be_bytes();
            for offset in 0..4 {
                let mut storage = [0u8; 8];
                storage[offset..offset + 5].copy_from_slice(&[29, b[0], b[1], b[2], b[3]]);
                assert_eq!(decode(&storage[offset..], 5), value);
            }
        }
    }

    #[test]
    fn exclusive_limit_rejects_every_truncated_payload() {
        for token in [28, 29, 247, 250, 251, 254, 255] {
            let bytes = [token, 0x80, 0x01, 0x02, 0x03];
            let needed = match token { 28 => 3, 29 => 5, _ => 2 };
            for available in 0..needed {
                assert_eq!(decode(&bytes, available), 0);
            }
            assert_ne!(decode(&bytes, needed), 0);
        }
        // The initial read and single-byte arithmetic do not check the limit.
        assert_eq!(decode(&[0], 0), -139);
        assert_eq!(decode(&[246], 0), 107);
        let bytes = [0, 247, 1];
        assert_eq!(unsafe { cff_parse_integer(bytes.as_ptr().add(1), bytes.as_ptr()) }, 0);
    }
}
