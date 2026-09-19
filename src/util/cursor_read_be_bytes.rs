//! Big-endian byte cursor reader @ 0x08087fe0.
//!
//! Original: `FUN_08087fe0` @ 0x08087fe0 (44 bytes; extent verified from
//! the raw words in `osos.dec`: its `bx lr` is at 0x08088008 and the next
//! separately entered function starts at 0x0808800c). Decoding ARM branch
//! words finds four direct `bl` call sites, all plain and unpredicated.
//!
//! Algorithm: load the caller-owned byte cursor, consume the requested byte
//! count (with the firmware's decrement-then-low-byte-mask counter), shift
//! each byte into a big-endian accumulator, write back the advanced cursor,
//! and return the accumulator. No deliberate deviations.

/// cursor_read_be_bytes — original: `FUN_08087fe0` @ 0x08087fe0 (44 bytes;
/// four unpredicated `bl` call sites).
///
/// Reads a variable-width big-endian integer from `*cursor` and advances the
/// cursor. The count behavior is intentionally unusual: each iteration masks
/// the decremented counter to eight bits, so zero reads nothing, 1..=256 read
/// that many bytes, and larger values wrap after their first byte.
///
/// # Safety
///
/// `cursor` must be writable and `*cursor` must address every byte consumed.
/// The firmware has no NULL or bounds checks.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.cursor_read_be_bytes")]
pub unsafe extern "C" fn cursor_read_be_bytes(cursor: *mut *const u8, mut count: u32) -> u32 {
    let mut value = 0u32;
    let mut byte_cursor = unsafe { *cursor };

    while count != 0 {
        value = (value << 8) | unsafe { *byte_cursor as u32 };
        byte_cursor = unsafe { byte_cursor.add(1) };
        count = count.wrapping_sub(1) & 0xff;
    }

    unsafe { *cursor = byte_cursor };
    value
}

#[cfg(test)]
mod tests {
    use super::cursor_read_be_bytes;

    #[test]
    fn reads_big_endian_and_advances_cursor() {
        let bytes = [0x12, 0x34, 0x56, 0x78, 0x9a];
        let mut cursor = bytes.as_ptr();

        assert_eq!(unsafe { cursor_read_be_bytes(&mut cursor, 4) }, 0x1234_5678);
        assert_eq!(cursor, unsafe { bytes.as_ptr().add(4) });
    }

    #[test]
    fn zero_count_preserves_cursor_and_returns_zero() {
        let bytes = [0xa5];
        let mut cursor = bytes.as_ptr();

        assert_eq!(unsafe { cursor_read_be_bytes(&mut cursor, 0) }, 0);
        assert_eq!(cursor, bytes.as_ptr());
    }

    #[test]
    fn count_256_consumes_256_bytes_but_count_257_consumes_one() {
        let bytes = [0x5au8; 257];
        let mut cursor = bytes.as_ptr();

        assert_eq!(unsafe { cursor_read_be_bytes(&mut cursor, 256) }, 0x5a5a_5a5a);
        assert_eq!(cursor, unsafe { bytes.as_ptr().add(256) });

        cursor = bytes.as_ptr();
        assert_eq!(unsafe { cursor_read_be_bytes(&mut cursor, 257) }, 0x5a);
        assert_eq!(cursor, unsafe { bytes.as_ptr().add(1) });
    }
}
