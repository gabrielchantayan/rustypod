//! `long_filename_byte_is_rejected` — original: `FUN_082b14e8` @
//! `0x082b14e8` (**52 bytes**, `0x082b14e8..0x082b151b`). The literal
//! pointer at `0x082b151c` is `0x089059a5`; the next real function starts
//! with `push {r4, lr}` at `0x082b1520`. Whole-image aligned A32 decoding
//! finds two inbound plain BL calls (`0x082e4a4c`, `0x08396df4`), zero
//! predicated inbound BL calls, and no outbound calls.
//!
//! Scan the byte list at `0x089059a5` until its NUL at `0x08905a72`,
//! returning one for a matching full-width u32 input and zero otherwise.
//! The list includes adjacent `SQLite format 3` bytes: its members are
//! space, `3`, `L`, `Q`, `S`, and `0x5b..=0xff`. NUL is not a member.
//!
//! Deliberate deviation: equivalent ranges and singleton comparisons replace
//! reads from immutable firmware storage; the adjacent-string memberships
//! are preserved rather than corrected to a conventional filename policy.

/// Returns one when `byte` occurs in the retail long-filename rejection list.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub extern "C" fn long_filename_byte_is_rejected(byte: u32) -> u32 {
    u32::from(
        byte == u32::from(b' ')
            || byte == u32::from(b'3')
            || byte == u32::from(b'L')
            || byte == u32::from(b'Q')
            || byte == u32::from(b'S')
            || (0x5b..=0xff).contains(&byte),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn retail_scan(byte: u32) -> u32 {
        // Independent reconstruction of the raw 205-byte list, including
        // the duplicate lowercase alphabet and the adjacent SQLite header.
        let prefix = b"bcdefghijklmnopqrstuvwxyz[\\]^_`";
        let suffix = b"SQLite format 3\0";
        for candidate in prefix.iter().copied()
            .chain(0x61u8..=0xff)
            .chain(suffix.iter().copied())
        {
            if candidate == 0 {
                return 0;
            }
            if u32::from(candidate) == byte {
                return 1;
            }
        }
        unreachable!()
    }

    #[test]
    fn matches_raw_scan_for_every_byte() {
        for byte in 0..=0xff {
            assert_eq!(long_filename_byte_is_rejected(byte), retail_scan(byte), "{byte:#04x}");
        }
    }

    #[test]
    fn does_not_truncate_full_width_arguments() {
        for byte in [0x100, 0x120, 0x133, 0x15b, 0x1ff, 0x80000020, u32::MAX] {
            assert_eq!(long_filename_byte_is_rejected(byte), 0, "{byte:#010x}");
        }
    }
}
