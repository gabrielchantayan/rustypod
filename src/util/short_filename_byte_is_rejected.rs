//! `short_filename_byte_is_rejected` — original: `FUN_082b14b0` @
//! `0x082b14b0` (**52 bytes**, `0x082b14b0..0x082b14e3`; the literal pointer
//! at `0x082b14e4` is `0x08905994`, and the next real function begins at
//! `0x082b14e8`). Raw A32 decoding finds three inbound plain unconditional
//! `bl` call sites (`0x082e2cac`, `0x082e2d0c`, and `0x082e4ab4`) and no
//! predicated inbound `bl` forms. The body makes no calls.
//!
//! The retail byte list begins at `0x08905994` and ends at the NUL after the
//! adjacent `SQLite format 3` bytes. It rejects `0x20`, `L`, `Q`, `S`, every
//! byte from `0x31` through `0x40`, and every byte from `0x61` through `0xff`.
//! Values above `0xff` are not list members.
//!
//! ## Deliberate deviations
//!
//! The literal byte list is represented as equivalent ranges and singleton
//! comparisons rather than dereferenced firmware storage.

/// Returns one when `byte` occurs in the retail short-filename rejection list.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub extern "C" fn short_filename_byte_is_rejected(byte: u32) -> u32 {
    u32::from(
        byte == u32::from(b' ')
            || byte == u32::from(b'L')
            || byte == u32::from(b'Q')
            || byte == u32::from(b'S')
            || (0x31..=0x40).contains(&byte)
            || (0x61..=0xff).contains(&byte),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference_rejection_list(byte: u32) -> u32 {
        u32::from(
            byte == u32::from(b' ')
                || byte == u32::from(b'L')
                || byte == u32::from(b'Q')
                || byte == u32::from(b'S')
                || (0x31..=0x40).contains(&byte)
                || (0x61..=0xff).contains(&byte),
        )
    }

    #[test]
    fn matches_the_retail_list_across_the_byte_domain() {
        for byte in 0..=u32::from(u8::MAX) {
            assert_eq!(
                short_filename_byte_is_rejected(byte),
                reference_rejection_list(byte),
                "byte {byte:#04x}",
            );
        }
    }

    #[test]
    fn preserves_range_edges_and_non_byte_inputs() {
        for (byte, expected) in [
            (0x1f, 0),
            (0x20, 1),
            (0x21, 0),
            (0x30, 0),
            (0x31, 1),
            (0x40, 1),
            (0x41, 0),
            (u32::from(b'L'), 1),
            (u32::from(b'M'), 0),
            (u32::from(b'Q'), 1),
            (u32::from(b'R'), 0),
            (u32::from(b'S'), 1),
            (u32::from(b'T'), 0),
            (0x60, 0),
            (0x61, 1),
            (0xff, 1),
            (0x100, 0),
            (u32::MAX, 0),
        ] {
            assert_eq!(short_filename_byte_is_rejected(byte), expected, "byte {byte:#010x}");
        }
    }
}
