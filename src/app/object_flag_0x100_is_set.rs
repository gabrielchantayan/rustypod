//! `object_flag_0x100_is_set` — original: `FUN_081fb5c8` @ 0x081fb5c8
//! (16 bytes).
//!
//! Loads the aligned 32-bit flag word at offset `+0x14` in an opaque object
//! and returns bit `0x100` normalized to zero or one. The raw words are
//! `e5900014`, `e2000c01`, `e1a00420`, and `e12fff1e`; the next independent
//! function starts at 0x081fb5d8, confirming the 16-byte extent. The body has
//! no BL instructions. Whole-image disassembly finds five inbound plain BL
//! call sites (0x081fb664, 0x081fb780, 0x081fb828, 0x081fb87c, 0x081fb934)
//! and zero predicated BL call sites.
//!
//! Callers use the result to choose the normal or cleanup path for an object
//! held at controller offsets `+0x48` and `+0x5c`; the object's type and the
//! wider meaning of this flag remain unidentified.
//!
//! Sources: `ipod-decomp/decomp/c/021/081fb5c8_FUN_081fb5c8.c`, recovered
//! callers `081fb634` and `081fbb34`, and `osos.dec`.
//!
//! Deliberate deviations: none.

/// Returns whether bit `0x100` is set in the aligned flag word at `object+0x14`.
///
/// # Safety
///
/// `object` must point to at least six readable, properly aligned `u32` words.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn object_flag_0x100_is_set(object: *const u32) -> u32 {
    (object.add(5).read() & 0x100) >> 8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_only_flag_bit_0x100() {
        let mut object = [0u32; 6];

        for (flags, expected) in [
            (0, 0),
            (0x100, 1),
            (0xff, 0),
            (0x200, 0),
            (0xffff_ffff, 1),
        ] {
            object[5] = flags;
            assert_eq!(unsafe { object_flag_0x100_is_set(object.as_ptr()) }, expected, "{flags:#x}");
        }
    }

    #[test]
    fn reads_the_flag_word_without_modifying_adjacent_words() {
        let mut object = [0xfeed_face; 6];
        object[5] = 0x100;
        let before = object;

        assert_eq!(unsafe { object_flag_0x100_is_set(object.as_ptr()) }, 1);
        assert_eq!(object, before);
    }
}
