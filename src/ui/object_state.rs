//! Accessor for an unidentified UI object's state word.

/// object_state_word — original: `FUN_08055e80` @ `0x08055e80` (12 bytes).
///
/// Source: `/home/gabe/Programming/ipod-decomp/decomp/c/003/08055e80_FUN_08055e80.c`.
/// The ARM leaf loads and returns the little-endian 32-bit state word at
/// offset `0xe38` in an otherwise unidentified UI object. It performs no
/// null or alignment checks, matching the original `ldr` ABI.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn object_state_word(object: *const u8) -> u32 {
    (object.add(0xe38) as *const u32).read()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_the_word_at_offset_e38() {
        let mut object = [0u8; 0xe3c];
        object[0xe38..0xe3c].copy_from_slice(&0x89ab_cdefu32.to_le_bytes());

        assert_eq!(unsafe { object_state_word(object.as_ptr()) }, 0x89ab_cdef);
    }

    #[test]
    fn ignores_adjacent_object_bytes() {
        let mut object = [0xa5u8; 0xe40];
        object[0xe34..0xe38].copy_from_slice(&0x1122_3344u32.to_le_bytes());
        object[0xe38..0xe3c].copy_from_slice(&0x5566_7788u32.to_le_bytes());
        object[0xe3c..0xe40].copy_from_slice(&0x99aa_bbccu32.to_le_bytes());

        assert_eq!(unsafe { object_state_word(object.as_ptr()) }, 0x5566_7788);
    }
}
