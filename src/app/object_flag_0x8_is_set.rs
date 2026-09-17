//! `object_flag_0x8_is_set` — original: `FUN_082a5d34` @ 0x082a5d34
//! (16 bytes; verified four plain BL callers and zero predicated BL callers).
//!
//! Loads byte `+0x18` from an opaque object, masks bit `0x08`, and normalizes
//! it to zero or one. Raw `osos.dec` words are `e5d00018`, `e2000008`,
//! `e1a001a0`, and `e12fff1e`; the next independent function begins at
//! 0x082a5d44, establishing the 16-byte extent. Callers use this predicate with
//! the sibling `+0x18` bit-`0x10` predicate while selecting controller items;
//! the object type and the wider flag meaning remain unidentified.
//!
//! Sources: `ipod-decomp/work/firmware/osos.dec` and
//! `ipod-decomp/decomp/c/029/082a5d34_FUN_082a5d34.c`; recovered callers
//! `FUN_081357ac`, `FUN_08135894`, and `FUN_08135950`.
//!
//! Deliberate deviation: LLVM emits a frame and uses a register-mask bit extract
//! instead of the stock immediate-mask/shift pair; both return the same 0/1 value.

/// Returns whether bit `0x08` is set in byte `+0x18` of an opaque object.
///
/// # Safety
///
/// `object` must point into a readable allocation that includes byte `+0x18`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn object_flag_0x8_is_set(object: *const u8) -> u32 {
    ((object.add(0x18).read() & 8) >> 3) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    const FLAG_OFFSET: usize = 0x18;
    const GUARD: u8 = 0xa5;

    #[test]
    fn normalizes_only_flag_bit_0x8() {
        let mut object = [GUARD; FLAG_OFFSET + 2];

        for (flags, expected) in [(0u8, 0), (8, 1), (7, 0), (0x10, 0), (u8::MAX, 1)] {
            object[FLAG_OFFSET] = flags;
            assert_eq!(unsafe { object_flag_0x8_is_set(object.as_ptr()) }, expected, "{flags:#04x}");
        }
    }

    #[test]
    fn reads_only_the_flag_byte_without_mutation() {
        let mut object = [GUARD; FLAG_OFFSET + 2];
        object[FLAG_OFFSET - 1] = 0x3c;
        object[FLAG_OFFSET] = 8;
        object[FLAG_OFFSET + 1] = 0xc3;
        let before = object;

        assert_eq!(unsafe { object_flag_0x8_is_set(object.as_ptr()) }, 1);
        assert_eq!(object, before, "a predicate must not mutate its object");
    }
}
