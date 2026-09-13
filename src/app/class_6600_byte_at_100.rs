//! `class_6600_byte_at_100` — original: `FUN_080fffdc` @
//! `0x080fffdc` (8 bytes; **7 direct `bl` call sites, all unconditional —
//! no predicated `bl` forms and no direct `b` tail sites**, verified by
//! decoding every ARM B/BL word in `work/firmware/osos.dec`).
//!
//! Raw ARM is `ldrb r0, [r0, #0x100]; bx lr`: return the unsigned byte at
//! `+0x100` from the class-0x6600 singleton without a NULL guard or mutation.
//! Every direct caller first invokes `instance_of_class_6600`, then branches on
//! zero versus nonzero; the byte's domain meaning is not otherwise established.
//! The port therefore deliberately retains an offset-based field name rather
//! than inventing a semantic flag.
//!
//! Sources: `ipod-decomp/decomp/c/009/080fffdc_FUN_080fffdc.c` and raw image
//! words at `0x080fffdc..0x080fffe4` (the separately linked next function
//! begins at `0x080fffe4`).
//!
//! Deviation: none.

/// Returns the raw unsigned byte at `+0x100` in a class-0x6600 object.
///
/// # Safety
///
/// `class_6600` must point into a readable allocation that includes byte
/// `+0x100`. The pointer may be unaligned because the retail routine performs
/// a byte load.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn class_6600_byte_at_100(class_6600: *const u8) -> u8 {
    class_6600.add(0x100).read()
}

#[cfg(test)]
mod tests {
    use super::*;

    const BYTE_OFFSET: usize = 0x100;
    const GUARD: u8 = 0xa5;

    #[test]
    fn returns_every_byte_value_without_mutation() {
        let mut class_6600 = [GUARD; BYTE_OFFSET + 2];

        for value in 0u8..=u8::MAX {
            class_6600[BYTE_OFFSET] = value;
            let before = class_6600;

            assert_eq!(unsafe { class_6600_byte_at_100(class_6600.as_ptr()) }, value, "byte={value:#04x}");
            assert_eq!(class_6600, before, "read changed class-0x6600 object");
        }
    }

    #[test]
    fn reads_only_offset_100_with_surrounding_guards() {
        let mut class_6600 = [GUARD; BYTE_OFFSET + 2];
        class_6600[BYTE_OFFSET - 1] = 0x3c;
        class_6600[BYTE_OFFSET] = 0x6d;
        class_6600[BYTE_OFFSET + 1] = 0xc3;
        let before = class_6600;

        assert_eq!(unsafe { class_6600_byte_at_100(class_6600.as_ptr()) }, 0x6d);
        assert_eq!(class_6600, before, "the byte load must not mutate its object");
        assert_eq!(class_6600[BYTE_OFFSET - 1], 0x3c, "byte before +0x100");
        assert_eq!(class_6600[BYTE_OFFSET + 1], 0xc3, "byte after +0x100");
    }

    #[test]
    fn reads_offset_100_from_an_unaligned_object() {
        let mut storage = [GUARD; BYTE_OFFSET + 3];
        let class_6600 = unsafe { storage.as_mut_ptr().add(1) };
        unsafe { class_6600.add(BYTE_OFFSET).write(0xe7) };
        let before = storage;

        assert_eq!(unsafe { class_6600_byte_at_100(class_6600) }, 0xe7);
        assert_eq!(storage, before, "the unaligned byte load must not mutate its object");
    }
}
