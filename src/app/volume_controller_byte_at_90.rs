//! `volume_controller_byte_at_90` — original: `FUN_081fa044` @
//! `0x081fa044` (8 bytes; **18 direct `bl` call sites, all unconditional —
//! no predicated `bl` forms and no direct `b` tail sites**, verified by
//! decoding every ARM B/BL word in `work/firmware/osos.dec`).
//!
//! Raw ARM is `ldrb r0, [r0, #0x90]; bx lr`: return the unsigned byte at
//! `+0x90` from a volume-controller object without a NULL guard or mutation.
//! Its constructor (`FUN_081fa070`) initializes this field to zero, while the
//! 18 direct callers distinguish zero, nonzero, and one; neither establishes
//! its domain meaning. The port therefore deliberately retains an
//! offset-based field name rather than inventing a semantic flag.
//!
//! Sources: `ipod-decomp/decomp/c/021/081fa044_FUN_081fa044.c` and raw image
//! words at `0x081fa044..0x081fa04c` (the separately linked next function
//! begins at `0x081fa04c`).
//!
//! Deviation: none.

/// Returns the raw unsigned byte at `+0x90` in a volume-controller object.
///
/// # Safety
///
/// `volume_controller` must point into a readable allocation that includes
/// byte `+0x90`. The pointer may be unaligned because the retail routine
/// performs a byte load.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn volume_controller_byte_at_90(volume_controller: *const u8) -> u8 {
    volume_controller.add(0x90).read()
}

#[cfg(test)]
mod tests {
    use super::*;

    const BYTE_OFFSET: usize = 0x90;
    const GUARD: u8 = 0xa5;

    #[test]
    fn returns_every_byte_value_without_mutation() {
        let mut volume_controller = [GUARD; BYTE_OFFSET + 2];

        for value in 0u8..=u8::MAX {
            volume_controller[BYTE_OFFSET] = value;
            let before = volume_controller;

            assert_eq!(unsafe { volume_controller_byte_at_90(volume_controller.as_ptr()) }, value, "byte={value:#04x}");
            assert_eq!(volume_controller, before, "read changed volume controller for byte={value:#04x}");
        }
    }

    #[test]
    fn reads_only_offset_90_with_surrounding_guards() {
        let mut volume_controller = [GUARD; BYTE_OFFSET + 2];
        volume_controller[BYTE_OFFSET - 1] = 0x3c;
        volume_controller[BYTE_OFFSET] = 0x6d;
        volume_controller[BYTE_OFFSET + 1] = 0xc3;
        let before = volume_controller;

        assert_eq!(unsafe { volume_controller_byte_at_90(volume_controller.as_ptr()) }, 0x6d);
        assert_eq!(volume_controller, before, "the byte load must not mutate its object");
        assert_eq!(volume_controller[BYTE_OFFSET - 1], 0x3c, "byte before +0x90");
        assert_eq!(volume_controller[BYTE_OFFSET + 1], 0xc3, "byte after +0x90");
    }

    #[test]
    fn reads_offset_90_from_an_unaligned_object() {
        let mut storage = [GUARD; BYTE_OFFSET + 3];
        let volume_controller = unsafe { storage.as_mut_ptr().add(1) };
        unsafe { volume_controller.add(BYTE_OFFSET).write(0xe7) };
        let before = storage;

        assert_eq!(unsafe { volume_controller_byte_at_90(volume_controller) }, 0xe7);
        assert_eq!(storage, before, "the unaligned byte load must not mutate its object");
    }
}
