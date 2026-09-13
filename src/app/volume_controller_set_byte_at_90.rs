//! `volume_controller_set_byte_at_90` — original: `FUN_081f9d90` @
//! `0x081f9d90` (8 bytes; **6 direct `bl` call sites, all unconditional —
//! no predicated `bl` forms and no direct `b` tail sites**, verified by
//! decoding every ARM B/BL word in `work/firmware/osos.dec`).
//!
//! Raw ARM is `strb r1, [r0, #0x90]; bx lr`: store the supplied byte at `+0x90`
//! in a volume-controller object without a NULL guard. Direct callers write
//! zero or one, but neither proves the field's domain meaning, so this port
//! deliberately retains an offset-based field name.
//!
//! Sources: `ipod-decomp/decomp/c/021/081f9d90_FUN_081f9d90.c` and raw image
//! words at `0x081f9d90..0x081f9d98` (the separately linked next function
//! begins at `0x081f9d98`).
//!
//! Deviation: none.

/// Stores the raw byte at `+0x90` in a volume-controller object.
///
/// # Safety
///
/// `volume_controller` must point into a writable allocation that includes
/// byte `+0x90`. The pointer may be unaligned because the retail routine
/// performs a byte store.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn volume_controller_set_byte_at_90(volume_controller: *mut u8, value: u8) {
    volume_controller.add(0x90).write(value);
}

#[cfg(test)]
mod tests {
    use super::*;

    const BYTE_OFFSET: usize = 0x90;
    const GUARD: u8 = 0xa5;

    #[test]
    fn stores_every_byte_value_without_touching_neighbors() {
        let mut volume_controller = [GUARD; BYTE_OFFSET + 2];
        volume_controller[BYTE_OFFSET - 1] = 0x3c;
        volume_controller[BYTE_OFFSET + 1] = 0xc3;

        for value in 0u8..=u8::MAX {
            let mut expected = volume_controller;
            expected[BYTE_OFFSET] = value;

            unsafe { volume_controller_set_byte_at_90(volume_controller.as_mut_ptr(), value) };

            assert_eq!(volume_controller, expected, "value={value:#04x}");
        }
    }

    #[test]
    fn stores_offset_90_from_an_unaligned_object() {
        let mut storage = [GUARD; BYTE_OFFSET + 3];
        let volume_controller = unsafe { storage.as_mut_ptr().add(1) };
        unsafe {
            volume_controller.add(BYTE_OFFSET - 1).write(0x3c);
            volume_controller.add(BYTE_OFFSET).write(0x6d);
            volume_controller.add(BYTE_OFFSET + 1).write(0xc3);
        }
        let mut expected = storage;
        expected[BYTE_OFFSET + 1] = 0xe7;

        unsafe { volume_controller_set_byte_at_90(volume_controller, 0xe7) };

        assert_eq!(storage, expected);
    }
}
