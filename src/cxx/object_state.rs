//! Raw object-state byte predicates ported from retailOS.

/// object_byte2_is_nonzero — original: `FUN_080395d8` @ `0x080395d8`
/// (16 bytes; source: `ipod-decomp/decomp/c/002/080395d8_FUN_080395d8.c`).
///
/// Reads exactly the byte at `object + 0x02` and returns the ARM boolean ABI
/// value: 0 when it is zero, otherwise 1. The four-instruction ARM leaf is
/// `ldrb r0,[r0,#2]; cmp r0,#0; movne r0,#1; bx lr`; neither the object's
/// concrete type nor the field's meaning has been recovered. The sole
/// recovered direct caller, `0x080a55ec`, records this result into its output
/// record at `+0x14` while parsing a 16-byte input record.
///
/// # Safety
///
/// `object` must designate at least three readable bytes. It is not
/// null-checked, matching the original `ldrb`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn object_byte2_is_nonzero(object: *const u8) -> u32 {
    u32::from(object.add(2).read_volatile() != 0)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    #[test]
    fn returns_arm_boolean_for_zero_and_nonzero_byte2_values() {
        for (byte2, expected) in [(0u8, 0u32), (1, 1), (0x80, 1), (u8::MAX, 1)] {
            let object = [0xa5, 0x5a, byte2];
            assert_eq!(unsafe { object_byte2_is_nonzero(object.as_ptr()) }, expected);
        }
    }

    #[test]
    fn reads_only_the_byte_at_target_offset_without_writing() {
        let mut storage = [0xd1, 0xa5, 0x5a, 0, 0xc3, 0xe7, 0xb4];
        let before = storage;
        let object = unsafe { storage.as_ptr().add(1) };

        assert_eq!(unsafe { object_byte2_is_nonzero(object) }, 0);
        storage[3] = 0x01;
        assert_eq!(unsafe { object_byte2_is_nonzero(object) }, 1);

        assert_eq!(storage[0], before[0]);
        assert_eq!(storage[1], before[1]);
        assert_eq!(storage[2], before[2]);
        assert_eq!(storage[4], before[4]);
        assert_eq!(storage[5], before[5]);
        assert_eq!(storage[6], before[6]);
    }
}
