//! `flag_2c_is_one` — original: `FUN_0811c284` @ 0x0811c284 (20 bytes).
//!
//! Loads the byte at offset `+0x2c` from an opaque application-side object and
//! returns one exactly when that byte equals one; it returns zero for every
//! other byte value. The object's layout and ownership remain unidentified, so
//! this module deliberately makes only the observed offset-based claim.
//!
//! Sources: `ipod-decomp/decomp/c/010/0811c284_FUN_0811c284.c` and the
//! `ldrb r0, [r0, #0x2c]; cmp r0, #1; movne/moveq` sequence at 0x0811c284 in
//! `ipod-decomp/decomp/osos.asm`.
//!
//! Deviation: none. This is intentionally not the complement of
//! `ui::flag_2c::flag_2c_is_clear`: byte values 2 through 255 return zero.

/// flag_2c_is_one — original: `FUN_0811c284` @ 0x0811c284 (20 bytes).
///
/// # Safety
///
/// `obj` must point into a readable allocation that includes byte `+0x2c`.
/// The pointer may be unaligned because the retail routine performs a byte
/// load.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn flag_2c_is_one(obj: *const u8) -> u32 {
    (obj.add(0x2c).read() == 1) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_byte_value_one_is_true() {
        let mut object = [0u8; 0x2d];
        for (flag, expected) in [(0u8, 0), (1, 1), (2, 0), (u8::MAX, 0)] {
            object[0x2c] = flag;
            assert_eq!(unsafe { flag_2c_is_one(object.as_ptr()) }, expected, "{flag}");
        }
    }

    #[test]
    fn byte_load_accepts_an_unaligned_object_base() {
        let mut storage = [0u8; 0x2e];
        let unaligned_object = unsafe { storage.as_mut_ptr().add(1) };
        unsafe { unaligned_object.add(0x2c).write(1) };

        assert_eq!(unsafe { flag_2c_is_one(unaligned_object) }, 1);
        unsafe { unaligned_object.add(0x2c).write(2) };
        assert_eq!(unsafe { flag_2c_is_one(unaligned_object) }, 0);
    }
}
