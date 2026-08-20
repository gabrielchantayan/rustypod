//! `object_byte_at_5` — original: `FUN_0813b0a4` @ `0x0813b0a4`
//! (8 bytes).
//!
//! Loads and returns the raw unsigned byte at `+0x05` from an opaque
//! application object. The recovered callers only compare the returned byte
//! against small values, so they do not establish a concrete object type or a
//! domain meaning for this field; this port therefore retains the offset-based
//! name.
//!
//! Sources: `ipod-decomp/decomp/c/012/0813b0a4_FUN_0813b0a4.c`, the
//! `ldrb r0, [r0, #5]; bx lr` leaf at `0x0813b0a4` in
//! `ipod-decomp/decomp/osos.asm`, and direct callers `FUN_081c08b8` @
//! `0x081c08b8` and `FUN_081ee314` @ `0x081ee314`.
//!
//! Deviation: none.

/// Returns the raw unsigned byte at `+0x05` in an opaque application object.
///
/// # Safety
///
/// `object` must point into a readable allocation that includes byte `+0x05`.
/// The pointer may be unaligned because the retail routine performs a byte
/// load.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn object_byte_at_5(object: *const u8) -> u8 {
    object.add(0x05).read()
}

#[cfg(test)]
mod tests {
    use super::*;

    const BYTE_OFFSET: usize = 0x05;
    const GUARD: u8 = 0xa5;

    #[test]
    fn returns_every_byte_value_without_mutation() {
        let mut object = [GUARD; BYTE_OFFSET + 2];

        for value in 0u8..=u8::MAX {
            object[BYTE_OFFSET] = value;
            let before = object;

            assert_eq!(unsafe { object_byte_at_5(object.as_ptr()) }, value, "byte={value:#04x}");
            assert_eq!(object, before, "read changed object for byte={value:#04x}");
        }
    }

    #[test]
    fn reads_only_offset_five_with_surrounding_guards() {
        let mut object = [GUARD; BYTE_OFFSET + 2];
        object[BYTE_OFFSET - 1] = 0x3c;
        object[BYTE_OFFSET] = 0x6d;
        object[BYTE_OFFSET + 1] = 0xc3;
        let before = object;

        assert_eq!(unsafe { object_byte_at_5(object.as_ptr()) }, 0x6d);
        assert_eq!(object, before, "the byte load must not mutate its object");
        assert_eq!(object[BYTE_OFFSET - 1], 0x3c, "byte before +0x05");
        assert_eq!(object[BYTE_OFFSET + 1], 0xc3, "byte after +0x05");
    }

    #[test]
    fn reads_the_shared_object_through_an_alias_without_mutation() {
        let mut object = [GUARD; BYTE_OFFSET + 2];
        let object_base = object.as_mut_ptr();
        let byte_alias = unsafe { object_base.add(BYTE_OFFSET) };
        unsafe { byte_alias.write(0xe7) };
        let before = object;

        assert_eq!(unsafe { object_byte_at_5(object_base) }, 0xe7);
        assert_eq!(object, before, "the aliased object was only read");
    }
}
