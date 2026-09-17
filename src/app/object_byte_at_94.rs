//! `object_byte_at_94` — original: `FUN_0826cb70` @ 0x0826cb70
//! (8 bytes; next real function begins at 0x0826cb78).
//!
//! Loads and zero-extends byte `+0x94` from an opaque object. Raw ARM is
//! `ldrb r0,[r0,#0x94]; bx lr`. Decoding all ARM branch-with-link words in
//! `osos.dec` finds four unconditional `bl` callers and no predicated `bl`
//! callers. The recovered callers use the byte as a nonzero event gate, but do
//! not establish a semantic field identity, so this port retains an
//! offset-based name.
//!
//! Sources: `ipod-decomp/work/firmware/osos.dec`; 
//! `ipod-decomp/decomp/c/026/0826cb70_FUN_0826cb70.c`; direct callers
//! `FUN_08157670`, `FUN_08157cdc`, `FUN_08158694`, and `FUN_081850f0`.
//!
//! Deviation: none.

/// Returns the zero-extended byte at `+0x94` of an opaque object.
///
/// # Safety
///
/// `object` must point into a readable allocation containing byte `+0x94`.
/// The pointer may be unaligned because the retail routine performs a byte
/// load.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn object_byte_at_94(object: *const u8) -> u8 {
    object.add(0x94).read()
}

#[cfg(test)]
mod tests {
    use super::*;

    const OFFSET: usize = 0x94;
    const GUARD: u8 = 0xa5;

    #[test]
    fn returns_each_possible_byte_value_without_booleanizing() {
        let mut object = [GUARD; OFFSET + 2];

        for value in [0u8, 1, 2, 0x80, u8::MAX] {
            object[OFFSET] = value;
            assert_eq!(unsafe { object_byte_at_94(object.as_ptr()) }, value);
        }
    }

    #[test]
    fn reads_exactly_the_offset_byte_from_an_unaligned_object() {
        let mut storage = [GUARD; OFFSET + 3];
        let object = unsafe { storage.as_mut_ptr().add(1) };
        unsafe { object.add(OFFSET).write(0x3c) };
        let before = storage;

        assert_eq!(unsafe { object_byte_at_94(object) }, 0x3c);
        assert_eq!(storage, before, "the accessor must not mutate its object");
        assert_eq!(storage[OFFSET], GUARD, "byte before the field");
        assert_eq!(storage[OFFSET + 2], GUARD, "byte after the field");
    }
}
