//! `byte_flag_at_d_is_one` — original: `FUN_0813af44` @ 0x0813af44
//! (20 bytes).
//!
//! Loads byte `+0x0d` from an opaque application object and returns one exactly
//! when it equals one; every other byte value returns zero. The two recovered
//! direct callers poll this predicate on subobjects, but establish neither the
//! containing object's type nor a semantic field name, so this port preserves
//! the conservative offset-based name.
//!
//! Sources: `ipod-decomp/decomp/c/012/0813af44_FUN_0813af44.c`, the
//! `ldrb r0, [r0, #0xd]; cmp r0, #1; movne/moveq; bx lr` sequence at
//! 0x0813af44 in `ipod-decomp/decomp/osos.asm`, and direct callers
//! `FUN_080f87ac` @ 0x080f87ac and `FUN_080fca98` @ 0x080fca98.
//!
//! Deviation: none.

/// Returns one exactly when byte `+0x0d` of an opaque object equals one.
///
/// # Safety
///
/// `object` must point into a readable allocation that includes byte `+0x0d`.
/// The pointer may be unaligned because the retail routine performs a byte
/// load.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn byte_flag_at_d_is_one(object: *const u8) -> u32 {
    (object.add(0x0d).read() == 1) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    const FLAG: usize = 0x0d;
    const GUARD: u8 = 0xa5;

    #[test]
    fn only_byte_value_one_is_true() {
        let mut object = [GUARD; FLAG + 2];

        for (flag, expected) in [(0u8, 0), (1, 1), (2, 0), (u8::MAX, 0)] {
            object[FLAG] = flag;
            assert_eq!(
                unsafe { byte_flag_at_d_is_one(object.as_ptr()) },
                expected,
                "byte={flag:#04x}"
            );
        }
    }

    #[test]
    fn reads_only_the_flag_byte_without_mutating_surrounding_guards() {
        let mut object = [GUARD; FLAG + 2];
        object[FLAG - 1] = 0x3c;
        object[FLAG] = 1;
        object[FLAG + 1] = 0xc3;
        let before = object;

        assert_eq!(unsafe { byte_flag_at_d_is_one(object.as_ptr()) }, 1);
        assert_eq!(object, before, "a predicate must not mutate its object");
        assert_eq!(object[FLAG - 1], 0x3c, "byte before +0x0d");
        assert_eq!(object[FLAG + 1], 0xc3, "byte after +0x0d");
    }

    #[test]
    fn reads_the_shared_object_through_an_alias_without_mutation() {
        let mut object = [GUARD; FLAG + 2];
        let object_base = object.as_mut_ptr();
        let flag_alias = unsafe { object_base.add(FLAG) };
        unsafe { flag_alias.write(1) };
        let before = object;

        assert_eq!(unsafe { byte_flag_at_d_is_one(object_base) }, 1);
        assert_eq!(object, before, "the aliased object was only read");
    }
}
