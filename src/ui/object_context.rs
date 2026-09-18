//! `object_set_context` — original: `thunk_FUN_08214368` @ `0x0820a4bc`
//! (4 bytes, `0x0820a4bc..0x0820a4bf`; the next independently linked function
//! begins at `0x0820a4c0` with `push {r4,r5,lr}`).
//!
//! Raw ARM is the single tail branch `b 0x0822b060`; that target tail-branches
//! to `0x08214368`, whose `str r1,[r0,#0x20]; bx lr` stores the context word.
//! A whole-image raw A32 branch decode finds four direct, unconditional `bl`
//! callers of this veneer and no predicated `bl` callers. The setter writes an
//! unchecked target-width context word at object offset `+0x20`.
//!
//! Deliberate deviation: Rust collapses the two tail veneers into their verified
//! store operation, rather than inventing identities for the veneer targets.

/// Stores a target-width caller context word in an opaque object.
///
/// # Safety
///
/// `object` must point to writable storage through offset `+0x23`, aligned for
/// a `u32`; as in retailOS, neither argument is validated.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn object_set_context(object: *mut u8, context: u32) {
    (object.add(0x20) as *mut u32).write(context);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    struct Object {
        prefix: [u32; 8],
        context: u32,
        suffix: [u32; 3],
    }

    #[test]
    fn overwrites_only_the_context_word() {
        let mut object = Object {
            prefix: [0x1111_1111; 8],
            context: 0x2222_2222,
            suffix: [0x3333_3333; 3],
        };

        unsafe { object_set_context(core::ptr::addr_of_mut!(object).cast(), 0xa5a5_5a5a) };

        assert_eq!(object.prefix, [0x1111_1111; 8]);
        assert_eq!(object.context, 0xa5a5_5a5a);
        assert_eq!(object.suffix, [0x3333_3333; 3]);
    }

    #[test]
    fn preserves_zero_and_all_one_context_words() {
        let mut object = Object {
            prefix: [0; 8],
            context: 0xfeed_face,
            suffix: [0; 3],
        };

        for context in [0, u32::MAX] {
            unsafe { object_set_context(core::ptr::addr_of_mut!(object).cast(), context) };
            assert_eq!(object.context, context);
        }
    }
}
