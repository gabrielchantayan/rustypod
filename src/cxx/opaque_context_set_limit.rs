//! `set_opaque_context_limit` — original: `thunk_FUN_082e7d18` @ 0x08261d7c
//! (four-byte veneer to `FUN_082e7d18` @ 0x082e7d18; 48-byte target body).
//!
//! # Extent and calls, binary-verified
//!
//! The assigned veneer is exactly `0xea0217e5`, `b 0x082e7d18`; its next
//! separately linked veneer begins at 0x08261d80. The target is 48 bytes:
//! instructions span 0x082e7d18..0x082e7d44, followed by the `0x41485450`
//! magic literal at 0x082e7d48 and the next function's prologue at 0x082e7d4c.
//! Whole-image ARM branch decoding finds four plain unconditional `bl` callers
//! (0x08262894, 0x0839e8f4, 0x0839ea60, 0x0839f43c) and zero predicated calls.
//!
//! # Algorithm
//!
//! Reject a NULL context, a context without its verified magic word, or an
//! unsigned limit below 0x800 with status 0x1a. Otherwise store the limit at
//! word index four and return zero. The concrete context type is unrecovered,
//! so this names only its observed limit field.
//!
//! # Deliberate deviation
//!
//! Rust returns from the target body instead of preserving the retail veneer
//! branch. The comparisons, status values, and target-width word index match.

const OPAQUE_CONTEXT_MAGIC: u32 = 0x4148_5450;
const MINIMUM_LIMIT: u32 = 0x800;
const INVALID_CONTEXT_STATUS: u32 = 0x1a;
const LIMIT_WORD_INDEX: usize = 4;

/// Sets an opaque context's limit when its header and minimum limit validate.
///
/// # Safety
///
/// When non-NULL, `context` must point to at least five aligned `u32` words.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn set_opaque_context_limit(context: *mut u32, limit: u32) -> u32 {
    if context.is_null() || *context != OPAQUE_CONTEXT_MAGIC || limit < MINIMUM_LIMIT {
        return INVALID_CONTEXT_STATUS;
    }

    *context.add(LIMIT_WORD_INDEX) = limit;
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_null_context() {
        assert_eq!(unsafe { set_opaque_context_limit(core::ptr::null_mut(), 0x800) }, 0x1a);
    }

    #[test]
    fn rejects_bad_magic_and_preserves_context() {
        let mut context = [0xdead_beef, 1, 2, 3, 0xaaaa_aaaa];
        assert_eq!(unsafe { set_opaque_context_limit(context.as_mut_ptr(), u32::MAX) }, 0x1a);
        assert_eq!(context[4], 0xaaaa_aaaa);
    }

    #[test]
    fn enforces_unsigned_minimum_limit() {
        let mut context = [OPAQUE_CONTEXT_MAGIC, 1, 2, 3, 0xaaaa_aaaa];
        for limit in [0, 0x7ff] {
            assert_eq!(unsafe { set_opaque_context_limit(context.as_mut_ptr(), limit) }, 0x1a);
            assert_eq!(context[4], 0xaaaa_aaaa);
        }
        assert_eq!(unsafe { set_opaque_context_limit(context.as_mut_ptr(), 0x800) }, 0);
        assert_eq!(context[4], 0x800);
    }

    #[test]
    fn stores_large_valid_limit_at_word_four() {
        let mut context = [OPAQUE_CONTEXT_MAGIC, 1, 2, 3, 0xaaaa_aaaa, 0xbbbb_bbbb];
        assert_eq!(unsafe { set_opaque_context_limit(context.as_mut_ptr(), u32::MAX) }, 0);
        assert_eq!(context[4], u32::MAX);
        assert_eq!(context[5], 0xbbbb_bbbb);
    }
}
