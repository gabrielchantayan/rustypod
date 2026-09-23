//! `parse_result_scope_construct` — original: `FUN_081d5e2c` @ 0x081d5e2c
//! (40 bytes, 0x081d5e2c..0x081d5e53; **3 inbound plain `bl` call sites,
//! 0 predicated `bl` call sites**).
//!
//! Raw ARM establishes the extent and algorithm: `push {r4,lr}; add r0,r0,#0x20;
//! bl 0x083b45ec; mov r3,#0; mov r2,#0; mov r1,#0; add r0,r0,#0x14;
//! bl 0x08283168; sub r0,r0,#0x34; pop {r4,pc}`. It zeroes the two-word
//! member at +0x20, initializes the embedded parser result at +0x34 to
//! `{ status: 0, code: 0, detail: 0 }`, and returns the enclosing scope.
//!
//! Deliberate deviations: none. The pointer values flow through both calls
//! exactly as they do through ARM r0.

use crate::app::parse_result::parse_result_init;
use crate::cxx::two_word_clear_alt::two_word_clear_alt;

/// Initializes the 0x38-byte parser scope's two-word member at +0x20 and
/// parser-result member at +0x34, returning `scope`.
///
/// # Safety
///
/// `scope` must point to writable storage covering offsets `0x20..0x38`, with
/// 4-byte alignment for the two-word member and 2-byte alignment for the
/// parser-result detail field. Stock code has no NULL guard.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn parse_result_scope_construct(scope: *mut u8) -> *mut u8 {
    const CLEAR_OFFSET: usize = 0x20;
    const RESULT_OFFSET: usize = 0x34;

    let result = two_word_clear_alt(scope.add(CLEAR_OFFSET).cast())
        .cast::<u8>()
        .add(RESULT_OFFSET - CLEAR_OFFSET);
    parse_result_init(result, 0, 0, 0).sub(RESULT_OFFSET)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initializes_only_the_two_embedded_members() {
        let mut scope = [0xa5u8; 0x3c];
        let returned = unsafe { parse_result_scope_construct(scope.as_mut_ptr()) };

        assert_eq!(returned, scope.as_mut_ptr());
        assert_eq!(&scope[..0x20], &[0xa5; 0x20]);
        assert_eq!(&scope[0x20..0x28], &[0; 8]);
        assert_eq!(&scope[0x28..0x34], &[0xa5; 12]);
        assert_eq!(&scope[0x34..0x38], &[0; 4]);
        assert_eq!(&scope[0x38..], &[0xa5; 4]);
    }

    #[test]
    fn overwrites_previously_initialized_members() {
        let mut scope = [0u8; 0x38];
        scope[0x20..0x28].fill(0x11);
        scope[0x34..0x38].fill(0x22);

        unsafe { parse_result_scope_construct(scope.as_mut_ptr()) };

        assert_eq!(&scope[0x20..0x28], &[0; 8]);
        assert_eq!(&scope[0x34..0x38], &[0; 4]);
    }
}
