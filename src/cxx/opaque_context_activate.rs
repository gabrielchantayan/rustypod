//! `opaque_context_activate` — veneer `thunk_FUN_082e7f78` @ 0x08262914
//! (4 bytes, branching to 0x082e7f78).
//!
//! # Extent and calls, binary-verified
//!
//! The sole veneer word is `0xea021597` (`b 0x082e7f78`); the next veneer
//! begins at 0x08262918, so it has no literal pool. Its target body spans
//! 0x082e7f78..0x082e7ff4 (128 bytes) through `pop {r4, pc}`; the following
//! word is the `0x434e4453` literal and 0x082e7ff8 starts the next function.
//! Whole-image ARM immediate decoding finds four unconditional `bl` callers
//! of the veneer and no predicated `bl` callers. The target contains four
//! unconditional `bl` instructions and no predicated calls.
//!
//! # Algorithm
//!
//! A NULL context returns `0x1a`. Otherwise, a context whose first word is
//! not `0x434e4453` is initialized with a NULL selector; an initialization
//! error returns immediately. A non-NULL child at word index 2 supplies its
//! word at +0x20 when the third ABI argument is zero. If both the child and
//! resulting selector are non-NULL, the routine copies four words from that
//! selector, advances the child through its opaque operation, then validates
//! the copied first word through another opaque operation.
//!
//! # Deliberate deviations
//!
//! The initializer and the two opaque operations are not identified. Target
//! builds call their verified retailOS addresses indirectly; host tests use
//! replaceable seams. The known four-word copy is inlined rather than calling
//! `FUN_083da458`.

use core::ptr;

const CONTEXT_MAGIC: u32 = 0x434e_4453;
const RETAIL_CONTEXT_INITIALIZE: usize = 0x082e_7e54;
const RETAIL_CHILD_ADVANCE: usize = 0x083d_fdec;
const RETAIL_WORD_VALIDATE: usize = 0x0808_60c0;

#[derive(Clone, Copy)]
pub struct OpaqueContextActivateOps {
    pub initialize: unsafe extern "C" fn(*mut u32, *const u32) -> u32,
    pub child_advance: unsafe extern "C" fn(*mut u32),
    pub word_validate: unsafe extern "C" fn(*const u32) -> u32,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_initialize(_: *mut u32, _: *const u32) -> u32 { 0 }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_child_advance(_: *mut u32) {}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_word_validate(_: *const u32) -> u32 { 0 }

#[cfg(not(target_os = "none"))]
pub static mut OPAQUE_CONTEXT_ACTIVATE_OPS: OpaqueContextActivateOps = OpaqueContextActivateOps {
    initialize: missing_initialize,
    child_advance: missing_child_advance,
    word_validate: missing_word_validate,
};

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn context_initialize(context: *mut u32) -> u32 {
    let call: unsafe extern "C" fn(*mut u32, *const u32) -> u32 = core::mem::transmute(RETAIL_CONTEXT_INITIALIZE);
    call(context, ptr::null())
}
#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn context_initialize(context: *mut u32) -> u32 {
    (ptr::read_volatile(ptr::addr_of!(OPAQUE_CONTEXT_ACTIVATE_OPS.initialize)))(context, ptr::null())
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn child_advance(child: *mut u32) {
    let call: unsafe extern "C" fn(*mut u32) = core::mem::transmute(RETAIL_CHILD_ADVANCE);
    call(child)
}
#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn child_advance(child: *mut u32) {
    (ptr::read_volatile(ptr::addr_of!(OPAQUE_CONTEXT_ACTIVATE_OPS.child_advance)))(child)
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn word_validate(word: *const u32) -> u32 {
    let call: unsafe extern "C" fn(*const u32) -> u32 = core::mem::transmute(RETAIL_WORD_VALIDATE);
    call(word)
}
#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn word_validate(word: *const u32) -> u32 {
    (ptr::read_volatile(ptr::addr_of!(OPAQUE_CONTEXT_ACTIVATE_OPS.word_validate)))(word)
}

/// Replacement for the veneer at **0x08262914**, which branches to the
/// 128-byte body at 0x082e7f78. `selector_or_child` is the observed r2 ABI
/// argument; retailOS substitutes `child[8]` only when it is zero.
///
/// # Safety
/// `context` must be NULL or point to at least three aligned u32 words. When
/// its child and selected pointer are non-NULL, both must satisfy their opaque
/// retailOS operation contracts.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn opaque_context_activate(
    context: *mut u32,
    _unused: u32,
    mut selector_or_child: u32,
) -> u32 {
    if context.is_null() { return 0x1a; }
    if ptr::read(context) != CONTEXT_MAGIC {
        let status = context_initialize(context);
        if status != 0 { return status; }
    }
    let child = ptr::read(context.add(2));
    if child != 0 && selector_or_child == 0 {
        selector_or_child = ptr::read((child as *const u32).add(8));
    }
    if child == 0 || selector_or_child == 0 { return 0; }

    let selected = selector_or_child as *const u32;
    let mut word = ptr::read(selected);
    child_advance(child as *mut u32);
    word_validate(ptr::addr_of!(word))
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut INITIALIZE_STATUS: u32 = 0;
    static mut INITIALIZE_CALLS: usize = 0;
    static mut ADVANCE_CALLS: usize = 0;
    static mut VALIDATE_WORD: u32 = 0;

    unsafe extern "C" fn initialize(_: *mut u32, selector: *const u32) -> u32 {
        assert!(selector.is_null()); INITIALIZE_CALLS += 1; INITIALIZE_STATUS
    }
    unsafe extern "C" fn advance(_: *mut u32) { ADVANCE_CALLS += 1; }
    unsafe extern "C" fn validate(word: *const u32) -> u32 { VALIDATE_WORD = ptr::read(word); 0x27 }

    #[test]
    fn null_context_returns_invalid_argument_without_calls() {
        let _guard = OPS_LOCK.lock();
        assert_eq!(unsafe { opaque_context_activate(ptr::null_mut(), 0, 0) }, 0x1a);
    }

    #[test]
    fn initializer_error_returns_before_child_access() {
        let _guard = OPS_LOCK.lock();
        unsafe {
            let saved = OPAQUE_CONTEXT_ACTIVATE_OPS;
            OPAQUE_CONTEXT_ACTIVATE_OPS = OpaqueContextActivateOps { initialize, child_advance: advance, word_validate: validate };
            INITIALIZE_STATUS = 0x42; INITIALIZE_CALLS = 0; ADVANCE_CALLS = 0;
            let mut context = [0; 3];
            assert_eq!(opaque_context_activate(context.as_mut_ptr(), 0, 0), 0x42);
            assert_eq!(INITIALIZE_CALLS, 1); assert_eq!(ADVANCE_CALLS, 0);
            OPAQUE_CONTEXT_ACTIVATE_OPS = saved;
        }
    }

    #[test]
    fn child_default_selector_is_copied_before_opaque_calls() {
        let _guard = OPS_LOCK.lock();
        unsafe {
            let saved = OPAQUE_CONTEXT_ACTIVATE_OPS;
            OPAQUE_CONTEXT_ACTIVATE_OPS = OpaqueContextActivateOps { initialize, child_advance: advance, word_validate: validate };
            INITIALIZE_STATUS = 0; INITIALIZE_CALLS = 0; ADVANCE_CALLS = 0; VALIDATE_WORD = 0;
            let Some(base) = try_map_u32_slab(hints::OPAQUE_CONTEXT_ACTIVATE, 0x1000) else {
                assert!(note_missing_u32_fixture("cxx/opaque_context_activate"));
                OPAQUE_CONTEXT_ACTIVATE_OPS = saved;
                return;
            };
            base.write_bytes(0, 0x1000);
            let selected = base.cast::<u32>();
            let child = selected.add(16);
            let context = selected.add(32);
            selected.write(0xdead_beef);
            child.add(8).write(selected as usize as u32);
            context.write(CONTEXT_MAGIC);
            context.add(2).write(child as usize as u32);
            assert_eq!(opaque_context_activate(context, 0, 0), 0x27);
            assert_eq!(INITIALIZE_CALLS, 0); assert_eq!(ADVANCE_CALLS, 1); assert_eq!(VALIDATE_WORD, 0xdead_beef);
            OPAQUE_CONTEXT_ACTIVATE_OPS = saved;
        }
    }
}
