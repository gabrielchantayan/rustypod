//! `initialize_opaque_context` — original: `FUN_0826291c` @ 0x0826291c
//! (40 bytes).
//!
//! # Extent and calls, binary-verified
//!
//! Raw `osos.dec` words run from the `push` at 0x0826291c through the
//! `pop {r4, pc}` at 0x08262940; the next separately linked function starts
//! at 0x08262944, so Ghidra's 40-byte extent is exact and has no literal pool:
//!
//! ```text
//! 0826291c  push {r4, lr}
//! 08262920  mov  r4, r0
//! 08262924  mov  r0, #0
//! 08262928  str  r0, [r4, #0x18]
//! 0826292c  mov  r0, r4
//! 08262930  mov  r1, #0
//! 08262934  bl   0x082e7e54
//! 08262938  str  r0, [r4, #0x18]
//! 0826293c  mov  r0, r4
//! 08262940  pop  {r4, pc}
//! ```
//!
//! Decoding every ARM `B`/`BL` immediate in `osos.dec` finds exactly nine
//! call sites, at 0x0818a298, 0x0818b3c4, 0x081d6990, 0x081d7d34,
//! 0x08261b64, 0x08261b80, 0x08262868, 0x08262a54, and 0x08262a70. All nine
//! are unconditional `bl`; there are no predicated calls or tail `b` calls.
//!
//! # Algorithm
//!
//! This clears the opaque context's status word (word index 6, byte +0x18),
//! initializes the context through `FUN_082e7e54` with its optional second
//! argument set to NULL, stores that operation's result in the same status
//! word, and returns the original context pointer. The concrete context type
//! and the callee's semantic identity are not recovered, so neither is
//! invented here.
//!
//! # Deliberate deviation
//!
//! `FUN_082e7e54` is not ported. Target builds call its fixed retailOS address
//! indirectly; host tests use an injectable seam. This changes the one direct
//! `bl` to an indirect `blx`, while preserving the exact argument order,
//! clear-before-call ordering, returned status, and original-pointer return.

use core::ptr;

/// Fixed retailOS address of the unported opaque-context initializer,
/// `FUN_082e7e54`.
const RETAIL_OPAQUE_CONTEXT_INITIALIZE: usize = 0x082e_7e54;

/// Host boundary for the unported opaque-context initializer. The second
/// argument is an optional context selector; this caller always supplies
/// NULL.
#[derive(Clone, Copy)]
pub struct OpaqueContextInitializeOps {
    pub initialize: unsafe extern "C" fn(context: *mut u32, selector: *const u32) -> u32,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_opaque_context_initialize(
    _context: *mut u32,
    _selector: *const u32,
) -> u32 {
    0
}

/// Host seam for `FUN_082e7e54`. Tests replace this with a recorder; target
/// builds instead call the original retailOS address directly.
#[cfg(not(target_os = "none"))]
pub static mut OPAQUE_CONTEXT_INITIALIZE_OPS: OpaqueContextInitializeOps =
    OpaqueContextInitializeOps {
        initialize: missing_opaque_context_initialize,
    };

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn opaque_context_initialize(context: *mut u32, selector: *const u32) -> u32 {
    let initialize: unsafe extern "C" fn(*mut u32, *const u32) -> u32 =
        core::mem::transmute(RETAIL_OPAQUE_CONTEXT_INITIALIZE);
    initialize(context, selector)
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn opaque_context_initialize(context: *mut u32, selector: *const u32) -> u32 {
    let initialize = ptr::read_volatile(ptr::addr_of!(OPAQUE_CONTEXT_INITIALIZE_OPS.initialize));
    initialize(context, selector)
}

/// `initialize_opaque_context` — original: `FUN_0826291c` @ **0x0826291c**
/// (40 bytes; 9 unconditional direct `bl` call sites, no predicated forms).
///
/// Clears then fills the opaque context's u32 status word at index 6 from the
/// default (`NULL` selector) opaque-context initializer. Returns `context`,
/// not the initializer's status; neither the pointer nor its returned status
/// is NULL- or error-checked by retailOS.
///
/// # Safety
///
/// `context` must point to at least seven writable, properly aligned u32
/// words, and the installed initializer must satisfy the retailOS contract for
/// the whole opaque context.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn initialize_opaque_context(context: *mut u32) -> *mut u32 {
    context.add(6).write(0);
    let status = opaque_context_initialize(context, ptr::null());
    context.add(6).write(status);
    context
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::Mutex;

    static OPS_LOCK: Mutex<()> = Mutex::new(());

    struct OpsRestore;

    impl Drop for OpsRestore {
        fn drop(&mut self) {
            unsafe {
                OPAQUE_CONTEXT_INITIALIZE_OPS = OpaqueContextInitializeOps {
                    initialize: missing_opaque_context_initialize,
                };
            }
        }
    }

    static mut CALL_COUNT: usize = 0;
    static mut SEEN_CONTEXT: *mut u32 = ptr::null_mut();
    static mut SEEN_SELECTOR: *const u32 = ptr::null();
    static mut STATUS_AT_CALL: u32 = u32::MAX;
    static mut RETURN_STATUS: u32 = 0;

    unsafe extern "C" fn recording_initialize(context: *mut u32, selector: *const u32) -> u32 {
        unsafe {
            CALL_COUNT += 1;
            SEEN_CONTEXT = context;
            SEEN_SELECTOR = selector;
            STATUS_AT_CALL = context.add(6).read();
            RETURN_STATUS
        }
    }

    fn install_recorder(return_status: u32) -> (parking_lot::MutexGuard<'static, ()>, OpsRestore) {
        let guard = OPS_LOCK.lock();
        unsafe {
            CALL_COUNT = 0;
            SEEN_CONTEXT = ptr::null_mut();
            SEEN_SELECTOR = ptr::null();
            STATUS_AT_CALL = u32::MAX;
            RETURN_STATUS = return_status;
            OPAQUE_CONTEXT_INITIALIZE_OPS = OpaqueContextInitializeOps {
                initialize: recording_initialize,
            };
        }
        (guard, OpsRestore)
    }

    #[test]
    fn clears_status_before_default_initialization_then_records_result() {
        let (_guard, _restore) = install_recorder(0x1a);
        let mut context = [0xa5a5_a5a5u32; 11];

        let returned = unsafe { initialize_opaque_context(context.as_mut_ptr()) };

        assert_eq!(returned, context.as_mut_ptr(), "r4 restores the original r0");
        assert_eq!(unsafe { CALL_COUNT }, 1, "exactly one bl");
        assert_eq!(unsafe { SEEN_CONTEXT }, context.as_mut_ptr());
        assert_eq!(unsafe { SEEN_SELECTOR }, ptr::null(), "mov r1, #0");
        assert_eq!(unsafe { STATUS_AT_CALL }, 0, "first str [r4, #0x18]");
        assert_eq!(context[6], 0x1a, "second str stores the returned status");
        assert_eq!(context[..6], [0xa5a5_a5a5; 6]);
        assert_eq!(context[7..], [0xa5a5_a5a5; 4]);
    }

    #[test]
    fn stores_success_status_even_when_the_word_started_nonzero() {
        let (_guard, _restore) = install_recorder(0);
        let mut context = [0u32; 7];
        context[6] = 0xffff_ffff;

        let returned = unsafe { initialize_opaque_context(context.as_mut_ptr()) };

        assert_eq!(returned, context.as_mut_ptr());
        assert_eq!(unsafe { STATUS_AT_CALL }, 0, "the old error cannot reach the callee");
        assert_eq!(context[6], 0, "status zero is stored without an error branch");
    }
}
