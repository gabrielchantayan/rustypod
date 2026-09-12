//! `validate_and_dispatch_tagged_context` — original:
//! `thunk_FUN_082e8070` @ **0x0826290c** (4-byte veneer).
//!
//! # Extent and calls, binary-verified
//!
//! The veneer is the one word `ea0215d7` (`b 0x082e8070`). Its immediately
//! following siblings are distinct veneers at 0x08262910, 0x08262914, and
//! 0x08262918, so the reported four-byte extent is exact and there is no
//! literal-pool word. The branch target starts with `push {r4,r5,r6,lr}` at
//! 0x082e8070 and its separately linked sibling starts at 0x082e80dc. Thus
//! the actual body is 108 bytes, not Ghidra's erroneous 568-byte extent.
//!
//! Decoding every ARM `B`/`BL` immediate in `osos.dec` finds exactly eight
//! callers of the veneer: 0x0818a518, 0x082618cc, 0x08261a40, 0x082625b0,
//! 0x08262a10, 0x0839e950, 0x0839eabc, and 0x0839f498. All eight are
//! unconditional `bl`; there are no predicated forms, tail `b` callers, or
//! data words equal to 0x0826290c.
//!
//! # Algorithm
//!
//! Reject a NULL context, NULL tagged input, or an input whose first word is
//! not 0x4d55_5458, returning 0x1a. If the context's first word is
//! 0x434e_4453, initialize it with a NULL selector and return a nonzero
//! initializer status immediately. Otherwise tail-dispatch the context and
//! tagged input to 0x080c96d8 with a NULL third argument. The actual object
//! types and the terminal dispatcher's identity are unrecovered, so this port
//! deliberately names only the verified validation and dispatch behavior.
//!
//! # Deliberate deviation
//!
//! Both callees are unported. Target builds call their fixed retailOS
//! addresses; host tests install seams. The original uses direct `bl` for the
//! initializer and a tail `b` for the terminal dispatcher, while the port
//! expresses both as calls and propagates their result unchanged.

use core::ptr;

const TAGGED_INPUT_MAGIC: u32 = 0x4d55_5458;
const CONTEXT_MAGIC: u32 = 0x434e_4453;
const INVALID_TAGGED_CONTEXT: u32 = 0x1a;
const RETAIL_OPAQUE_CONTEXT_INITIALIZE: usize = 0x082e_7e54;
const RETAIL_TAGGED_CONTEXT_DISPATCH: usize = 0x080c_96d8;

type OpaqueContextInitialize = unsafe extern "C" fn(*mut u32, *const u32) -> u32;
type TaggedContextDispatch = unsafe extern "C" fn(*mut u32, *mut u32, *const u32) -> u32;

#[derive(Clone, Copy)]
pub struct TaggedContextDispatchOps {
    pub initialize: OpaqueContextInitialize,
    pub dispatch: TaggedContextDispatch,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_opaque_context_initialize(
    _context: *mut u32,
    _selector: *const u32,
) -> u32 {
    0
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_tagged_context_dispatch(
    _context: *mut u32,
    _tagged_input: *mut u32,
    _selector: *const u32,
) -> u32 {
    0
}

/// Host boundaries for the two unported retailOS calls. Target builds call
/// their fixed addresses directly.
#[cfg(not(target_os = "none"))]
pub static mut TAGGED_CONTEXT_DISPATCH_OPS: TaggedContextDispatchOps = TaggedContextDispatchOps {
    initialize: missing_opaque_context_initialize,
    dispatch: missing_tagged_context_dispatch,
};

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn opaque_context_initialize(context: *mut u32, selector: *const u32) -> u32 {
    let initialize: OpaqueContextInitialize = core::mem::transmute(RETAIL_OPAQUE_CONTEXT_INITIALIZE);
    initialize(context, selector)
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn opaque_context_initialize(context: *mut u32, selector: *const u32) -> u32 {
    let initialize = ptr::read_volatile(ptr::addr_of!(TAGGED_CONTEXT_DISPATCH_OPS.initialize));
    initialize(context, selector)
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn tagged_context_dispatch(
    context: *mut u32,
    tagged_input: *mut u32,
    selector: *const u32,
) -> u32 {
    let dispatch: TaggedContextDispatch = core::mem::transmute(RETAIL_TAGGED_CONTEXT_DISPATCH);
    dispatch(context, tagged_input, selector)
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn tagged_context_dispatch(
    context: *mut u32,
    tagged_input: *mut u32,
    selector: *const u32,
) -> u32 {
    let dispatch = ptr::read_volatile(ptr::addr_of!(TAGGED_CONTEXT_DISPATCH_OPS.dispatch));
    dispatch(context, tagged_input, selector)
}

/// `validate_and_dispatch_tagged_context` — original:
/// `thunk_FUN_082e8070` @ **0x0826290c** (4-byte veneer; eight unconditional
/// direct `bl` call sites, no predicated forms).
///
/// Validates the first words of `context` and `tagged_input`, conditionally
/// initializes a context marked `CONTEXT_MAGIC`, then dispatches the pair with
/// a NULL selector. Returns validation status, initializer status, or the
/// terminal dispatcher's result unchanged.
///
/// # Safety
///
/// When non-NULL, `context` and `tagged_input` must each point to at least one
/// readable, properly aligned `u32`. The installed unported operations must
/// accept these pointers and the NULL selector according to retailOS's opaque
/// contracts.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn validate_and_dispatch_tagged_context(
    context: *mut u32,
    tagged_input: *mut u32,
) -> u32 {
    if context.is_null() || tagged_input.is_null() || tagged_input.read() != TAGGED_INPUT_MAGIC {
        return INVALID_TAGGED_CONTEXT;
    }

    if context.read() == CONTEXT_MAGIC {
        let status = opaque_context_initialize(context, ptr::null());
        if status != 0 {
            return status;
        }
    }

    tagged_context_dispatch(context, tagged_input, ptr::null())
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::Mutex;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut INITIALIZE_CALLS: usize = 0;
    static mut DISPATCH_CALLS: usize = 0;
    static mut SEEN_CONTEXT: *mut u32 = ptr::null_mut();
    static mut SEEN_INPUT: *mut u32 = ptr::null_mut();
    static mut SEEN_INITIALIZE_SELECTOR: *const u32 = ptr::null();
    static mut SEEN_DISPATCH_SELECTOR: *const u32 = ptr::null();
    static mut INITIALIZE_STATUS: u32 = 0;
    static mut DISPATCH_STATUS: u32 = 0;

    struct OpsRestore;

    impl Drop for OpsRestore {
        fn drop(&mut self) {
            unsafe {
                TAGGED_CONTEXT_DISPATCH_OPS = TaggedContextDispatchOps {
                    initialize: missing_opaque_context_initialize,
                    dispatch: missing_tagged_context_dispatch,
                };
            }
        }
    }

    unsafe extern "C" fn recording_initialize(context: *mut u32, selector: *const u32) -> u32 {
        unsafe {
            INITIALIZE_CALLS += 1;
            SEEN_CONTEXT = context;
            SEEN_INITIALIZE_SELECTOR = selector;
            INITIALIZE_STATUS
        }
    }

    unsafe extern "C" fn recording_dispatch(
        context: *mut u32,
        tagged_input: *mut u32,
        selector: *const u32,
    ) -> u32 {
        unsafe {
            DISPATCH_CALLS += 1;
            SEEN_CONTEXT = context;
            SEEN_INPUT = tagged_input;
            SEEN_DISPATCH_SELECTOR = selector;
            DISPATCH_STATUS
        }
    }

    fn install_recorders(
        initialize_status: u32,
        dispatch_status: u32,
    ) -> (parking_lot::MutexGuard<'static, ()>, OpsRestore) {
        let guard = OPS_LOCK.lock();
        unsafe {
            INITIALIZE_CALLS = 0;
            DISPATCH_CALLS = 0;
            SEEN_CONTEXT = ptr::null_mut();
            SEEN_INPUT = ptr::null_mut();
            SEEN_INITIALIZE_SELECTOR = ptr::null();
            SEEN_DISPATCH_SELECTOR = ptr::null();
            INITIALIZE_STATUS = initialize_status;
            DISPATCH_STATUS = dispatch_status;
            TAGGED_CONTEXT_DISPATCH_OPS = TaggedContextDispatchOps {
                initialize: recording_initialize,
                dispatch: recording_dispatch,
            };
        }
        (guard, OpsRestore)
    }

    #[test]
    fn null_context_returns_invalid_without_reading_the_tagged_input() {
        let (_guard, _restore) = install_recorders(0, 0);
        let mut invalid_input = 0;

        let result = unsafe {
            validate_and_dispatch_tagged_context(ptr::null_mut(), &mut invalid_input)
        };

        assert_eq!(result, INVALID_TAGGED_CONTEXT);
        assert_eq!(unsafe { INITIALIZE_CALLS }, 0);
        assert_eq!(unsafe { DISPATCH_CALLS }, 0);
    }

    #[test]
    fn null_or_wrong_magic_input_returns_invalid_without_calling_seams() {
        let (_guard, _restore) = install_recorders(0, 0);
        let mut context = CONTEXT_MAGIC;
        let mut wrong_input = TAGGED_INPUT_MAGIC ^ 1;

        let null_result = unsafe {
            validate_and_dispatch_tagged_context(&mut context, ptr::null_mut())
        };
        let wrong_magic_result = unsafe {
            validate_and_dispatch_tagged_context(&mut context, &mut wrong_input)
        };

        assert_eq!(null_result, INVALID_TAGGED_CONTEXT);
        assert_eq!(wrong_magic_result, INVALID_TAGGED_CONTEXT);
        assert_eq!(unsafe { INITIALIZE_CALLS }, 0);
        assert_eq!(unsafe { DISPATCH_CALLS }, 0);
    }

    #[test]
    fn context_initializer_error_bypasses_terminal_dispatch() {
        let (_guard, _restore) = install_recorders(0x40, 0xdead_beef);
        let mut context = CONTEXT_MAGIC;
        let mut tagged_input = TAGGED_INPUT_MAGIC;
        let context_ptr = ptr::addr_of_mut!(context);
        let tagged_input_ptr = ptr::addr_of_mut!(tagged_input);

        let result = unsafe {
            validate_and_dispatch_tagged_context(context_ptr, tagged_input_ptr)
        };

        assert_eq!(result, 0x40);
        assert_eq!(unsafe { INITIALIZE_CALLS }, 1);
        assert_eq!(unsafe { SEEN_CONTEXT }, context_ptr);
        assert_eq!(unsafe { SEEN_INITIALIZE_SELECTOR }, ptr::null());
        assert_eq!(unsafe { DISPATCH_CALLS }, 0);
    }

    #[test]
    fn initialized_context_dispatches_with_original_arguments_and_null_selector() {
        let (_guard, _restore) = install_recorders(0, 0x5a);
        let mut context = CONTEXT_MAGIC;
        let mut tagged_input = TAGGED_INPUT_MAGIC;
        let context_ptr = ptr::addr_of_mut!(context);
        let tagged_input_ptr = ptr::addr_of_mut!(tagged_input);

        let result = unsafe {
            validate_and_dispatch_tagged_context(context_ptr, tagged_input_ptr)
        };

        assert_eq!(result, 0x5a);
        assert_eq!(unsafe { INITIALIZE_CALLS }, 1);
        assert_eq!(unsafe { DISPATCH_CALLS }, 1);
        assert_eq!(unsafe { SEEN_CONTEXT }, context_ptr);
        assert_eq!(unsafe { SEEN_INPUT }, tagged_input_ptr);
        assert_eq!(unsafe { SEEN_INITIALIZE_SELECTOR }, ptr::null());
        assert_eq!(unsafe { SEEN_DISPATCH_SELECTOR }, ptr::null());
    }

    #[test]
    fn nonmatching_context_magic_skips_initialization_but_dispatches() {
        let (_guard, _restore) = install_recorders(0x40, 0x77);
        let mut context = CONTEXT_MAGIC ^ 1;
        let mut tagged_input = TAGGED_INPUT_MAGIC;

        let result = unsafe {
            validate_and_dispatch_tagged_context(&mut context, &mut tagged_input)
        };

        assert_eq!(result, 0x77);
        assert_eq!(unsafe { INITIALIZE_CALLS }, 0);
        assert_eq!(unsafe { DISPATCH_CALLS }, 1);
    }
}
