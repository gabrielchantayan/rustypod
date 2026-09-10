//! Tdat UI-element message dispatch.
//!
//! - `tdat_dispatch_message` — original: `FUN_080442a0` @ `0x080442a0`
//!   (52 bytes; 11 direct `bl` call sites, all unconditional, plus one
//!   `beq` tail branch at `0x0806aaa0`).

use core::ptr;

use super::tdat_class_check::ui_element_is_tdat_class;

/// Target-word index of the message handler (`ldrne ip,[r4,#0x4c]`).
const MESSAGE_HANDLER_WORD: usize = 0x4c / 4;
/// Target-word index of the handler context (`ldrne r3,[r4,#0x50]`).
const MESSAGE_CONTEXT_WORD: usize = 0x50 / 4;
/// Returned when `element` is not a 'tdat' element (`mvneq r0,#0x31`).
const TDAT_DISPATCH_REJECTED: u32 = 0xffff_ffce;

/// ABI of a message handler stored in a 'tdat' element at +0x4c.
pub type TdatMessageHandler = unsafe extern "C" fn(*mut u8, u32, *mut u8, u32) -> u32;

/// ABI boundary for the virtual handler word stored in the element.
///
/// `handler_address` remains a target-width word; the target dispatcher turns
/// it into [`TdatMessageHandler`] only on the 32-bit retailOS build.
pub type TdatMessageDispatch = unsafe extern "C" fn(u32, *mut u8, u32, *mut u8, u32) -> u32;

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_tdat_message_dispatch(
    handler_address: u32,
    element: *mut u8,
    message: u32,
    arguments: *mut u8,
    context: u32,
) -> u32 {
    let handler: TdatMessageHandler = core::mem::transmute(handler_address as usize);
    handler(element, message, arguments, context)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn retail_tdat_message_dispatch(
    _handler_address: u32,
    _element: *mut u8,
    _message: u32,
    _arguments: *mut u8,
    _context: u32,
) -> u32 {
    0
}

/// Calls outside this one-function port.
///
/// A matching retailOS element stores a dynamically selected handler at +0x4c,
/// so host tests replace the target-only pointer invocation while retaining the
/// exact handler word and four handler arguments.
#[derive(Clone, Copy)]
pub struct TdatMessageOps {
    pub dispatch: TdatMessageDispatch,
}

/// Production boundary for the virtual handler invocation.
pub const DEFAULT_TDAT_MESSAGE_OPS: TdatMessageOps = TdatMessageOps {
    dispatch: retail_tdat_message_dispatch,
};

/// Active virtual-handler invocation boundary.
pub static mut TDAT_MESSAGE_OPS: TdatMessageOps = DEFAULT_TDAT_MESSAGE_OPS;

#[inline(always)]
fn tdat_message_ops() -> TdatMessageOps {
    unsafe { ptr::read_volatile(ptr::addr_of!(TDAT_MESSAGE_OPS)) }
}

/// tdat_dispatch_message — original: `FUN_080442a0` @ `0x080442a0` (52 bytes).
///
/// Raw ARM decoded from `work/firmware/osos.dec` is exactly
/// `0x080442a0..0x080442d4`; the next sibling starts with `cmp r0,#6` at
/// `0x080442d4`. It calls the already-ported 'tdat' predicate
/// [`ui_element_is_tdat_class`] at `0x0806aa3c`, then, on success, loads the
/// handler and its context words from element+0x4c/+0x50 and tail-dispatches
/// the handler as `(element, message, arguments, context)`. On rejection it
/// returns `0xffff_ffce`. Decoding every ARM B/BL encoding in `osos.dec`
/// finds 11 direct callers, all unconditional `bl`; the only predicated branch
/// target is a `beq` tail dispatch at `0x0806aaa0`, which invokes this wrapper
/// only on that refcount transition.
///
/// Deliberate deviation: Rust calls the ported class predicate directly. The
/// stored handler is target-address data, so target builds transmute and call
/// it through `TDAT_MESSAGE_OPS`; host tests replace that boundary rather than
/// treating a 32-bit firmware code address as a native function pointer.
///
/// # Safety
///
/// `element` may be NULL because the class predicate guards it. A non-NULL
/// matching element must be readable through +0x53; its handler at +0x4c must
/// be a callable retailOS address on target builds. `arguments` is forwarded
/// unchanged and has only the handler's contract.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.tdat_dispatch_message")]
pub unsafe extern "C" fn tdat_dispatch_message(
    element: *mut u8,
    message: u32,
    arguments: *mut u8,
) -> u32 {
    if ui_element_is_tdat_class(element) == 0 {
        return TDAT_DISPATCH_REJECTED;
    }

    let words = element.cast::<u32>();
    let handler_address = words.add(MESSAGE_HANDLER_WORD).read();
    let context = words.add(MESSAGE_CONTEXT_WORD).read();
    (tdat_message_ops().dispatch)(handler_address, element, message, arguments, context)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::Mutex;

    const TDAT_CLASS_TAG: u32 = 0x7464_6174;
    const OTHER_CLASS_TAG: u32 = 0x706c_7374;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut DISPATCH_CALLS: u32 = 0;
    static mut HANDLER_ADDRESS: u32 = 0;
    static mut DISPATCH_ELEMENT: usize = 0;
    static mut DISPATCH_MESSAGE: u32 = 0;
    static mut DISPATCH_ARGUMENTS: usize = 0;
    static mut DISPATCH_CONTEXT: u32 = 0;
    static mut DISPATCH_RESULT: u32 = 0;

    unsafe extern "C" fn record_dispatch(
        handler_address: u32,
        element: *mut u8,
        message: u32,
        arguments: *mut u8,
        context: u32,
    ) -> u32 {
        DISPATCH_CALLS += 1;
        HANDLER_ADDRESS = handler_address;
        DISPATCH_ELEMENT = element as usize;
        DISPATCH_MESSAGE = message;
        DISPATCH_ARGUMENTS = arguments as usize;
        DISPATCH_CONTEXT = context;
        DISPATCH_RESULT
    }

    struct OpsGuard(TdatMessageOps);

    impl Drop for OpsGuard {
        fn drop(&mut self) {
            unsafe { TDAT_MESSAGE_OPS = self.0 };
        }
    }

    unsafe fn install_recorder(result: u32) -> OpsGuard {
        let previous = TDAT_MESSAGE_OPS;
        TDAT_MESSAGE_OPS = TdatMessageOps {
            dispatch: record_dispatch,
        };
        DISPATCH_CALLS = 0;
        HANDLER_ADDRESS = 0;
        DISPATCH_ELEMENT = 0;
        DISPATCH_MESSAGE = 0;
        DISPATCH_ARGUMENTS = 0;
        DISPATCH_CONTEXT = 0;
        DISPATCH_RESULT = result;
        OpsGuard(previous)
    }

    #[test]
    fn null_and_other_class_are_rejected_without_dispatch() {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let _ops = unsafe { install_recorder(0xfeed_face) };
        let mut other = [0u32; MESSAGE_CONTEXT_WORD + 1];
        other[1] = OTHER_CLASS_TAG;

        assert_eq!(
            unsafe { tdat_dispatch_message(core::ptr::null_mut(), 0, core::ptr::null_mut()) },
            TDAT_DISPATCH_REJECTED,
        );
        assert_eq!(
            unsafe { tdat_dispatch_message(other.as_mut_ptr().cast(), 0, core::ptr::null_mut()) },
            TDAT_DISPATCH_REJECTED,
        );
        assert_eq!(unsafe { DISPATCH_CALLS }, 0);
    }

    #[test]
    fn tdat_element_forwards_handler_and_all_arguments() {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some(element) = crate::testing::try_map_u32_slab(
            crate::testing::hints::TDAT_MESSAGE_DISPATCH,
            0x100,
        ) else {
            assert!(crate::testing::note_missing_u32_fixture(module_path!()));
            return;
        };
        let _ops = unsafe { install_recorder(0xc0de_cafe) };

        unsafe {
            core::ptr::write_bytes(element, 0, 0x100);
            let words = element.cast::<u32>();
            words.add(1).write(TDAT_CLASS_TAG);
            words.add(MESSAGE_HANDLER_WORD).write(0x0812_3456);
            words.add(MESSAGE_CONTEXT_WORD).write(0x9abc_def0);
        }
        let arguments = unsafe { element.add(0x60) };

        let result = unsafe {
            tdat_dispatch_message(element, 0x7464_616f, arguments)
        };

        assert_eq!(result, 0xc0de_cafe);
        unsafe {
            assert_eq!(DISPATCH_CALLS, 1);
            assert_eq!(HANDLER_ADDRESS, 0x0812_3456);
            assert_eq!(DISPATCH_ELEMENT, element as usize);
            assert_eq!(DISPATCH_MESSAGE, 0x7464_616f);
            assert_eq!(DISPATCH_ARGUMENTS, arguments as usize);
            assert_eq!(DISPATCH_CONTEXT, 0x9abc_def0);
        }
    }
}
