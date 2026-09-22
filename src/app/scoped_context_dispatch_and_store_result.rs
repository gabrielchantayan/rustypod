//! Dispatches a receiver's context-producing vtable method and stores its result.
//!
//! `FUN_082317a4` @ `0x082317a4`, 96 bytes (`0x082317a4..0x08231803`).
//! Raw-word decoding establishes three unconditional plain `bl` calls
//! (`0x08270394`, `0x082a4460`, and `0x08270414`), no predicated `bl` calls,
//! and one indirect `blx` through receiver-vtable slot `+0x170`. It constructs
//! a zero-mode [`ScopedContext`], asks the receiver at `this+4` to fill it,
//! resolves the context into `this+0x28`, stores the third argument at
//! `this+0x2c`, then destroys the stack context. The `+0x170` target remains
//! an observed virtual dispatch and `0x082a4460` remains an unported direct
//! firmware call; neither is assigned an invented identity. Host tests use
//! widened structural pointers instead of target-width raw object fields.

use core::{mem::MaybeUninit, ptr};

use crate::app::scoped_context::{scoped_context_construct, scoped_context_destroy, ScopedContext};

const RECEIVER_SLOT: usize = 0x04 / 4;
const RESULT_SLOT: usize = 0x28 / 4;
const STORED_VALUE_SLOT: usize = 0x2c / 4;
const CONTEXT_DISPATCH_SLOT: usize = 0x170 / 4;
const CONTEXT_RESULT_IF_AVAILABLE: usize = 0x082a_4460;

type ContextDispatch = unsafe extern "C" fn(*mut u8, u32, *mut ScopedContext);
type ContextResultIfAvailable = unsafe extern "C" fn(*mut ScopedContext, *mut u32) -> u32;

/// scoped_context_dispatch_and_store_result — original: `FUN_082317a4` @
/// `0x082317a4` (96 bytes; **3 unconditional plain `bl` calls, no predicated
/// `bl` calls**, plus one indirect `blx` through vtable slot `+0x170`).
///
/// Constructs a zeroed-mode scoped context, dispatches the opaque receiver's
/// `+0x170` method with `(receiver, argument, &context)`, conditionally writes
/// its resolved word to `this+0x28`, then writes `value` to `this+0x2c` before
/// destroying the context. Deliberate deviation: the unresolved `+0x170`
/// method stays a physical vtable dispatch; the unported `0x082a4460` remains
/// a fixed firmware call on target, while host tests model both structurally.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
#[cfg(target_os = "none")]
pub unsafe extern "C" fn scoped_context_dispatch_and_store_result(
    object: *mut u8,
    argument: u32,
    value: u32,
) {
    let mut context = MaybeUninit::<ScopedContext>::uninit();
    scoped_context_construct(context.as_mut_ptr(), ptr::null_mut(), 0);

    let words = object.cast::<u32>();
    let receiver = words.add(RECEIVER_SLOT).read_volatile() as usize as *mut u8;
    let vtable = receiver.cast::<u32>().read_volatile() as usize as *const u32;
    let dispatch_address = vtable.add(CONTEXT_DISPATCH_SLOT).read_volatile();
    let dispatch: ContextDispatch = core::mem::transmute(dispatch_address as usize);
    dispatch(receiver, argument, context.as_mut_ptr());

    let resolve: ContextResultIfAvailable = core::mem::transmute(CONTEXT_RESULT_IF_AVAILABLE);
    resolve(context.as_mut_ptr(), words.add(RESULT_SLOT));
    words.add(STORED_VALUE_SLOT).write_volatile(value);
    scoped_context_destroy(context.as_mut_ptr());
}

#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostContextDispatchVtable {
    pub unresolved_before_dispatch: [usize; CONTEXT_DISPATCH_SLOT],
    pub dispatch: ContextDispatch,
}

#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostContextDispatchReceiver {
    pub vtable: *const HostContextDispatchVtable,
}

#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostContextDispatchObject {
    pub unresolved_00: usize,
    pub receiver: *mut HostContextDispatchReceiver,
    pub unresolved_08_to_27: [u8; 0x20],
    pub result: u32,
    pub value: u32,
}

#[cfg(not(target_os = "none"))]
type HostContextResultIfAvailable = unsafe extern "C" fn(*mut ScopedContext, *mut u32) -> u32;

#[cfg(not(target_os = "none"))]
static mut HOST_CONTEXT_RESULT_IF_AVAILABLE: HostContextResultIfAvailable = unavailable_context_result;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_context_result(_: *mut ScopedContext, _: *mut u32) -> u32 {
    0
}

#[cfg(not(target_os = "none"))]
#[inline(never)]
pub unsafe extern "C" fn scoped_context_dispatch_and_store_result(
    object: *mut HostContextDispatchObject,
    argument: u32,
    value: u32,
) {
    let mut context = MaybeUninit::<ScopedContext>::uninit();
    scoped_context_construct(context.as_mut_ptr(), ptr::null_mut(), 0);

    let receiver = (*object).receiver;
    let vtable = ptr::read_volatile(ptr::addr_of!((*receiver).vtable));
    ((*vtable).dispatch)(receiver.cast(), argument, context.as_mut_ptr());
    ptr::read_volatile(ptr::addr_of!(HOST_CONTEXT_RESULT_IF_AVAILABLE))(context.as_mut_ptr(), ptr::addr_of_mut!((*object).result));
    (*object).value = value;
    scoped_context_destroy(context.as_mut_ptr());
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut DISPATCH_ARGUMENT: u32 = 0;
    static mut DISPATCH_MODE: u8 = 0xff;
    static mut RESULT_AVAILABLE: bool = false;

    unsafe extern "C" fn dispatch(_: *mut u8, argument: u32, context: *mut ScopedContext) {
        DISPATCH_ARGUMENT = argument;
        DISPATCH_MODE = (*context).mode;
    }

    unsafe extern "C" fn resolve(_: *mut ScopedContext, destination: *mut u32) -> u32 {
        if RESULT_AVAILABLE {
            *destination = 0x9e37_79b9;
            1
        } else {
            0
        }
    }

    static VTABLE: HostContextDispatchVtable = HostContextDispatchVtable {
        unresolved_before_dispatch: [0; CONTEXT_DISPATCH_SLOT],
        dispatch,
    };

    fn object(receiver: *mut HostContextDispatchReceiver) -> HostContextDispatchObject {
        HostContextDispatchObject {
            unresolved_00: 0,
            receiver,
            unresolved_08_to_27: [0; 0x20],
            result: 0xa5a5_a5a5,
            value: 0,
        }
    }

    #[test]
    fn dispatches_argument_and_stores_available_context_result() {
        let _guard = LOCK.lock();
        unsafe {
            HOST_CONTEXT_RESULT_IF_AVAILABLE = resolve;
            RESULT_AVAILABLE = true;
            let mut receiver = HostContextDispatchReceiver { vtable: &VTABLE };
            let mut object = object(&mut receiver);
            scoped_context_dispatch_and_store_result(&mut object, 0x1020_3040, 0x5566_7788);
            assert_eq!(DISPATCH_ARGUMENT, 0x1020_3040);
            assert_eq!(DISPATCH_MODE, 0);
            assert_eq!(object.result, 0x9e37_79b9);
            assert_eq!(object.value, 0x5566_7788);
        }
    }

    #[test]
    fn preserves_result_when_context_is_unavailable() {
        let _guard = LOCK.lock();
        unsafe {
            HOST_CONTEXT_RESULT_IF_AVAILABLE = resolve;
            RESULT_AVAILABLE = false;
            let mut receiver = HostContextDispatchReceiver { vtable: &VTABLE };
            let mut object = object(&mut receiver);
            scoped_context_dispatch_and_store_result(&mut object, 0, u32::MAX);
            assert_eq!(object.result, 0xa5a5_a5a5);
            assert_eq!(object.value, u32::MAX);
        }
    }
}
