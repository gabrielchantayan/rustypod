//! `task_context_observable_dispatch` — original: `FUN_08110a60` @ `0x08110a60`.
//!
//! **68 bytes** (`0x08110a60..0x08110aa4`); `0x08110aa4` starts the next
//! independently linked function. Raw `osos.dec` has four direct plain `bl`
//! calls in the body (`0x080cb828` twice, `0x082aadd4`, and `0x08271cec`) and
//! no predicated direct `bl`; the final dispatch is an indirect `blx` through
//! vtable slot `+0x1c`.
//!
//! Algorithm: get the current task context and load its target word `+0x2c`.
//! On NULL, allocate 16 bytes with tag-2 `operator_new`, construct an
//! observable array there, re-fetch the current context, and publish the
//! constructor result at `+0x2c`. Then invoke that object's runtime vtable
//! slot `+0x1c` with the object and a pointer to the caller's word.
//!
//! Deliberate deviation: the runtime vtable target has no recoverable static
//! identity, so target code dispatches it structurally while host tests use a
//! typed seam. The target-width `+0x2c` field is addressed as word 11 rather
//! than through `TaskCtx`, whose host pointer fields are wider.

use crate::cxx::observable_array::observable_array_construct;
use crate::heap::veneers::operator_new;

const OBSERVABLE_ARRAY_SIZE: usize = 16;
const TASK_CONTEXT_OBSERVABLE_WORD: usize = 11;

#[cfg(not(target_os = "none"))]
pub struct TaskContextObservableDispatchOps {
    pub current_context: unsafe extern "C" fn() -> *mut u8,
    pub dispatch: unsafe extern "C" fn(*mut u8, *mut u32),
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_current_context() -> *mut u8 {
    panic!("install task-context observable dispatch host operations before calling")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_dispatch(_observable: *mut u8, _argument: *mut u32) {
    panic!("install task-context observable dispatch host operations before calling")
}

#[cfg(not(target_os = "none"))]
pub const DEFAULT_TASK_CONTEXT_OBSERVABLE_DISPATCH_OPS: TaskContextObservableDispatchOps = TaskContextObservableDispatchOps {
    current_context: missing_current_context,
    dispatch: missing_dispatch,
};
#[cfg(not(target_os = "none"))]
pub static mut TASK_CONTEXT_OBSERVABLE_DISPATCH_OPS: TaskContextObservableDispatchOps =
    DEFAULT_TASK_CONTEXT_OBSERVABLE_DISPATCH_OPS;

/// Calls the current task context's lazily allocated observable with `argument`.
///
/// # Safety
///
/// On target, the current task context, its target-width word at `+0x2c`, and
/// the observable's vtable slot `+0x1c` must be valid. Host callers must
/// install [`TASK_CONTEXT_OBSERVABLE_DISPATCH_OPS`] and provide a u32-addressable
/// context block of at least 12 words.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn task_context_observable_dispatch(mut argument: u32) {
    #[cfg(target_os = "none")]
    {
        type Dispatch = unsafe extern "C" fn(*mut u8, *mut u32);
        let context = crate::kernel::task::current_task_ctx_block().cast::<u32>();
        let mut observable = context.add(TASK_CONTEXT_OBSERVABLE_WORD).read_volatile() as *mut u8;
        if observable.is_null() {
            observable = observable_array_construct(operator_new(OBSERVABLE_ARRAY_SIZE).cast()).cast();
            let context = crate::kernel::task::current_task_ctx_block().cast::<u32>();
            context.add(TASK_CONTEXT_OBSERVABLE_WORD).write_volatile(observable as u32);
        }
        let vtable = observable.cast::<*const u8>().read_volatile();
        let dispatch: Dispatch = vtable.add(0x1c).cast::<Dispatch>().read_volatile();
        dispatch(observable, core::ptr::addr_of_mut!(argument));
    }

    #[cfg(not(target_os = "none"))]
    {
        let ops = core::ptr::read_volatile(core::ptr::addr_of!(TASK_CONTEXT_OBSERVABLE_DISPATCH_OPS));
        let context = (ops.current_context)().cast::<u32>();
        let mut observable = context.add(TASK_CONTEXT_OBSERVABLE_WORD).read_volatile() as *mut u8;
        if observable.is_null() {
            observable = observable_array_construct(operator_new(OBSERVABLE_ARRAY_SIZE).cast()).cast();
            let context = (ops.current_context)().cast::<u32>();
            context.add(TASK_CONTEXT_OBSERVABLE_WORD).write_volatile(observable as u32);
        }
        (ops.dispatch)(observable, core::ptr::addr_of_mut!(argument));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut CONTEXT: *mut u8 = core::ptr::null_mut();
    static mut CONTEXT_CALLS: usize = 0;
    static mut DISPATCHED_OBSERVABLE: *mut u8 = core::ptr::null_mut();
    static mut DISPATCHED_ARGUMENT: u32 = 0;

    unsafe extern "C" fn current_context() -> *mut u8 {
        CONTEXT_CALLS += 1;
        CONTEXT
    }
    unsafe extern "C" fn dispatch(observable: *mut u8, argument: *mut u32) {
        DISPATCHED_OBSERVABLE = observable;
        DISPATCHED_ARGUMENT = argument.read();
    }

    #[test]
    fn lazy_allocation_constructs_publishes_and_dispatches_argument() {
        let _test_lock = TEST_LOCK.lock();
        let _heap_lock = crate::heap::veneers::tests::mock_heap();
        let Some(context) = crate::testing::try_map_u32_slab(
            crate::testing::hints::TASK_CONTEXT_OBSERVABLE_DISPATCH,
            0x1000,
        ) else { return };
        unsafe {
            core::ptr::write_bytes(context, 0, 0x1000);
            CONTEXT = context;
            CONTEXT_CALLS = 0;
            DISPATCHED_OBSERVABLE = core::ptr::null_mut();
            DISPATCHED_ARGUMENT = 0;
            let observable = context.add(0x100);
            crate::heap::veneers::tests::set_alloc_ret(observable);
            TASK_CONTEXT_OBSERVABLE_DISPATCH_OPS = TaskContextObservableDispatchOps { current_context, dispatch };
            task_context_observable_dispatch(0x1234_5678);
            let observable = context.add(0x100);
            assert_eq!(context.cast::<u32>().add(TASK_CONTEXT_OBSERVABLE_WORD).read(), observable as u32);
            assert_eq!(crate::heap::veneers::tests::alloc_log(), (1, OBSERVABLE_ARRAY_SIZE, 2));
            assert_eq!(CONTEXT_CALLS, 2);
            assert_eq!(DISPATCHED_OBSERVABLE, observable);
            assert_eq!(DISPATCHED_ARGUMENT, 0x1234_5678);
        }
    }

    #[test]
    fn cached_observable_skips_allocation_and_refetch() {
        let _test_lock = TEST_LOCK.lock();
        let _heap_lock = crate::heap::veneers::tests::mock_heap();
        let Some(context) = crate::testing::try_map_u32_slab(
            crate::testing::hints::TASK_CONTEXT_OBSERVABLE_DISPATCH_CACHED,
            0x1000,
        ) else { return };
        unsafe {
            core::ptr::write_bytes(context, 0, 0x1000);
            let observable = 0x1234_0000usize as *mut u8;
            context.cast::<u32>().add(TASK_CONTEXT_OBSERVABLE_WORD).write(observable as u32);
            CONTEXT = context;
            CONTEXT_CALLS = 0;
            DISPATCHED_OBSERVABLE = core::ptr::null_mut();
            DISPATCHED_ARGUMENT = 0;
            TASK_CONTEXT_OBSERVABLE_DISPATCH_OPS = TaskContextObservableDispatchOps { current_context, dispatch };
            task_context_observable_dispatch(7);
            assert_eq!(crate::heap::veneers::tests::alloc_log().0, 0);
            assert_eq!(CONTEXT_CALLS, 1);
            assert_eq!(DISPATCHED_OBSERVABLE, observable);
            assert_eq!(DISPATCHED_ARGUMENT, 7);
        }
    }
}
