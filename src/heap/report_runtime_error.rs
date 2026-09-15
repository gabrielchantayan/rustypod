//! Runtime error reporting and non-local unwind.
//!
//! `report_runtime_error` is retailOS `FUN_081b53e4` at 0x081b53e4.
//! Raw ARM is 48 bytes (0x081b53e4..0x081b5413): the following `ldr r1,
//! [r0, #4]` at 0x081b5414 starts a separate leaf function. It has four
//! plain `bl` calls, including one predicated `bleq`, and no other call form.
//!
//! The routine obtains the active runtime-error context, reports a missing
//! context with -1, stores its code at context+0x180, publishes the opaque
//! descriptor through the context setter, then `longjmp`s to that context
//! with value 1. The three context helpers are not yet ported, so target
//! defaults call their verified stock addresses; host operations make the
//! ordering and fixed word offset observable. Deliberate deviation: the host
//! unwind operation returns so tests can inspect the completed stores; retail
//! `longjmp` never returns.

use crate::runtime::setjmp::{longjmp, JmpBuf};

const ERROR_CODE_OFFSET: usize = 0x180;

#[derive(Clone, Copy)]
pub struct RuntimeErrorOps {
    pub active_context: unsafe extern "C" fn() -> *mut u8,
    pub missing_context: unsafe extern "C" fn(code: i32),
    pub set_descriptor: unsafe extern "C" fn(descriptor: *const u8),
    pub unwind: unsafe extern "C" fn(context: *const JmpBuf, value: i32),
}

#[cfg(target_os = "none")]
unsafe extern "C" fn active_context() -> *mut u8 {
    let function: unsafe extern "C" fn() -> *mut u8 = core::mem::transmute(0x081b_53a0usize);
    function()
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn active_context() -> *mut u8 {
    core::ptr::null_mut()
}

#[cfg(target_os = "none")]
unsafe extern "C" fn missing_context(code: i32) {
    let function: unsafe extern "C" fn(i32) = core::mem::transmute(0x0808_6e68usize);
    function(code)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_context(_code: i32) {}

#[cfg(target_os = "none")]
unsafe extern "C" fn set_descriptor(descriptor: *const u8) {
    let function: unsafe extern "C" fn(*const u8) = core::mem::transmute(0x081b_53c0usize);
    function(descriptor)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn set_descriptor(_descriptor: *const u8) {}

unsafe extern "C" fn unwind(context: *const JmpBuf, value: i32) {
    longjmp(context, value)
}

pub const DEFAULT_RUNTIME_ERROR_OPS: RuntimeErrorOps = RuntimeErrorOps {
    active_context,
    missing_context,
    set_descriptor,
    unwind,
};

pub static mut RUNTIME_ERROR_OPS: RuntimeErrorOps = DEFAULT_RUNTIME_ERROR_OPS;

#[inline(always)]
fn runtime_error_ops() -> RuntimeErrorOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(RUNTIME_ERROR_OPS)) }
}

/// report_runtime_error — original: `FUN_081b53e4` @ 0x081b53e4 (48 bytes).
///
/// See the module header for raw-code provenance, call count, algorithm, and
/// the host-only returning-unwind deviation.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn report_runtime_error(code: u32, descriptor: *const u8) {
    let ops = runtime_error_ops();
    let context = (ops.active_context)();
    if context.is_null() {
        (ops.missing_context)(-1);
    }
    context.add(ERROR_CODE_OFFSET).cast::<u32>().write(code);
    (ops.set_descriptor)(descriptor);
    (ops.unwind)(context.cast::<JmpBuf>(), 1);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut CONTEXT: [u8; ERROR_CODE_OFFSET + 8] = [0; ERROR_CODE_OFFSET + 8];
    static mut SET_DESCRIPTOR: *const u8 = core::ptr::null();
    static mut MISSING_CODE: i32 = 0;
    static mut UNWIND_CONTEXT: *const JmpBuf = core::ptr::null();
    static mut UNWIND_VALUE: i32 = 0;

    unsafe extern "C" fn mock_active_context() -> *mut u8 {
        core::ptr::addr_of_mut!(CONTEXT).cast()
    }
    unsafe extern "C" fn mock_missing_context(code: i32) {
        MISSING_CODE = code;
    }
    unsafe extern "C" fn mock_set_descriptor(descriptor: *const u8) {
        SET_DESCRIPTOR = descriptor;
    }
    unsafe extern "C" fn mock_unwind(context: *const JmpBuf, value: i32) {
        UNWIND_CONTEXT = context;
        UNWIND_VALUE = value;
    }

    unsafe fn install_mocks() {
        core::ptr::addr_of_mut!(CONTEXT).write([0; ERROR_CODE_OFFSET + 8]);
        SET_DESCRIPTOR = core::ptr::null();
        MISSING_CODE = 0;
        UNWIND_CONTEXT = core::ptr::null();
        UNWIND_VALUE = 0;
        core::ptr::addr_of_mut!(RUNTIME_ERROR_OPS).write(RuntimeErrorOps {
            active_context: mock_active_context,
            missing_context: mock_missing_context,
            set_descriptor: mock_set_descriptor,
            unwind: mock_unwind,
        });
    }

    unsafe fn teardown() {
        core::ptr::addr_of_mut!(RUNTIME_ERROR_OPS).write(DEFAULT_RUNTIME_ERROR_OPS);
    }

    #[test]
    fn stores_opaque_descriptor_and_unwinds_with_one() {
        let _guard = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            install_mocks();
            let descriptor = 0x088f_8c48usize as *const u8;
            report_runtime_error(4, descriptor);
            assert_eq!(CONTEXT.as_ptr().add(ERROR_CODE_OFFSET).cast::<u32>().read(), 4);
            assert_eq!(SET_DESCRIPTOR, descriptor, "descriptor remains opaque");
            assert_eq!(UNWIND_CONTEXT, CONTEXT.as_ptr().cast::<JmpBuf>());
            assert_eq!(UNWIND_VALUE, 1);
            assert_eq!(MISSING_CODE, 0);
            teardown();
        }
    }

    #[test]
    fn preserves_zero_and_maximum_error_codes() {
        let _guard = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            install_mocks();
            for code in [0, u32::MAX] {
                report_runtime_error(code, core::ptr::null());
                assert_eq!(CONTEXT.as_ptr().add(ERROR_CODE_OFFSET).cast::<u32>().read(), code);
                assert!(SET_DESCRIPTOR.is_null());
                assert_eq!(UNWIND_VALUE, 1);
            }
            teardown();
        }
    }
}
