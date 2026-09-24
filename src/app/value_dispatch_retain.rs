//! `value_dispatch_retain` — original: `FUN_08124f64` @ `0x08124f64`
//! (24 bytes, `0x08124f64..0x08124f7c`; the next separately linked function
//! starts with `push {r4,r5,lr}` at `0x08124f7c`).
//!
//! Raw ARM decoding found **3 direct `bl` callers, all unconditional and no
//! predicated `bl` callers**: `0x08133250`, `0x08133634`, and `0x081f0458`.
//!
//! The routine preserves its third argument as the dispatcher's fifth ABI
//! argument, then dispatches `value` through `FUN_08124ff4` with fixed flags
//! `{ dispatch_enabled=1, reserved=1 }`. It does not release the value.
//!
//! Deliberate deviation: the dispatcher is still unported. This wrapper reuses
//! the existing target call and host seam from `callback_dispatch_release`.

use crate::app::callback_dispatch_release::DispatchValue;

#[cfg(target_os = "none")]
use crate::app::callback_dispatch_release::ValueDispatch;

#[cfg(target_os = "none")]
const RETAIL_VALUE_DISPATCH: usize = 0x0812_4ff4;

/// Dispatches `value` with the retained-value flags used by `FUN_08124f64`.
///
/// # Safety
///
/// `context` and `value` must meet the unported dispatcher's requirements.
/// Stock code performs no NULL checks before entering the dispatcher.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn value_dispatch_retain(
    context: *mut u8,
    value: *mut DispatchValue,
    extra: u32,
) {
    #[cfg(target_os = "none")]
    {
        let dispatch: ValueDispatch = core::mem::transmute(RETAIL_VALUE_DISPATCH);
        dispatch(context, value, 1, 1, extra);
    }

    #[cfg(not(target_os = "none"))]
    {
        let dispatch = core::ptr::read_volatile(core::ptr::addr_of!(
            crate::app::callback_dispatch_release::DISPATCH_AND_DESTROY_VALUE_OPS.dispatch
        ));
        dispatch(context, value, 1, 1, extra);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::app::callback_dispatch_release::{
        DispatchAndDestroyValueOps, CALLBACK_DISPATCH_OPS_LOCK,
        DEFAULT_DISPATCH_AND_DESTROY_VALUE_OPS, DISPATCH_AND_DESTROY_VALUE_OPS,
    };
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::MutexGuard;

    static mut DISPATCH_CALL: Option<(*mut u8, *mut DispatchValue, u32, u32, u32)> = None;

    unsafe extern "C" fn record_dispatch(
        context: *mut u8,
        value: *mut DispatchValue,
        dispatch_enabled: u32,
        reserved: u32,
        extra: u32,
    ) -> u32 {
        DISPATCH_CALL = Some((context, value, dispatch_enabled, reserved, extra));
        0
    }

    fn install_recorder() -> MutexGuard<'static, ()> {
        let guard = CALLBACK_DISPATCH_OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            addr_of_mut!(DISPATCH_CALL).write(None);
            addr_of_mut!(DISPATCH_AND_DESTROY_VALUE_OPS).write(DispatchAndDestroyValueOps {
                dispatch: record_dispatch,
            });
        }
        guard
    }

    fn restore_default(guard: MutexGuard<'static, ()>) {
        unsafe {
            addr_of_mut!(DISPATCH_AND_DESTROY_VALUE_OPS)
                .write(DEFAULT_DISPATCH_AND_DESTROY_VALUE_OPS);
        }
        drop(guard);
    }

    #[test]
    fn forwards_third_argument_with_retained_value_flags() {
        let guard = install_recorder();
        let mut context = [0u8; 4];
        let mut value = DispatchValue { vtable: core::ptr::null() };

        unsafe {
            value_dispatch_retain(context.as_mut_ptr(), addr_of_mut!(value), 0x9e37_79b9);
            assert_eq!(
                addr_of!(DISPATCH_CALL).read(),
                Some((context.as_mut_ptr(), addr_of_mut!(value), 1, 1, 0x9e37_79b9))
            );
        }
        restore_default(guard);
    }

    #[test]
    fn forwards_null_value_without_releasing_it() {
        let guard = install_recorder();
        let mut context = [0u8; 4];

        unsafe {
            value_dispatch_retain(context.as_mut_ptr(), core::ptr::null_mut(), 0);
            assert_eq!(
                addr_of!(DISPATCH_CALL).read(),
                Some((context.as_mut_ptr(), core::ptr::null_mut(), 1, 1, 0))
            );
        }
        restore_default(guard);
    }
}
