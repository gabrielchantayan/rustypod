//! `initializer_profile_dispatch` — original: `FUN_080d2d1c` @ **0x080d2d1c**
//! (**92 bytes**, `0x080d2d1c..0x080d2d78`; the next function begins at
//! `0x080d2d7c` with `ldr r1, [r0]`).
//!
//! Raw A32 decoding finds **three inbound plain unconditional BL callers**
//! (`0x081bbd94`, `0x081bbdac`, and `0x081f4c5c`) and **zero predicated BL
//! callers**. The body makes one plain direct BL to unported
//! `FUN_080e9cbc` and no predicated BL forms.
//!
//! Algorithm: clamp `profile` into 1..=11 (zero becomes 1); select 8 for
//! profile 1, 64 for 7, 256 for 10, and 128 otherwise; then call the
//! unported seven-argument initializer with `(name, initializer_arg, 0,
//! selected_size, callback_arg, 0, 0)`.
//!
//! Deliberate deviation: `FUN_080e9cbc` remains unported. Target builds call
//! its verified retailOS address; host builds use a replaceable seam to prove
//! the selected size and complete argument ordering.

#[cfg(not(target_os = "none"))]
use core::ptr::addr_of;

const RETAIL_INITIALIZER_DISPATCH: usize = 0x080e_9cbc;

/// ABI of the unported initializer dispatcher `FUN_080e9cbc`.
pub type InitializerDispatch = unsafe extern "C" fn(u32, u32, u32, u32, u32, u32, u32);

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn invoke_initializer_dispatch(args: [u32; 7]) {
    let dispatch: InitializerDispatch = core::mem::transmute(RETAIL_INITIALIZER_DISPATCH);
    dispatch(args[0], args[1], args[2], args[3], args[4], args[5], args[6]);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_initializer_dispatch(
    _arg0: u32,
    _arg1: u32,
    _arg2: u32,
    _arg3: u32,
    _arg4: u32,
    _arg5: u32,
    _arg6: u32,
) {}

/// Host seam for the unported initializer dispatcher.
#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct InitializerDispatchOps {
    pub invoke: InitializerDispatch,
}

#[cfg(not(target_os = "none"))]
pub const DEFAULT_INITIALIZER_DISPATCH_OPS: InitializerDispatchOps = InitializerDispatchOps {
    invoke: missing_initializer_dispatch,
};

#[cfg(not(target_os = "none"))]
pub static mut INITIALIZER_DISPATCH_OPS: InitializerDispatchOps = DEFAULT_INITIALIZER_DISPATCH_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn invoke_initializer_dispatch(args: [u32; 7]) {
    let dispatch = core::ptr::read_volatile(addr_of!(INITIALIZER_DISPATCH_OPS.invoke));
    dispatch(args[0], args[1], args[2], args[3], args[4], args[5], args[6]);
}

/// Selects an initializer profile and dispatches it through the retail initializer.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn initializer_profile_dispatch(
    name: u32,
    initializer_arg: u32,
    callback_arg: u32,
    profile: u32,
) {
    let profile = if profile == 0 { 1 } else { profile.min(11) };
    let selected_size = match profile {
        1 => 8,
        7 => 64,
        10 => 256,
        _ => 128,
    };

    invoke_initializer_dispatch([name, initializer_arg, 0, selected_size, callback_arg, 0, 0]);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut CALL_ARGS: [u32; 7] = [0; 7];

    unsafe extern "C" fn recording_initializer_dispatch(
        arg0: u32,
        arg1: u32,
        arg2: u32,
        arg3: u32,
        arg4: u32,
        arg5: u32,
        arg6: u32,
    ) {
        CALL_ARGS = [arg0, arg1, arg2, arg3, arg4, arg5, arg6];
    }

    unsafe fn reset() {
        CALL_ARGS = [0; 7];
        INITIALIZER_DISPATCH_OPS = InitializerDispatchOps {
            invoke: recording_initializer_dispatch,
        };
    }

    #[test]
    fn profiles_select_sizes_and_preserve_initializer_argument_order() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let cases = [(0, 8), (1, 8), (2, 128), (7, 64), (10, 256), (11, 128), (12, 128), (u32::MAX, 128)];

        unsafe {
            reset();
            for (profile, selected_size) in cases {
                initializer_profile_dispatch(0x1111_2222, 0x3333_4444, 0x5555_6666, profile);
                assert_eq!(CALL_ARGS, [0x1111_2222, 0x3333_4444, 0, selected_size, 0x5555_6666, 0, 0]);
            }
        }
    }
}
