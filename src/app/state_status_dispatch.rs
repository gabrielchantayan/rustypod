//! State-status dispatch — `FUN_0817de2c` @ `0x0817de2c` (96 bytes).
//!
//! The raw words run through `0x0817de87`; `0x0817de8c` starts an independent
//! function. Three direct incoming `bl` sites are at `0x0817d7e8`,
//! `0x0817dc74`, and `0x0817dde8`; all are unconditional (zero predicated
//! forms). The body has four unconditional outgoing `bl` instructions and
//! tail-branches through the shared epilogue at `0x081b0de84` to `0x081b0fe8`.
//!
//! It first rejects states other than 3 or 4. It then checks the embedded
//! scoped-context token's owner bit 3. A set bit converts the pointed
//! context's status byte; a clear bit dispatches only when its code is 1000,
//! converting zero instead. Both successful paths tail-dispatch the converted
//! result with a mode: 2 when bit 3 is set, otherwise 0. The shared tail
//! obtains the UI manager and forwards those two registers to an unported
//! IRAM target. Deliberate deviation: that target has no recovered identity,
//! so target builds call the verified shared-tail ABI directly and host builds
//! expose that boundary as a seam.

#[cfg(target_os = "none")]
use crate::app::scoped_context::{scoped_context_owner_flags_bit_3, ScopedContext};
use crate::runtime::status_byte_to_result::status_byte_to_result;
use crate::util::value_predicate::byte_is_three_or_four;

const STATE_CONTEXT_OFFSET: usize = 0x20;
const CONTEXT_STATUS_OFFSET: usize = 4;
const CONTEXT_CODE_OFFSET: usize = 8;
const REQUIRED_CONTEXT_CODE: u32 = 1000;

type DispatchStatusMode = unsafe extern "C" fn(u32, u32);
type ScopedContextOwnerFlagsBit3 = unsafe extern "C" fn(*const u8) -> u32;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn scoped_context_bit_3(token: *const u8) -> u32 {
    scoped_context_owner_flags_bit_3(token.cast::<ScopedContext>())
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_scoped_context_bit_3(_token: *const u8) -> u32 { 0 }

#[cfg(not(target_os = "none"))]
pub static mut SCOPED_CONTEXT_BIT_3: ScopedContextOwnerFlagsBit3 = missing_scoped_context_bit_3;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn scoped_context_bit_3(token: *const u8) -> u32 {
    core::ptr::read_volatile(core::ptr::addr_of!(SCOPED_CONTEXT_BIT_3))(token)
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_dispatch_status_mode(mode: u32, result: u32) {
    let dispatch: DispatchStatusMode = core::mem::transmute(0x081b_0fe8usize);
    dispatch(mode, result);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_dispatch_status_mode(_mode: u32, _result: u32) {}

#[cfg(not(target_os = "none"))]
pub static mut DISPATCH_STATUS_MODE: DispatchStatusMode = missing_dispatch_status_mode;

#[inline(always)]
unsafe fn dispatch_status_mode(mode: u32, result: u32) {
    #[cfg(target_os = "none")]
    retail_dispatch_status_mode(mode, result);

    #[cfg(not(target_os = "none"))]
    core::ptr::read_volatile(core::ptr::addr_of!(DISPATCH_STATUS_MODE))(mode, result);
}

#[inline(always)]
unsafe fn state_context(state: *mut u8) -> *const u8 {
    #[cfg(target_os = "none")]
    {
        (state.add(STATE_CONTEXT_OFFSET) as *const *const u8).read_volatile()
    }

    #[cfg(not(target_os = "none"))]
    {
        #[repr(C)]
        struct HostState {
            _before_context: [u8; STATE_CONTEXT_OFFSET],
            context: *const u8,
        }
        core::ptr::read_volatile(state.cast::<HostState>()).context
    }
}

/// state_status_dispatch — original: `FUN_0817de2c` @ `0x0817de2c` (96 bytes).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn state_status_dispatch(state: *mut u8) {
    if byte_is_three_or_four(state) == 0 {
        return;
    }

    let (mode, result) = if scoped_context_bit_3(state.add(4)) != 0 {
        let context = state_context(state);
        (2, status_byte_to_result(context.add(CONTEXT_STATUS_OFFSET).read() as u32))
    } else {
        let context = state_context(state);
        if (context.add(CONTEXT_CODE_OFFSET) as *const u32).read() != REQUIRED_CONTEXT_CODE {
            return;
        }
        (0, status_byte_to_result(0))
    };
    dispatch_status_mode(mode, result);
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut BIT_3: u32 = 0;
    static mut DISPATCH: Option<(u32, u32)> = None;

    unsafe extern "C" fn bit_3(_token: *const u8) -> u32 { BIT_3 }
    unsafe extern "C" fn record_dispatch(mode: u32, result: u32) {
        DISPATCH = Some((mode, result));
    }

    #[repr(C)]
    struct HostState {
        state: u8,
        _embedded_token: [u8; 31],
        context: *const u8,
    }

    #[repr(C)]
    struct Context {
        _before_status: [u8; CONTEXT_STATUS_OFFSET],
        status: u8,
        _padding: [u8; 3],
        code: u32,
    }

    unsafe fn run(state: u8, bit_3_value: u32, status: u8, code: u32) -> Option<(u32, u32)> {
        let context = Context { _before_status: [0; CONTEXT_STATUS_OFFSET], status, _padding: [0; 3], code };
        let mut input = HostState { state, _embedded_token: [0; 31], context: (&context as *const Context).cast() };
        BIT_3 = bit_3_value;
        DISPATCH = None;
        state_status_dispatch((&mut input as *mut HostState).cast());
        DISPATCH
    }

    #[test]
    fn rejects_an_inactive_state_without_dispatching() {
        let _lock = LOCK.lock();
        unsafe {
            SCOPED_CONTEXT_BIT_3 = bit_3;
            DISPATCH_STATUS_MODE = record_dispatch;
            assert_eq!(run(2, 1, 1, 1000), None);
        }
    }

    #[test]
    fn requires_code_1000_when_the_owner_bit_is_clear() {
        let _lock = LOCK.lock();
        unsafe {
            SCOPED_CONTEXT_BIT_3 = bit_3;
            DISPATCH_STATUS_MODE = record_dispatch;
            assert_eq!(run(3, 0, 0xff, 999), None);
            assert_eq!(run(4, 0, 0xff, 1000), Some((0, 0)));
        }
    }

    #[test]
    fn converts_the_context_status_when_the_owner_bit_is_set() {
        let _lock = LOCK.lock();
        unsafe {
            SCOPED_CONTEXT_BIT_3 = bit_3;
            DISPATCH_STATUS_MODE = record_dispatch;
            assert_eq!(run(3, 1, 0xff, 0), Some((2, u32::MAX)));
        }
    }
}
