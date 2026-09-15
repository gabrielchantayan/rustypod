//! `object_state_initialize` — original: `FUN_0810025c` @ `0x0810025c`
//! (108 bytes; **five direct inbound `bl` call sites, all unconditional; no
//! predicated `bl` forms**, verified by decoding ARM B/BL words in
//! `work/firmware/osos.dec`).
//!
//! Raw ARM spans `0x0810025c..0x081002c8`: 104 bytes of code followed by the
//! literal-pool pointer `0x089ca69c`; `push {r4, lr}` at `0x081002cc` begins
//! the next separately linked function. On the first call for an object whose
//! byte at `+0x90` is zero, it sends gateway payload `0x26` with flag one,
//! dispatches selectors 4 and 0 to retained retailOS `FUN_08100968` using the
//! words at `0x089ca6a4` and `0x089ca6a0`, stores one at `+0x90`, then sends the
//! same payload with timeout 1000. Every call returns the word at `+0x2c`.
//!
//! Deliberate deviation: `FUN_08100968` has no established identity or Rust
//! port, so this boundary retains its address rather than inventing a callee
//! name. Host tests install a recording seam; device builds enter retailOS at
//! `0x08100968`.

use crate::kernel::gateway_request::gateway_request_timed as retail_gateway_request_timed;
use crate::kernel::gateway_request_blocking::gateway_request_blocking as retail_gateway_request_blocking;

const INITIALIZE_FLAG_OFFSET: usize = 0x90;
const RESULT_OFFSET: usize = 0x2c;
const STATE_INIT_TABLE: usize = 0x089c_a69c;

/// Retained retailOS dispatcher at `FUN_08100968`.
pub type FirmwareStateDispatch = unsafe extern "C" fn(*mut u8, *mut u8, u32, u32);

pub type GatewayRequest = unsafe extern "C" fn(usize, usize);

#[cfg(target_os = "none")]
pub static mut OBJECT_STATE_GATEWAY_BLOCKING: GatewayRequest = retail_gateway_request_blocking;
#[cfg(target_os = "none")]
pub static mut OBJECT_STATE_GATEWAY_TIMED: GatewayRequest = retail_gateway_request_timed;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_gateway_request(_payload: usize, _argument: usize) {}
#[cfg(not(target_os = "none"))]
pub static mut OBJECT_STATE_GATEWAY_BLOCKING: GatewayRequest = host_gateway_request;
#[cfg(not(target_os = "none"))]
pub static mut OBJECT_STATE_GATEWAY_TIMED: GatewayRequest = host_gateway_request;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_state_dispatch(object: *mut u8, state: *mut u8, selector: u32, value: u32) {
    let dispatch: FirmwareStateDispatch = core::mem::transmute(0x0810_0968usize);
    dispatch(object, state, selector, value);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_state_dispatch(_object: *mut u8, _state: *mut u8, _selector: u32, _value: u32) {}

#[cfg(target_os = "none")]
pub static mut FIRMWARE_STATE_DISPATCH: FirmwareStateDispatch = firmware_state_dispatch;

#[cfg(not(target_os = "none"))]
pub static mut FIRMWARE_STATE_DISPATCH: FirmwareStateDispatch = host_state_dispatch;

#[inline(always)]
unsafe fn initialization_value(index: usize) -> u32 {
    #[cfg(target_os = "none")]
    {
        core::ptr::read_volatile((STATE_INIT_TABLE as *const u32).add(index))
    }

    #[cfg(not(target_os = "none"))]
    {
        // Raw words at 0x089ca6a0 and 0x089ca6a4 in the retail image.
        [0x5700_746c, 0x646c_726f][index - 1]
    }
}

/// Initializes the object's retained state once and returns its result word.
///
/// # Safety
///
/// `object` must be aligned and point to a writable object spanning `+0x90`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn object_state_initialize(object: *mut u8) -> u32 {
    if object.add(INITIALIZE_FLAG_OFFSET).read() == 0 {
        (OBJECT_STATE_GATEWAY_BLOCKING)(0x26, 1);
        let state = object.add(0x28);
        (FIRMWARE_STATE_DISPATCH)(object, state, 4, initialization_value(2));
        (FIRMWARE_STATE_DISPATCH)(object, state, 0, initialization_value(1));
        object.add(INITIALIZE_FLAG_OFFSET).write(1);
        (OBJECT_STATE_GATEWAY_TIMED)(0x26, 1000);
    }
    (object.add(RESULT_OFFSET) as *const u32).read()
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;
    
    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: [(u32, u32); 2] = [(0, 0); 2];
    static mut CALL_COUNT: usize = 0;
    static mut GATEWAY_CALLS: [(usize, usize); 2] = [(0, 0); 2];
    static mut GATEWAY_CALL_COUNT: usize = 0;

    unsafe extern "C" fn record_gateway(payload: usize, argument: usize) {
        GATEWAY_CALLS[GATEWAY_CALL_COUNT] = (payload, argument);
        GATEWAY_CALL_COUNT += 1;
    }


    unsafe extern "C" fn record_dispatch(_object: *mut u8, _state: *mut u8, selector: u32, value: u32) {
        CALLS[CALL_COUNT] = (selector, value);
        CALL_COUNT += 1;
    }

    #[test]
    fn initializes_once_and_returns_result_word() {
        let _lock = TEST_LOCK.lock();
        let mut object = [0u8; INITIALIZE_FLAG_OFFSET + 4];
        unsafe {
            (object.as_mut_ptr().add(RESULT_OFFSET) as *mut u32).write(0x1234_5678);
            FIRMWARE_STATE_DISPATCH = record_dispatch;
            CALL_COUNT = 0;
            OBJECT_STATE_GATEWAY_BLOCKING = record_gateway;
            OBJECT_STATE_GATEWAY_TIMED = record_gateway;
            GATEWAY_CALL_COUNT = 0;
            assert_eq!(object_state_initialize(object.as_mut_ptr()), 0x1234_5678);
            assert_eq!(CALL_COUNT, 2);
            assert_eq!(CALLS, [(4, 0x646c_726f), (0, 0x5700_746c)]);
            assert_eq!(GATEWAY_CALLS, [(0x26, 1), (0x26, 1000)]);
            assert_eq!(object[INITIALIZE_FLAG_OFFSET], 1);
            assert_eq!(object_state_initialize(object.as_mut_ptr()), 0x1234_5678);
            assert_eq!(CALL_COUNT, 2);
            FIRMWARE_STATE_DISPATCH = host_state_dispatch;
            OBJECT_STATE_GATEWAY_BLOCKING = host_gateway_request;
            OBJECT_STATE_GATEWAY_TIMED = host_gateway_request;
        }
    }

    #[test]
    fn initialized_object_skips_all_dispatches() {
        let _lock = TEST_LOCK.lock();
        let mut object = [0u8; INITIALIZE_FLAG_OFFSET + 4];
        unsafe {
            object[INITIALIZE_FLAG_OFFSET] = 0xff;
            (object.as_mut_ptr().add(RESULT_OFFSET) as *mut u32).write(7);
            FIRMWARE_STATE_DISPATCH = record_dispatch;
            CALL_COUNT = 0;
            OBJECT_STATE_GATEWAY_BLOCKING = record_gateway;
            OBJECT_STATE_GATEWAY_TIMED = record_gateway;
            GATEWAY_CALL_COUNT = 0;
            assert_eq!(object_state_initialize(object.as_mut_ptr()), 7);
            assert_eq!(CALL_COUNT, 0);
            FIRMWARE_STATE_DISPATCH = host_state_dispatch;
            assert_eq!(GATEWAY_CALL_COUNT, 0);
            OBJECT_STATE_GATEWAY_BLOCKING = host_gateway_request;
            OBJECT_STATE_GATEWAY_TIMED = host_gateway_request;
        }
    }
}
