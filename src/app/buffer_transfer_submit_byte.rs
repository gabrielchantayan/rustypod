//! `buffer_transfer_submit_byte` — original: `FUN_081e2ba8` @ `0x081e2ba8`
//! (188-byte A32 instruction body; its 12-byte literal pool is not code).
//!
//! # Verified calls and algorithm
//!
//! Raw ARM establishes the body at `0x081e2ba8..0x081e2c63`; literals occupy
//! `0x081e2c64..0x081e2c6f`, and the next real function starts at `0x081e2c70`.
//! It makes six plain unconditional `bl` calls and no predicated `bl` calls.
//! If `state+0x2d4` supplies a transfer dispatcher and the outstanding byte at
//! `state+0x2e3` is at most three, it dispatches operation 8/kind 6 with the
//! supplied byte. A null dispatch result becomes status 28. Otherwise the byte
//! is published under the verified lock before the request is processed with
//! timeout 3000. Four or more outstanding transfers cancel the state and emit
//! error `(8, 0, 13, 4)`; that check also runs after a skipped or completed
//! dispatch.
//!
//! # Deliberate deviations
//!
//! The six targets and the locked global byte have no recovered semantic
//! identities in `names.yaml`. Target builds call their verified addresses;
//! host builds use a narrow operations seam. Rust returns normally after the
//! error callback rather than reproducing the ARM epilogue.

/// ABI of the unported dispatch target at `0x080f6da0`.
pub type BufferTransferDispatch = unsafe extern "C" fn(*mut u8, u32, u32, u32, *const u8, u32, *mut u8) -> *mut u8;
/// ABI of the unported request processor at `0x081e2ff4`.
pub type BufferTransferProcess = unsafe extern "C" fn(*mut u8, u32, u32) -> u32;
/// ABI of the unported cancellation target at `0x081e2ae8`.
pub type BufferTransferCancel = unsafe extern "C" fn(*mut u8, u32, u32);
/// ABI of the unported error target at `0x08257b60`.
pub type BufferTransferError = unsafe extern "C" fn(u32, u32, u32, u32);
pub type BufferTransferLock = unsafe extern "C" fn(*mut u8);
pub type BufferTransferStoreByte = unsafe extern "C" fn(u8);

pub struct BufferTransferSubmitByteOps {
    pub dispatch: BufferTransferDispatch,
    pub process: BufferTransferProcess,
    pub cancel: BufferTransferCancel,
    pub error: BufferTransferError,
    pub lock: BufferTransferLock,
    pub unlock: BufferTransferLock,
    pub store_byte: BufferTransferStoreByte,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_dispatch(_dispatcher: *mut u8, _zero: u32, _operation: u32, _kind: u32, _byte: *const u8, _count: u32, _state: *mut u8) -> *mut u8 { core::ptr::null_mut() }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_process(_request: *mut u8, _zero: u32, _timeout: u32) -> u32 { 0 }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_cancel(_state: *mut u8, _zero: u32, _zero_again: u32) {}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_error(_operation: u32, _zero: u32, _error: u32, _count: u32) {}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_lock(_lock: *mut u8) {}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_store_byte(_byte: u8) {}

#[cfg(not(target_os = "none"))]
pub const DEFAULT_BUFFER_TRANSFER_SUBMIT_BYTE_OPS: BufferTransferSubmitByteOps = BufferTransferSubmitByteOps {
    dispatch: missing_dispatch, process: missing_process, cancel: missing_cancel, error: missing_error,
    lock: missing_lock, unlock: missing_lock, store_byte: missing_store_byte,
};
#[cfg(not(target_os = "none"))]
pub static mut BUFFER_TRANSFER_SUBMIT_BYTE_OPS: BufferTransferSubmitByteOps = DEFAULT_BUFFER_TRANSFER_SUBMIT_BYTE_OPS;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn target_ops() -> BufferTransferSubmitByteOps {
    unsafe {
        BufferTransferSubmitByteOps {
            dispatch: core::mem::transmute(0x080f_6da0usize), process: core::mem::transmute(0x081e_2ff4usize),
            cancel: core::mem::transmute(0x081e_2ae8usize), error: core::mem::transmute(0x0825_7b60usize),
            lock: core::mem::transmute(0x0826_1e20usize), unlock: core::mem::transmute(0x0826_1e24usize),
            store_byte: store_target_byte,
        }
    }
}
#[cfg(target_os = "none")]
unsafe extern "C" fn store_target_byte(byte: u8) { unsafe { core::ptr::write_volatile((0x089c_ca14usize as *mut u8).add(3), byte) } }

/// Submits one byte through the transfer dispatcher and applies its outstanding-transfer limit.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn buffer_transfer_submit_byte(state: *mut u8, byte: u32) -> u32 {
    #[cfg(target_os = "none")]
    let ops = unsafe { target_ops() };
    #[cfg(not(target_os = "none"))]
    let ops = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(BUFFER_TRANSFER_SUBMIT_BYTE_OPS)) };
    let mut status = 11;
    let dispatcher = unsafe { core::ptr::read_unaligned(state.add(0x2d4).cast::<*mut u8>()) };
    if !dispatcher.is_null() && unsafe { state.add(0x2e3).read() } <= 3 {
        let submitted_byte = byte as u8;
        let request = unsafe { (ops.dispatch)(dispatcher, 0, 8, 6, &submitted_byte, 1, state) };
        if request.is_null() {
            status = 28;
        } else {
            unsafe { (ops.lock)(0x08ac_88a0usize as *mut u8) };
            unsafe { (ops.store_byte)(submitted_byte) };
            unsafe { (ops.unlock)(0x08ac_88a0usize as *mut u8) };
            status = unsafe { (ops.process)(request, 0, 3000) };
        }
    }
    if unsafe { state.add(0x2e3).read() } >= 4 {
        unsafe { (ops.cancel)(state, 0, 0) };
        unsafe { (ops.error)(8, 0, 13, 4) };
    }
    status
}

#[cfg(test)]
extern crate std;
#[cfg(test)]
mod tests {
    use super::*;
    static LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    static mut EVENTS: [u32; 8] = [0; 8];
    static mut EVENT_COUNT: usize = 0;
    unsafe extern "C" fn dispatch(_d: *mut u8, _z: u32, operation: u32, kind: u32, byte: *const u8, count: u32, _s: *mut u8) -> *mut u8 { unsafe { EVENTS[EVENT_COUNT] = operation | (kind << 8) | ((*byte as u32) << 16) | (count << 24); EVENT_COUNT += 1; 1usize as *mut u8 } }
    unsafe extern "C" fn null_dispatch(_d: *mut u8, _z: u32, _o: u32, _k: u32, _b: *const u8, _c: u32, _s: *mut u8) -> *mut u8 { core::ptr::null_mut() }
    unsafe extern "C" fn process(_r: *mut u8, _z: u32, timeout: u32) -> u32 { unsafe { EVENTS[EVENT_COUNT] = timeout; EVENT_COUNT += 1; 0x55 } }
    unsafe extern "C" fn cancel(_s: *mut u8, _z: u32, _zz: u32) { unsafe { EVENTS[EVENT_COUNT] = 0xc; EVENT_COUNT += 1 } }
    unsafe extern "C" fn error(a: u32, b: u32, c: u32, d: u32) { unsafe { EVENTS[EVENT_COUNT] = a | (b << 8) | (c << 16) | (d << 24); EVENT_COUNT += 1 } }
    unsafe extern "C" fn lock(_p: *mut u8) { unsafe { EVENTS[EVENT_COUNT] = 1; EVENT_COUNT += 1 } }
    unsafe extern "C" fn unlock(_p: *mut u8) { unsafe { EVENTS[EVENT_COUNT] = 2; EVENT_COUNT += 1 } }
    unsafe extern "C" fn store(byte: u8) { unsafe { EVENTS[EVENT_COUNT] = byte as u32; EVENT_COUNT += 1 } }
    unsafe fn install() { BUFFER_TRANSFER_SUBMIT_BYTE_OPS = BufferTransferSubmitByteOps { dispatch, process, cancel, error, lock, unlock, store_byte: store }; EVENT_COUNT = 0; }
    #[test]
    fn submits_byte_under_lock_and_returns_processor_status() {
        let _guard = LOCK.lock(); unsafe { install(); }
        let mut state = [0u8; 0x2e4]; unsafe { core::ptr::write_unaligned(state.as_mut_ptr().add(0x2d4).cast::<*mut u8>(), 1usize as *mut u8); }
        assert_eq!(unsafe { buffer_transfer_submit_byte(state.as_mut_ptr(), 0xab) }, 0x55);
        unsafe { assert_eq!(&EVENTS[..EVENT_COUNT], &[0x01ab_0608, 1, 0xab, 2, 3000]); }
    }
    #[test]
    fn null_request_returns_28_without_locking_or_processing() {
        let _guard = LOCK.lock(); unsafe { install(); BUFFER_TRANSFER_SUBMIT_BYTE_OPS.dispatch = null_dispatch; }
        let mut state = [0u8; 0x2e4]; unsafe { core::ptr::write_unaligned(state.as_mut_ptr().add(0x2d4).cast::<*mut u8>(), 1usize as *mut u8); }
        assert_eq!(unsafe { buffer_transfer_submit_byte(state.as_mut_ptr(), 0xab) }, 28);
        unsafe { assert_eq!(&EVENTS[..EVENT_COUNT], &[]); }
    }
    #[test]
    fn null_dispatch_is_status_28_and_limit_cancels_even_without_dispatcher() {
        let _guard = LOCK.lock(); unsafe { install(); }
        let mut state = [0u8; 0x2e4]; state[0x2e3] = 4;
        assert_eq!(unsafe { buffer_transfer_submit_byte(state.as_mut_ptr(), 0xff) }, 11);
        unsafe { assert_eq!(&EVENTS[..EVENT_COUNT], &[0xc, 0x040d_0008]); }
    }
}
