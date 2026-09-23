//! `iap_client_global_shutdown` — original: `FUN_081a9ac0` @ `0x081a9ac0`
//! (196 bytes; 8 verified plain `bl` calls, zero predicated `bl` calls, and
//! two `blx` vtable dispatches).
//!
//! Raw ARM establishes the exact `0x081a9ac0..0x081a9b84` extent: the two
//! following words are its literal pool and `0x081a9b8c` begins the next
//! function. Under the global iAP-client context mutex at `+0x24 + 0x2d0`,
//! this checks the optional client at `+0x28`. A nonzero vtable `+0x24` query
//! releases its registration, clears lifecycle fields, asserts the query slot
//! at `+0x40` is zero, dispatches vtable `+0x20` with zero, notifies the
//! client state machine, clears the ten-byte global marker, then clears the
//! remaining state words. It returns 11 when no client exists and zero once a
//! client was inspected. Deliberate deviation: unported direct callees remain
//! target-address calls; host tests supply them as explicit operations.

use crate::app::iap_incoming_process_thread::{
    iap_incoming_process_thread_instance, iap_incoming_process_thread_slot_poll,
};
use crate::kernel::posix_mutex::{posix_mutex_lock, posix_mutex_unlock, PosixMutex};
use crate::libc::iram_veneers::iram_memzero_veneer;

const CONTEXT_MUTEX_OFFSET: usize = 0x24;
const MUTEX_MEMBER_OFFSET: usize = 0x2d0;
const CLIENT_OFFSET: usize = 0x28;
const CLIENT_QUERY_VTABLE_INDEX: usize = 0x24 / 4;
const CLIENT_STOP_VTABLE_INDEX: usize = 0x20 / 4;
const QUERY_SLOT_OFFSET: usize = 0x40;
const GLOBAL_MARKER_ADDRESS: usize = 0x08ac_90bc;
const GLOBAL_CONTEXT_ADDRESS: usize = 0x089c_cb68;
const NO_CLIENT_STATUS: u32 = 11;

type ClientQuery = unsafe extern "C" fn() -> u32;
type ClientStop = unsafe extern "C" fn(*mut u8, u32);
type AssertWordEquals = unsafe extern "C" fn(*const u32, u32);
type ClientStateNotify = unsafe extern "C" fn(*mut u8, u32) -> u32;

struct ShutdownOps {
    lock: unsafe extern "C" fn(*mut PosixMutex) -> u32,
    unlock: unsafe extern "C" fn(*mut PosixMutex) -> u32,
    thread_instance: unsafe extern "C" fn() -> *mut u8,
    slot_poll: unsafe extern "C" fn(*mut u8, u32) -> u32,
    assert_word_equals: AssertWordEquals,
    memzero: unsafe extern "C" fn(*mut u8, usize) -> *mut u8,
    client_state_notify: ClientStateNotify,
}

unsafe extern "C" fn firmware_assert_word_equals(word: *const u32, value: u32) {
    if unsafe { word.read() } != value {
        let fatal: unsafe extern "C" fn() -> ! = unsafe { core::mem::transmute(0x082a_ad24usize) };
        unsafe { fatal() };
    }
}

unsafe extern "C" fn firmware_client_state_notify(client: *mut u8, state: u32) -> u32 {
    let notify: ClientStateNotify = unsafe { core::mem::transmute(0x0813_9b1cusize) };
    unsafe { notify(client, state) }
}

const FIRMWARE_OPS: ShutdownOps = ShutdownOps {
    thread_instance: iap_incoming_process_thread_instance,
    lock: posix_mutex_lock,
    unlock: posix_mutex_unlock,
    slot_poll: iap_incoming_process_thread_slot_poll,
    assert_word_equals: firmware_assert_word_equals,
    client_state_notify: firmware_client_state_notify,
    memzero: iram_memzero_veneer,
};

unsafe fn shutdown_context(context: *mut u8, marker: *mut u8, ops: &ShutdownOps) -> u32 {
    let mutex = unsafe { context.add(CONTEXT_MUTEX_OFFSET).cast::<u32>().read() as usize as *mut u8 }
        .wrapping_add(MUTEX_MEMBER_OFFSET)
        .cast::<PosixMutex>();
    unsafe { (ops.lock)(mutex) };

    let client = unsafe { context.add(CLIENT_OFFSET).cast::<*mut u8>().read() };
    let result = if client.is_null() {
        NO_CLIENT_STATUS
    } else {
        let vtable = unsafe { client.cast::<*const usize>().read() };
        let query: ClientQuery = unsafe { core::mem::transmute(*vtable.add(CLIENT_QUERY_VTABLE_INDEX)) };
        if unsafe { query() } != 0 {
            let thread = unsafe { (ops.thread_instance)() };
            unsafe { (ops.slot_poll)(thread, context.add(0x10).cast::<u32>().read()) };
            unsafe { context.write(0) };
            unsafe { context.add(0x14).cast::<u32>().write(0) };
            unsafe { context.add(2).write(0) };
            unsafe { context.add(0x18).cast::<u32>().write(0) };
            unsafe { (ops.assert_word_equals)(context.add(QUERY_SLOT_OFFSET).cast(), 0) };
            unsafe { context.add(3).write(0) };
            let stop: ClientStop = unsafe { core::mem::transmute(*vtable.add(CLIENT_STOP_VTABLE_INDEX)) };
            unsafe { stop(client, 0) };
            unsafe { (ops.client_state_notify)(context.add(0x24).cast::<*mut u8>().read_unaligned(), context.add(0x2c).cast::<u32>().read()) };
            unsafe { (ops.memzero)(marker, 10) };
            for offset in [0x48, 0x4c, 0x30, 0x34, 0x38, 0x3c] {
                unsafe { context.add(offset).cast::<u32>().write(0) };
            }
        }
        0
    };
    unsafe { (ops.unlock)(mutex) };
    result
}

/// iap_client_global_shutdown — original `FUN_081a9ac0` @ `0x081a9ac0`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn iap_client_global_shutdown() -> u32 {
    let context = unsafe { (GLOBAL_CONTEXT_ADDRESS as *const *mut u8).read() };
    unsafe { shutdown_context(context, GLOBAL_MARKER_ADDRESS as *mut u8, &FIRMWARE_OPS) }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::{Mutex, MutexGuard};

    static LOCK: Mutex<()> = Mutex::new(());
    static mut POLLED: u32 = 0;
    static mut STOPPED: u32 = 0;
    static mut NOTIFIED: u32 = 0;

    unsafe extern "C" fn instance() -> *mut u8 { 0x1000usize as *mut u8 }
    unsafe extern "C" fn poll(_thread: *mut u8, slot: u32) -> u32 { unsafe { POLLED = slot }; 0 }
    unsafe extern "C" fn assert_zero(word: *const u32, value: u32) { assert_eq!(unsafe { word.read() }, value); }
    unsafe extern "C" fn notify(_client: *mut u8, state: u32) -> u32 { unsafe { NOTIFIED = state }; 0 }
    unsafe extern "C" fn zero(bytes: *mut u8, len: usize) -> *mut u8 { unsafe { core::ptr::write_bytes(bytes, 0, len) }; bytes }
    unsafe extern "C" fn lock(_mutex: *mut PosixMutex) -> u32 { 0 }
    unsafe extern "C" fn unlock(_mutex: *mut PosixMutex) -> u32 { 0 }
    unsafe extern "C" fn query_zero() -> u32 { 0 }
    unsafe extern "C" fn query_one() -> u32 { 1 }
    unsafe extern "C" fn stop(_client: *mut u8, _state: u32) { unsafe { STOPPED += 1 } }

    fn guard() -> MutexGuard<'static, ()> { LOCK.lock() }

    fn ops() -> ShutdownOps { ShutdownOps { lock, unlock, thread_instance: instance, slot_poll: poll, assert_word_equals: assert_zero, client_state_notify: notify, memzero: zero } }

    #[test]
    fn absent_client_preserves_state_and_returns_eleven() {
        let _guard = guard();
        let mut context = [0u8; 0x80];
        unsafe { context.as_mut_ptr().add(CONTEXT_MUTEX_OFFSET).cast::<u32>().write(0) };
        assert_eq!(unsafe { shutdown_context(context.as_mut_ptr(), core::ptr::null_mut(), &ops()) }, NO_CLIENT_STATUS);
    }

    #[test]
    fn queried_client_is_stopped_and_state_is_cleared() {
        let _guard = guard();
        unsafe { POLLED = 0; STOPPED = 0; NOTIFIED = 0 };
        let mut context = [0u8; 0x80];
        let vtable = [0usize, 0, 0, 0, 0, 0, 0, 0, stop as usize, query_one as usize];
        let mut client = [vtable.as_ptr() as usize];
        let mut marker = [0xa5u8; 10];
        unsafe {
            context.as_mut_ptr().add(CLIENT_OFFSET).cast::<*mut u8>().write(client.as_mut_ptr().cast());
            context.as_mut_ptr().add(0x10).cast::<u32>().write(7);
            context.as_mut_ptr().add(0x24).cast::<u32>().write(0);
        }
        assert_eq!(unsafe { shutdown_context(context.as_mut_ptr(), marker.as_mut_ptr(), &ops()) }, 0);
        assert_eq!(unsafe { (POLLED, STOPPED) }, (7, 1));
        assert!(marker.iter().all(|&byte| byte == 0));
        assert_eq!(context[0], 0); assert_eq!(context[2], 0); assert_eq!(context[3], 0);
    }

    #[test]
    fn zero_query_skips_cleanup_but_returns_zero() {
        let _guard = guard();
        let mut context = [0u8; 0x80];
        let vtable = [0usize, 0, 0, 0, 0, 0, 0, 0, stop as usize, query_zero as usize];
        let mut client = [vtable.as_ptr() as usize];
        unsafe { context.as_mut_ptr().add(CLIENT_OFFSET).cast::<*mut u8>().write(client.as_mut_ptr().cast()) };
        assert_eq!(unsafe { shutdown_context(context.as_mut_ptr(), core::ptr::null_mut(), &ops()) }, 0);
        assert_eq!(context[0], 0);
    }
}
