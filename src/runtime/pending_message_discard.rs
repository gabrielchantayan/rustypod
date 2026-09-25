//! `pending_message_discard_next` — original: `FUN_080498b4` @ `0x080498b4`
//! (36 bytes; next function begins at 0x080498d8; 2 plain and 1 predicated
//! inbound `bl` call sites, binary-scanned).
//!
//! Discards the next pending message by taking one queue entry with removal
//! enabled and no output destinations. The unported take operation at
//! `0x0809ae9c` returns its queued result unchanged. Ghidra declares this
//! wrapper `void`, but raw code leaves the callee's `r0` intact at return, so
//! this port deliberately exposes that `u32` result.

type TakePendingMessage = unsafe extern "C" fn(
    u32,
    u32,
    *mut u8,
    *mut u8,
    *mut u8,
    *mut u8,
) -> u32;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn take_pending_message() -> TakePendingMessage {
    core::mem::transmute(0x0809_ae9cusize)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_take_pending_message(
    _remove: u32,
    _peek: u32,
    _first_data: *mut u8,
    _first_flags: *mut u8,
    _second_data: *mut u8,
    _second_flags: *mut u8,
) -> u32 {
    0
}

#[cfg(not(target_os = "none"))]
static mut TAKE_PENDING_MESSAGE: TakePendingMessage = missing_take_pending_message;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn take_pending_message() -> TakePendingMessage {
    core::ptr::read_volatile(core::ptr::addr_of!(TAKE_PENDING_MESSAGE))
}

#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn pending_message_discard_next() -> u32 {
    take_pending_message()(1, 0, core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut())
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: u32 = 0;
    static mut ARGS: (u32, u32, usize, usize, usize, usize) = (0, 0, 0, 0, 0, 0);
    static mut RESULT: u32 = 0;

    struct TestOps {
        _lock: MutexGuard<'static, ()>,
        saved: TakePendingMessage,
    }

    impl Drop for TestOps {
        fn drop(&mut self) {
            unsafe { TAKE_PENDING_MESSAGE = self.saved };
        }
    }

    unsafe extern "C" fn record_take(
        remove: u32,
        peek: u32,
        first_data: *mut u8,
        first_flags: *mut u8,
        second_data: *mut u8,
        second_flags: *mut u8,
    ) -> u32 {
        CALLS += 1;
        ARGS = (remove, peek, first_data as usize, first_flags as usize, second_data as usize, second_flags as usize);
        RESULT
    }
    fn install(result: u32) -> TestOps {
        let lock = OPS_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            let saved = core::ptr::read_volatile(core::ptr::addr_of!(TAKE_PENDING_MESSAGE));
            TAKE_PENDING_MESSAGE = record_take;
            CALLS = 0;
            ARGS = (0, 0, 0, 0, 0, 0);
            RESULT = result;
            TestOps { _lock: lock, saved }
        }
    }

    #[test]
    fn removes_one_pending_message_without_collecting_outputs() {
        let _ops = install(0x1234_5678);
        let result = unsafe { pending_message_discard_next() };
        unsafe {
            assert_eq!(result, 0x1234_5678);
            assert_eq!(CALLS, 1);
            assert_eq!(ARGS, (1, 0, 0, 0, 0, 0));
        }
    }

    #[test]
    fn preserves_an_empty_queue_result() {
        let _ops = install(0);
        assert_eq!(unsafe { pending_message_discard_next() }, 0);
        unsafe { assert_eq!(CALLS, 1) };
    }
}
