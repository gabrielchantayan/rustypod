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

/// Read the next pending message result without consuming its queue entry.
///
/// Original: `FUN_08049a2c` @ `0x08049a2c`; true size 36 bytes, ending
/// before the next function at `0x08049a50`. Raw-word scan verifies two
/// incoming plain BLs, zero predicated BLs, and one outgoing plain BL.
/// Calls the existing `0x0809ae9c` seam with remove=0, peek=0 and four
/// null output pointers: select (read_index + 1) % 16, return its result,
/// and leave the queue and payload ownership unchanged; empty returns zero.
/// Deliberate deviation: expose the preserved r0 as u32, not Ghidra's void.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn pending_message_next_result() -> u32 {
    take_pending_message()(0, 0, core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut())
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static OPS_LOCK: Mutex<()> = Mutex::new(());

    struct TestOps {
        _lock: MutexGuard<'static, ()>,
        saved: TakePendingMessage,
    }

    impl Drop for TestOps {
        fn drop(&mut self) {
            unsafe { TAKE_PENDING_MESSAGE = self.saved };
        }
    }

    fn install(result: u32) -> TestOps {
        let lock = OPS_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            let saved = core::ptr::read_volatile(core::ptr::addr_of!(TAKE_PENDING_MESSAGE));
            TAKE_PENDING_MESSAGE = queue_take;
            QUEUE = [0; 16];
            READ_INDEX = 0;
            WRITE_INDEX = 1;
            QUEUE[1] = result;
            TestOps { _lock: lock, saved }
        }
    }


    static mut QUEUE: [u32; 16] = [0; 16];
    static mut READ_INDEX: usize = 0;
    static mut WRITE_INDEX: usize = 0;

    // Reference the retail queue's selection/removal rules rather than
    // echoing the wrapper arguments. Null destinations require no payloads.
    unsafe extern "C" fn queue_take(
        remove: u32,
        peek: u32,
        _first_data: *mut u8,
        _first_flags: *mut u8,
        _second_data: *mut u8,
        _second_flags: *mut u8,
    ) -> u32 {
        if remove != 0 && peek != 0 { return 0x44; }
        if READ_INDEX == WRITE_INDEX { return 0; }
        let index = if peek == 0 { (READ_INDEX + 1) % 16 } else { WRITE_INDEX };
        let result = QUEUE[index];
        if remove != 0 {
            READ_INDEX = index;
            QUEUE[index] = 0;
        }
        result
    }

    #[test]
    fn next_result_preserves_queue_across_wraparound_and_discard() {
        let _ops = install(0);
        unsafe {
            TAKE_PENDING_MESSAGE = queue_take;
            for read_index in [0, 14, 15] {
                QUEUE = [0; 16];
                READ_INDEX = read_index;
                WRITE_INDEX = (read_index + 2) % 16;
                QUEUE[(read_index + 1) % 16] = 0x2400_009b;
                QUEUE[WRITE_INDEX] = 0xffff_ffff;
                assert_eq!(pending_message_next_result(), 0x2400_009b);
                assert_eq!(pending_message_next_result(), 0x2400_009b);
                assert_eq!(READ_INDEX, read_index);
                assert_eq!(pending_message_discard_next(), 0x2400_009b);
                assert_eq!(pending_message_next_result(), 0xffff_ffff);
                assert_eq!(pending_message_discard_next(), 0xffff_ffff);
                assert_eq!(pending_message_next_result(), 0);
                assert_eq!(READ_INDEX, WRITE_INDEX);
            }
        }
    }

    #[test]
    fn zero_result_is_not_consumed_or_skipped() {
        let _ops = install(0);
        unsafe {
            TAKE_PENDING_MESSAGE = queue_take;
            QUEUE = [0; 16];
            READ_INDEX = 15;
            WRITE_INDEX = 1;
            QUEUE[1] = 0x8000_0000;
            assert_eq!(pending_message_next_result(), 0);
            assert_eq!(READ_INDEX, 15);
            assert_eq!(pending_message_discard_next(), 0);
            assert_eq!(pending_message_next_result(), 0x8000_0000);
        }
    }
}
