//! `callback_record_invoke` — original: `FUN_0837cafc` @ `0x0837cafc`.
//!
//! Raw `osos.dec` establishes the true 72-byte extent
//! `0x0837cafc..0x0837cb44`; the next separately entered function begins with
//! `push {r4, lr}` at `0x0837cb44`. A whole-image ARM immediate-branch decode
//! finds two inbound plain `bl` calls and no predicated `bl` calls.
//!
//! # Algorithm
//!
//! A non-null record with a non-null callback and a nonnegative call count
//! invokes the callback with its context word. A zero callback result poisons
//! the count to `-1`; every nonzero result increments it. Invalid records
//! return zero without changing memory.
//!
//! Deliberate deviation: the callback is an indirect `blx` through the record's
//! target-width code word, so host builds use a target-width dispatch seam.

/// Target-layout callback record consumed by [`callback_record_invoke`].
#[repr(C)]
pub struct CallbackRecord {
    pub callback: u32,
    pub context: u32,
    pub call_count: i32,
}

#[cfg(not(target_os = "none"))]
pub type CallbackRecordInvoke = unsafe extern "C" fn(u32, u32) -> u32;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_callback_record_invoke(_callback: u32, _context: u32) -> u32 {
    panic!("install callback-record invoke operation")
}

#[cfg(not(target_os = "none"))]
pub const DEFAULT_CALLBACK_RECORD_INVOKE: CallbackRecordInvoke = missing_callback_record_invoke;

/// Active host-test indirect-callback operation.
#[cfg(not(target_os = "none"))]
pub static mut CALLBACK_RECORD_INVOKE: CallbackRecordInvoke = DEFAULT_CALLBACK_RECORD_INVOKE;

/// Invokes a callback record while its call count remains nonnegative.
///
/// Original: `FUN_0837cafc` @ `0x0837cafc` (72 bytes; two inbound plain `bl`
/// calls and no predicated `bl` calls).
///
/// # Safety
///
/// When non-null, `record` must address a valid [`CallbackRecord`]. Its
/// callback code word must name a callable target when the count is nonnegative.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn callback_record_invoke(record: *mut CallbackRecord) -> u32 {
    if record.is_null() {
        return 0;
    }

    let record = unsafe { &mut *record };
    if record.callback == 0 || record.call_count < 0 {
        return 0;
    }

    #[cfg(target_os = "none")]
    let result = {
        let invoke: unsafe extern "C" fn(u32) -> u32 =
            unsafe { core::mem::transmute(record.callback as usize) };
        unsafe { invoke(record.context) }
    };
    #[cfg(not(target_os = "none"))]
    let result = {
        let invoke = unsafe {
            core::ptr::read_volatile(core::ptr::addr_of!(CALLBACK_RECORD_INVOKE))
        };
        unsafe { invoke(record.callback, record.context) }
    };
    record.call_count = if result == 0 { -1 } else { record.call_count.wrapping_add(1) };
    result
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::{Mutex, MutexGuard};

    static INVOKE_LOCK: Mutex<()> = Mutex::new(());
    static mut SEEN_CALLBACK: u32 = 0;
    static mut SEEN_CONTEXT: u32 = 0;
    static mut RESULT: u32 = 0;
    static mut CALLS: u32 = 0;

    unsafe extern "C" fn record_invoke(callback: u32, context: u32) -> u32 {
        SEEN_CALLBACK = callback;
        SEEN_CONTEXT = context;
        CALLS += 1;
        RESULT
    }

    fn install(result: u32) -> MutexGuard<'static, ()> {
        let guard = INVOKE_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            addr_of_mut!(SEEN_CALLBACK).write(0);
            addr_of_mut!(SEEN_CONTEXT).write(0);
            addr_of_mut!(RESULT).write(result);
            addr_of_mut!(CALLS).write(0);
            addr_of_mut!(CALLBACK_RECORD_INVOKE).write(record_invoke);
        }
        guard
    }

    fn restore(guard: MutexGuard<'static, ()>) {
        unsafe { addr_of_mut!(CALLBACK_RECORD_INVOKE).write(DEFAULT_CALLBACK_RECORD_INVOKE) };
        drop(guard);
    }

    #[test]
    fn invokes_live_record_and_increments_count_on_nonzero_result() {
        let guard = install(0x55);
        let mut record = CallbackRecord { callback: 0x1234_5678, context: 0xfeed_beef, call_count: 4 };
        assert_eq!(unsafe { callback_record_invoke(&mut record) }, 0x55);
        unsafe {
            assert_eq!(addr_of!(CALLS).read(), 1);
            assert_eq!(addr_of!(SEEN_CALLBACK).read(), 0x1234_5678);
            assert_eq!(addr_of!(SEEN_CONTEXT).read(), 0xfeed_beef);
        }
        assert_eq!(record.call_count, 5);
        restore(guard);
    }

    #[test]
    fn zero_result_poison_count_blocks_future_invocations() {
        let guard = install(0);
        let mut record = CallbackRecord { callback: 1, context: 2, call_count: 0 };
        assert_eq!(unsafe { callback_record_invoke(&mut record) }, 0);
        assert_eq!(record.call_count, -1);
        assert_eq!(unsafe { callback_record_invoke(&mut record) }, 0);
        unsafe { assert_eq!(addr_of!(CALLS).read(), 1) };
        restore(guard);
    }

    #[test]
    fn null_callback_and_negative_count_do_not_dispatch() {
        let guard = install(1);
        let mut null_callback = CallbackRecord { callback: 0, context: 2, call_count: 0 };
        let mut exhausted = CallbackRecord { callback: 1, context: 2, call_count: -1 };
        assert_eq!(unsafe { callback_record_invoke(core::ptr::null_mut()) }, 0);
        assert_eq!(unsafe { callback_record_invoke(&mut null_callback) }, 0);
        assert_eq!(unsafe { callback_record_invoke(&mut exhausted) }, 0);
        unsafe { assert_eq!(addr_of!(CALLS).read(), 0) };
        restore(guard);
    }
}
