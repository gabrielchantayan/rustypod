//! `record_dispatch_result` — original: `FUN_08080f18` @ `0x08080f18`
//! (68 bytes; the next distinct function begins at `0x08080f5c`).
//!
//! # Verified calls and algorithm
//!
//! Raw ARM words establish two outbound plain `bl` calls (`0x0827213c` and
//! `0x080ed6e8`) and no predicated outbound `bl`; four inbound direct plain
//! `bl` sites reach this entry, with no predicated inbound form. It clears a
//! 20-byte stack record, dispatches it through the unported target, and returns
//! the signed halfword at record offset `0x0c` only when that target returns
//! nonzero; otherwise it returns zero.
//!
//! # Deliberate deviations
//!
//! The dispatch target at `0x080ed6e8` has no recovered semantic identity.
//! Target builds call its verified address; host builds use a narrow callback
//! seam. Rust returns normally after the call rather than restoring ARM's
//! callee-saved registers explicitly.

/// ABI of the unported dispatch target at `0x080ed6e8`.
pub type RecordDispatch = unsafe extern "C" fn(*mut u8, u32, u32, *mut u32, u32) -> u32;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_record_dispatch(
    _record: *mut u8,
    _first: u32,
    _second: u32,
    _third_slot: *mut u32,
    _option: u32,
) -> u32 {
    0
}

/// Host seam for the unported retailOS dispatch target.
#[cfg(not(target_os = "none"))]
pub static mut RECORD_DISPATCH: RecordDispatch = missing_record_dispatch;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn record_dispatch_target() -> RecordDispatch {
    core::mem::transmute(0x080e_d6e8usize)
}

/// Dispatches a cleared transient record and returns its signed result field.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn record_dispatch_result(
    first: u32,
    second: u32,
    third: u32,
    option: u32,
) -> i32 {
    let mut record = [0u32; 5];
    unsafe { crate::util::zero_three_words_four_halfwords::zero_three_words_four_halfwords(record.as_mut_ptr()) };
    let mut third_slot = third;
    #[cfg(target_os = "none")]
    let dispatched = unsafe {
        record_dispatch_target()(record.as_mut_ptr().cast(), first, second, &mut third_slot, option)
    };
    #[cfg(not(target_os = "none"))]
    let dispatched = unsafe { RECORD_DISPATCH(record.as_mut_ptr().cast(), first, second, &mut third_slot, option) };

    if dispatched == 0 {
        0
    } else {
        unsafe {
            core::ptr::read_unaligned(record.as_ptr().cast::<u8>().add(12).cast::<i16>()) as i32
        }
    }
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;

    static TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    static mut CALL: (*mut u8, u32, u32, u32, u32) = (core::ptr::null_mut(), 0, 0, 0, 0);
    static mut DISPATCH_RESULT: u32 = 0;
    static mut RECORD_VALUE: i16 = 0;

    unsafe extern "C" fn record_dispatch(
        record: *mut u8,
        first: u32,
        second: u32,
        third_slot: *mut u32,
        option: u32,
    ) -> u32 {
        unsafe {
            CALL = (record, first, second, third_slot.read(), option);
            assert_eq!(core::slice::from_raw_parts(record, 20), &[0; 20]);
            core::ptr::write_unaligned(record.add(12).cast::<i16>(), RECORD_VALUE);
            DISPATCH_RESULT
        }
    }

    #[test]
    fn returns_signed_record_field_only_after_successful_dispatch() {
        let _guard = TEST_LOCK.lock();
        unsafe {
            RECORD_DISPATCH = record_dispatch;
            DISPATCH_RESULT = 1;
            RECORD_VALUE = -1234;
        }
        assert_eq!(unsafe { record_dispatch_result(1, 2, 3, 4) }, -1234);
        unsafe {
            assert_eq!((CALL.1, CALL.2, CALL.3, CALL.4), (1, 2, 3, 4));
            DISPATCH_RESULT = 0;
            RECORD_VALUE = 42;
        }
        assert_eq!(unsafe { record_dispatch_result(5, 6, 7, 8) }, 0);
    }
}
