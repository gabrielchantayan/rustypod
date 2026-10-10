//! Apply packed date/time: `FUN_080985f4` @ `0x080985f4`.
//!
//! True extent: 116 bytes, `0x080985f4..0x08098668`, including the
//! four-byte literal at +112; the next real function starts at 0x08098668.
//! Raw A32 decoding verifies two plain outbound BLs, zero predicated BLs,
//! and one indirect BLXNE. Inbound: two plain BLs, zero predicated BLs.
//! Zero a 20-byte update record, copy input bytes 0..4 to offsets 2..6 and
//! the aligned halfword at +6 to +8, apply selection 0x7f, then invoke the
//! optional callback at 0x089ca300 +8. Return zero regardless of notification.
//! The callers' extra r1 mask is ignored by the original.
//!
//! Deliberate deviations: Rust stack initialization replaces the ported IRAM
//! zero-fill helper; volatile byte reads prevent LLVM memcpy substitution.
//! The already ported calendar updater is called directly.
//! Host builds substitute an optional notification slot for fixed device RAM.

use core::ptr;
use super::calendar_update_fields::calendar_update_fields;

type CalendarNotification = unsafe extern "C" fn();

#[cfg(not(target_os = "none"))]
static mut CALENDAR_NOTIFICATION: Option<CalendarNotification> = None;

/// # Safety
/// `datetime` must reference eight readable bytes and be halfword aligned.
/// Device callback slot +8 must be NULL or a valid no-argument C callback.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn calendar_apply_datetime(datetime: *const u8) -> u32 {
    let mut record = [0u32; 5];
    let bytes = record.as_mut_ptr().cast::<u8>();
    unsafe {
        for offset in 0..5 {
            bytes.add(offset + 2).write(ptr::read_volatile(datetime.add(offset)));
        }
        bytes.add(8).cast::<u16>().write(datetime.add(6).cast::<u16>().read());
        calendar_update_fields(bytes, 0x7f);
        #[cfg(target_os = "none")]
        {
            let callback = ptr::read(0x089c_a308usize as *const usize);
            if callback != 0 {
                core::mem::transmute::<usize, CalendarNotification>(callback)();
            }
        }
        #[cfg(not(target_os = "none"))]
        if let Some(callback) = ptr::read_volatile(ptr::addr_of!(CALENDAR_NOTIFICATION)) {
            callback();
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::calendar_update_fields::{INITIALIZE_RECORD, COMMIT_RECORD,
        APPLY_CALENDAR_ADJUSTMENT, CALENDAR_UPDATE_FIELDS_TEST_LOCK};

    static mut COMMITTED: [u8; 12] = [0; 12];
    static mut EVENTS: u32 = 0;
    unsafe extern "C" fn initialize(record: *mut u8) {
        record.write_bytes(0xa5, 12);
        EVENTS = 1;
    }
    unsafe extern "C" fn commit(record: *mut u8) {
        assert_eq!(EVENTS, 1);
        ptr::copy_nonoverlapping(record, ptr::addr_of_mut!(COMMITTED).cast(), 12);
        EVENTS = 2;
    }
    unsafe extern "C" fn unexpected_adjustment(_: i8, _: u8) {
        panic!("date/time application must not adjust UTC/DST");
    }
    unsafe extern "C" fn notify() {
        assert_eq!(EVENTS, 2);
        EVENTS = 3;
    }
    #[test]
    fn applies_all_fields_ignores_padding_and_notifies_after_commit() {
        let _lock = match CALENDAR_UPDATE_FIELDS_TEST_LOCK.lock() {
            Ok(guard) => guard,
            Err(error) => panic!("calendar test lock poisoned: {error}"),
        };
        unsafe {
            let previous = (INITIALIZE_RECORD, COMMIT_RECORD, APPLY_CALENDAR_ADJUSTMENT,
                CALENDAR_NOTIFICATION);
            INITIALIZE_RECORD = initialize;
            COMMIT_RECORD = commit;
            APPLY_CALENDAR_ADJUSTMENT = unexpected_adjustment;
            // Includes zero/max fields and a nonzero ignored byte +5.
            for input in [[0u16; 4], [0xffff; 4], [0x0201, 0x0403, 0xee05, 0x1234]] {
                for callback in [None, Some(notify as CalendarNotification)] {
                    CALENDAR_NOTIFICATION = callback;
                    assert_eq!(calendar_apply_datetime(input.as_ptr().cast()), 0);
                    let b = input.map(u16::to_le_bytes);
                    assert_eq!(COMMITTED, [b[3][0], b[3][1], b[2][0], b[1][1],
                        0xa5, 0xa5, 0xa5, 0xa5, b[1][0], b[0][1], b[0][0], 0xa5]);
                    assert_eq!(EVENTS, if callback.is_some() { 3 } else { 2 });
                }
            }
            (INITIALIZE_RECORD, COMMIT_RECORD, APPLY_CALENDAR_ADJUSTMENT,
                CALENDAR_NOTIFICATION) = previous;
        }
    }
}
