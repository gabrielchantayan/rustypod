//! Rata Die day number -> day of month: `FUN_080b3fbc` @ 0x080b3fbc.
//!
//! # Verified extent and calls
//!
//! Raw `osos.dec` words establish the exact 20-byte extent
//! `0x080b3fbc..0x080b3fd0`: `push {r1-r3,lr}; mov r1,sp; bl 0x0807eafc;
//! ldrb r0,[sp,#3]; pop {r2,r3,pc}`. The next real entry is the
//! `ldr r0,[pc,#0]` / `bx r0` veneer at 0x080b3fd0. The body has one plain
//! `bl` and no predicated `bl`; raw branch decoding finds three plain inbound
//! `bl` call sites (0x08140fb4, 0x08141468, 0x081ca678) and none predicated.
//!
//! # Algorithm
//!
//! The wrapper passes a stack-backed packed [`DateTime`] to the existing
//! `FUN_0807eafc` calendar-converter seam, then returns its +3 day-of-month
//! byte. The original does not initialize the other nine stack bytes.
//!
//! # Deliberate deviations
//!
//! [`core::mem::MaybeUninit`] models the uninitialized scratch record while
//! avoiding an unnecessary initialization in Rust. Only the callee-written
//! `day` field is read.

use core::mem::MaybeUninit;

use super::datetime::DateTime;
use super::unix_to_datetime::day_number_to_datetime;

/// day_number_day_of_month — original: `FUN_080b3fbc` @ 0x080b3fbc
/// (**20 bytes, 0x080b3fbc..0x080b3fd0; 3 plain inbound `bl`, no predicated
/// `bl` — verified from `osos.dec`).
///
/// Converts `day_number` through `FUN_0807eafc` and returns the packed
/// calendar record's day-of-month byte. The calendar converter must write
/// that field; as in retailOS, no other scratch-record byte is initialized.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn day_number_day_of_month(day_number: u32) -> u8 {
    let mut datetime = MaybeUninit::<DateTime>::uninit();
    day_number_to_datetime()(day_number, datetime.as_mut_ptr());
    (*datetime.as_ptr()).day
}

#[cfg(test)]
mod tests {
    extern crate std;

    use core::sync::atomic::{AtomicU32, Ordering};

    use super::*;
    use super::super::unix_to_datetime::{DayNumberToDateTimeFn, DAY_NUMBER_TO_DATETIME, DAY_NUMBER_TO_DATETIME_TEST_LOCK};

    static LAST_DAY_NUMBER: AtomicU32 = AtomicU32::new(0);
    static CALLS: AtomicU32 = AtomicU32::new(0);

    unsafe extern "C" fn calendar_model(day_number: u32, out: *mut DateTime) {
        LAST_DAY_NUMBER.store(day_number, Ordering::Relaxed);
        CALLS.fetch_add(1, Ordering::Relaxed);
        (*out).day = day_number.wrapping_mul(37).wrapping_add(11) as u8;
    }

    #[test]
    fn returns_the_converter_day_byte_for_boundary_day_numbers() {
        let _guard = DAY_NUMBER_TO_DATETIME_TEST_LOCK.lock().unwrap();
        unsafe {
            let saved: DayNumberToDateTimeFn = DAY_NUMBER_TO_DATETIME;
            DAY_NUMBER_TO_DATETIME = calendar_model;
            CALLS.store(0, Ordering::Relaxed);

            for day_number in [0, 1, 7, 719_163, u32::MAX] {
                assert_eq!(day_number_day_of_month(day_number), day_number.wrapping_mul(37).wrapping_add(11) as u8);
                assert_eq!(LAST_DAY_NUMBER.load(Ordering::Relaxed), day_number);
            }

            assert_eq!(CALLS.load(Ordering::Relaxed), 5);
            DAY_NUMBER_TO_DATETIME = saved;
        }
    }
}
