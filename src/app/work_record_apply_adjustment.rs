//! Work-record adjustment — `FUN_081dceb8` @ `0x081dceb8`.
//! True extent: 36 bytes, ending at the next push at `0x081dcedc`.
//! Raw A32: one outgoing plain BL, no predicated outgoing BL; zero incoming
//! plain BL and two incoming predicated BL (0x081dcb10, 0x081dcc08).
//!
//! Calls 0x08140344 with the target at +0x74, day delta at +0x7c and
//! seconds-delta address +0x80, then marks +0x86 as applied unconditionally.
//! The callee copies its base day/seconds pair (+0x1c) to +0x24 and tail-calls
//! the day/seconds adder at 0x081b4d60. The exact class identity is unknown.
//! Deliberate deviations: target pointer words remain u32 on hosts; a host
//! callback replaces the unported retail callee. No target behavior change.

pub type ApplyAdjustment = unsafe extern "C" fn(*mut u8, i32, *const i32);

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_adjustment(_: *mut u8, _: i32, _: *const i32) {
    panic!("install work-record adjustment provider")
}
#[cfg(not(target_os = "none"))]
pub static mut APPLY_ADJUSTMENT: ApplyAdjustment = missing_adjustment;

/// # Safety
/// `record` must be word-aligned and readable/writable through +0x87. Its
/// +0x74 target pointer and adjustment fields must be valid for the provider.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn work_record_apply_adjustment(record: *mut u8) {
    let target = record.add(0x74).cast::<u32>().read() as usize as *mut u8;
    let days = record.add(0x7c).cast::<i32>().read();
    let seconds = record.add(0x80).cast::<i32>();
    #[cfg(target_os = "none")]
    let apply = core::mem::transmute::<usize, ApplyAdjustment>(0x0814_0344);
    #[cfg(not(target_os = "none"))]
    let apply = core::ptr::read_volatile(core::ptr::addr_of!(APPLY_ADJUSTMENT));
    apply(target, days, seconds);
    record.add(0x86).write(1);
}

#[cfg(test)]
mod tests {
    use super::*;

    // Behavioral model of the retail provider. Also alters its input flag,
    // making the wrapper's post-call mark ordering observable.
    unsafe extern "C" fn apply(target: *mut u8, days: i32, seconds: *const i32) {
        let words = target.cast::<i32>();
        let total = words.add(8).read().wrapping_add(seconds.read());
        let carry = total.div_euclid(86400);
        words.add(9).write(words.add(7).read().wrapping_add(days).wrapping_add(carry));
        words.add(10).write(total.rem_euclid(86400));
        seconds.cast::<u8>().add(6).cast_mut().write(0);
    }

    #[test]
    fn marks_after_apply_and_preserves_adjacent_flags_on_repeated_updates() {
        let Some(slab) = crate::testing::try_map_u32_slab(
            crate::testing::hints::WORK_RECORD_APPLY_ADJUSTMENT, 4096) else { return };
        unsafe {
            APPLY_ADJUSTMENT = apply;
            let target = slab.add(0x100);
            let mut record = [0xa5a5_a5a5u32; 34];
            record[0x74 / 4] = target as usize as u32;
            for &(base_day, base_seconds, days, seconds, expected_day, expected_seconds) in &[
                (10i32, 0i32, -2i32, -1i32, 7i32, 86399i32),
                (10, 86399, 2, 1, 13, 0),
                (i32::MAX, 0, 1, 0, i32::MIN, 0),
            ] {
                target.add(0x1c).cast::<i32>().write(base_day);
                target.add(0x20).cast::<i32>().write(base_seconds);
                record[0x7c / 4] = days as u32;
                record[0x80 / 4] = seconds as u32;
                let mut expected = record;
                expected[0x84 / 4] = 0xa501_a5a5;
                work_record_apply_adjustment(record.as_mut_ptr().cast());
                assert_eq!(target.add(0x24).cast::<i32>().read(), expected_day);
                assert_eq!(target.add(0x28).cast::<i32>().read(), expected_seconds);
                assert_eq!(record, expected);
            }
        }
    }
}
