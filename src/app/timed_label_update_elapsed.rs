//! Timed-label elapsed-time update: `FUN_081d1324` @ 0x081d1324.
//!
//! Raw extent 0x081d1324..0x081d13b4 is 144 bytes (140 code, one literal).
//! Two inbound plain BLs (0x0815cbac, 0x081d1000), no predicated BLs;
//! three outgoing plain BLs, no predicated BLs. The next real function
//! begins with push {r4,lr} at 0x081d13b4.
//! If TCSportTimer byte +0x4c is nonzero, sample Timer E, unsigned-divide
//! the wrapping delta by 1000, add it with wrapping to +8 and +12, and
//! replace the previous sample at +4. Subtract 120 from positive signed
//! +32 (without flooring at zero), then unsigned-clamp +8/+12 to one day.
//!
//! No target behavioral deviations. Ghidra's extra arguments are saved
//! scratch registers, not inputs. Unused stack copies are omitted. The
//! named singleton accessor has no Rust implementation in this worktree;
//! its verified firmware address remains a volatile function-pointer seam.
//! Hosts must supply an accessor; the timer uses its existing host seam.
//! Codegen review: LLVM adds a frame and initializes the timer scratch word,
//! uses BLX for the singleton seam, and omits unused delta/quotient copies.
//! Both direct ported calls, field offsets, wrapping additions, signed
//! countdown predication and unsigned clamp predication remain intact.

use crate::drivers::timer::read_usec_timer_into;
use crate::runtime::rt_div::__rt_udiv;

type SportTimerInstance = unsafe extern "C" fn() -> *mut u8;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_sport_timer_instance() -> *mut u8 {
    core::mem::transmute::<usize, SportTimerInstance>(0x0815_e1ac)()
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_sport_timer_instance() -> *mut u8 {
    panic!("sport timer instance requires firmware registry or a host seam");
}

#[cfg(target_os = "none")]
pub static mut SPORT_TIMER_INSTANCE: SportTimerInstance = firmware_sport_timer_instance;
#[cfg(not(target_os = "none"))]
pub static mut SPORT_TIMER_INSTANCE: SportTimerInstance = unavailable_sport_timer_instance;

/// # Safety
/// `this` names at least 36 writable word-aligned bytes. The accessor must
/// return a live object with readable byte +0x4c, even when disabled.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn timed_label_update_elapsed(this: *mut u32) {
    update_with_instance(this, core::ptr::read_volatile(core::ptr::addr_of!(SPORT_TIMER_INSTANCE)));
}

#[inline(always)]
unsafe fn update_with_instance(this: *mut u32, instance: SportTimerInstance) {
    if instance().add(0x4c).read_volatile() == 0 {
        return;
    }
    let mut now = 0;
    read_usec_timer_into(&mut now);
    let elapsed_ms = __rt_udiv(now.wrapping_sub(this.add(1).read_volatile()), 1000);
    for index in [2, 3] {
        this.add(index).write_volatile(this.add(index).read_volatile().wrapping_add(elapsed_ms));
    }
    this.add(1).write_volatile(now);
    let countdown = this.add(8).read_volatile() as i32;
    if countdown > 0 {
        this.add(8).write_volatile(countdown.wrapping_sub(120) as u32);
    }
    for index in [2, 3] {
        if this.add(index).read_volatile() > 86_400_000 {
            this.add(index).write_volatile(86_400_000);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static ENABLED: [u8; 77] = [0x80; 77];
    static DISABLED: [u8; 77] = [0; 77];
    unsafe extern "C" fn enabled() -> *mut u8 { ENABLED.as_ptr() as *mut u8 }
    unsafe extern "C" fn disabled() -> *mut u8 { DISABLED.as_ptr() as *mut u8 }

    #[test]
    fn disabled_preserves_entire_owner_even_above_clamp() {
        let mut words = [u32::MAX; 18];
        unsafe { update_with_instance(words.as_mut_ptr(), disabled) };
        assert_eq!(words, [u32::MAX; 18]);
    }

    #[test]
    fn wrapping_delta_truncation_countdown_and_post_add_clamp() {
        for (previous, now, delta) in [(0, 999, 0), (0, 1000, 1), (u32::MAX - 499, 500, 1), (1, 0, 4_294_967)] {
            for countdown in [i32::MIN, -1, 0, 1, 119, 120, 121, i32::MAX] {
                for (total, lap) in [(0, 7), (86_400_000, 86_399_999), (u32::MAX, u32::MAX - 1)] {
                    let _timer = crate::drivers::timer::configure_usec_timer_for_test(now, 0);
                    let mut words = [0xa5a5_a5a5; 18];
                    words[1] = previous;
                    words[2] = total;
                    words[3] = lap;
                    words[8] = countdown as u32;
                    let mut expected = words;
                    expected[1] = now;
                    expected[2] = total.wrapping_add(delta).min(86_400_000);
                    expected[3] = lap.wrapping_add(delta).min(86_400_000);
                    expected[8] = if countdown > 0 { (countdown - 120) as u32 } else { countdown as u32 };
                    unsafe { update_with_instance(words.as_mut_ptr(), enabled) };
                    assert_eq!(words, expected);
                }
            }
        }
    }
}
