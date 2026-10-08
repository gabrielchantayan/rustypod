//! `dma_control_transition` — `FUN_08107a00` @ **0x08107a00**.
//! True extent: 144 bytes, ending at the next function's push at 0x08107a90.
//! Raw aligned A32 decoding verifies two incoming plain BLs (0x08107e48,
//! 0x08107e98), zero predicated callers, and four outgoing plain BLs:
//! timer-read at 0x08107a1c/0x08107a58 and elapsed at 0x08107a40/0x08107a7c.
//!
//! Nonzero mode ORs bit 7 into IODMA control +0x804 and waits while both
//! status +0x14 bit 6 and control bit 2 are clear. Zero mode ORs bit 8 and
//! waits while both bits are set. Each path samples the timer once and
//! stops on completion or a 100-us timeout, always returning one. The
//! context argument is unused. Both callers bracket DMA channel operations.
//!
//! Deliberate deviations: share the two polling paths and use the existing
//! IRAM timer veneer ports (0x08037e20/0x08037eb8), whose literal targets
//! 0x22001edc/0x22001ee8 mirror osos 0x08001edc/0x08001ee8. Private generic
//! timer callbacks and register pointers permit deterministic host tests;
//! production accesses remain aligned volatile words, with no allocation.

use crate::drivers::timer::{iram_usec_timer_elapsed_veneer, iram_usec_timer_read_veneer};

#[inline(always)]
unsafe fn transition_with_timer(
    mode: u32,
    status: *const u32,
    control: *mut u32,
    read_timer: impl FnOnce() -> u32,
    mut elapsed: impl FnMut(u32, u32) -> bool,
) -> u32 {
    let enabling = mode != 0;
    let old = control.read_volatile();
    control.write_volatile(old | if enabling { 0x80 } else { 0x100 });
    let start = read_timer();
    loop {
        let status_set = status.read_volatile() & 0x40 != 0;
        if status_set == enabling {
            break;
        }
        let control_set = control.read_volatile() & 4 != 0;
        if control_set == enabling {
            break;
        }
        if elapsed(start, 100) {
            break;
        }
    }
    1
}

/// Requests an IODMA control transition; timeout is not reported as failure.
///
/// # Safety
/// The S5L8702 IODMA controller and microsecond timer must be initialized.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn dma_control_transition(_context: *mut u8, mode: u32) -> u32 {
    transition_with_timer(
        mode,
        0x3840_0014 as *const u32,
        0x3840_0804 as *mut u32,
        || iram_usec_timer_read_veneer(),
        |start, interval| iram_usec_timer_elapsed_veneer(start, interval),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn either_completion_bit_stops_polling_and_preserves_other_control_bits() {
        for mode in [0, 1, 2, u32::MAX] {
            for status_set in [false, true] {
                for control_set in [false, true] {
                    let status = if status_set { 0x40 } else { 0 };
                    let initial = 0xa500_0200 | if control_set { 4 } else { 0 };
                    let mut control = initial;
                    let mut polls = 0;
                    let result = unsafe {
                        transition_with_timer(mode, &status, &mut control, || 73,
                            |start, interval| {
                                assert_eq!((start, interval), (73, 100));
                                polls += 1;
                                true
                            })
                    };
                    let enabling = mode != 0;
                    assert_eq!(result, 1);
                    assert_eq!(control, initial | if enabling { 0x80 } else { 0x100 });
                    assert_eq!(polls, u32::from(status_set != enabling && control_set != enabling));
                }
            }
        }
    }

    #[test]
    fn hardware_transition_after_poll_stops_without_another_deadline_check() {
        for mode in [0, 1] {
            for complete_via_status in [false, true] {
                let mut status: u32 = if mode == 0 { 0x40 } else { 0 };
                let mut control: u32 = if mode == 0 { 4 } else { 0 };
                let status_ptr = &mut status as *mut u32;
                let control_ptr = &mut control as *mut u32;
                let mut polls = 0;
                let result = unsafe {
                    transition_with_timer(mode, status_ptr, control_ptr, || 0xffff_fff0,
                        |start, interval| {
                            assert_eq!((start, interval), (0xffff_fff0, 100));
                            polls += 1;
                            assert_eq!(polls, 1);
                            if complete_via_status {
                                status_ptr.write_volatile(if mode == 0 { 0 } else { 0x40 });
                            } else {
                                let value = control_ptr.read_volatile();
                                control_ptr.write_volatile(if mode == 0 { value & !4 } else { value | 4 });
                            }
                            false
                        })
                };
                assert_eq!(result, 1);
                assert_eq!(polls, 1);
            }
        }
    }

    #[test]
    fn timeout_at_wrapping_deadline_returns_success_with_busy_bits_unchanged() {
        for mode in [0, 1] {
            let status = if mode == 0 { 0x40 } else { 0 };
            let mut control = if mode == 0 { 4 } else { 0 };
            let mut polls = 0;
            let result = unsafe {
                transition_with_timer(mode, &status, &mut control, || 0xffff_fff0,
                    |start, interval| {
                        polls += 1;
                        let now = if polls == 1 { 0x53u32 } else { 0x54u32 };
                        now.wrapping_sub(start) >= interval
                    })
            };
            assert_eq!(polls, 2);
            assert_eq!(result, 1);
            assert_eq!(control, if mode == 0 { 0x104 } else { 0x80 });
        }
    }
}
