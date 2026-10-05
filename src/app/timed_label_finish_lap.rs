//! Finish a timed-label lap: `FUN_081d0ff8` @ 0x081d0ff8.
//!
//! Raw extent [0x081d0ff8, 0x081d102c) is 52 executable bytes; the next
//! function starts with push {r4,r5,r6,lr}. Two inbound plain BLs at
//! 0x0815db68/0x0815e658 and two outbound plain BLs at 0x081d1000/0x081d100c;
//! no predicated BLs. Update elapsed time, append the lap word at +0x0c
//! through the embedded collection helper, reload that word into +0x10,
//! clear +0x0c and +0x20, and return 1 regardless of the append result.
//!
//! No target behavioral deviations. Reuse the existing elapsed-time port.
//! The unported helper at 0x081d0f74 allocates a four-byte value and submits
//! it through collection virtual slot +0x1c; retain it as a firmware seam.
//! Host builds require an injected append implementation. Word indices keep
//! target offsets independent of host pointer width.
//! Codegen review: LLVM adds a frame and uses BLX through the append seam;
//! the direct elapsed call, post-callback reload and ordered stores remain.

use crate::app::timed_label_update_elapsed::timed_label_update_elapsed;

type AppendLap = unsafe extern "C" fn(*mut u32, *const u32) -> u32;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_append_lap(owner: *mut u32, value: *const u32) -> u32 {
    core::mem::transmute::<usize, AppendLap>(0x081d_0f74)(owner, value)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_append_lap(_: *mut u32, _: *const u32) -> u32 {
    panic!("lap append requires firmware collection or a host seam");
}

#[cfg(target_os = "none")]
pub static mut TIMED_LABEL_APPEND_LAP: AppendLap = firmware_append_lap;
#[cfg(not(target_os = "none"))]
pub static mut TIMED_LABEL_APPEND_LAP: AppendLap = unavailable_append_lap;

/// # Safety
/// `owner` must name a live, word-aligned timed-label owner (72 bytes on
/// target). The elapsed-time accessor and append seam must be valid; append
/// must preserve the owner allocation, but may mutate its words.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn timed_label_finish_lap(owner: *mut u32) -> u32 {
    timed_label_update_elapsed(owner);
    let append = core::ptr::read_volatile(core::ptr::addr_of!(TIMED_LABEL_APPEND_LAP));
    append(owner, owner.add(3));
    owner.add(4).write_volatile(owner.add(3).read_volatile());
    owner.add(3).write_volatile(0);
    owner.add(8).write_volatile(0);
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::timed_label_update_elapsed::SPORT_TIMER_INSTANCE;

    static ENABLED: [u8; 77] = [1; 77];
    static DISABLED: [u8; 77] = [0; 77];
    unsafe extern "C" fn enabled() -> *mut u8 { ENABLED.as_ptr() as *mut u8 }
    unsafe extern "C" fn disabled() -> *mut u8 { DISABLED.as_ptr() as *mut u8 }

    // Store the submitted value in an otherwise untouched word and emulate
    // a reentrant collection notification replacing the current lap.
    unsafe extern "C" fn append(owner: *mut u32, value: *const u32) -> u32 {
        assert_eq!(value, owner.add(3));
        owner.add(5).write(value.read());
        owner.add(3).write(value.read().wrapping_add(7));
        0
    }

    struct Restore {
        append: AppendLap,
        instance: unsafe extern "C" fn() -> *mut u8,
    }
    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe {
                TIMED_LABEL_APPEND_LAP = self.append;
                SPORT_TIMER_INSTANCE = self.instance;
            }
        }
    }

    #[test]
    fn finishes_updated_lap_and_reloads_after_reentrant_append() {
        unsafe {
            let _restore = Restore { append: TIMED_LABEL_APPEND_LAP, instance: SPORT_TIMER_INSTANCE };
            TIMED_LABEL_APPEND_LAP = append;
            for active in [false, true] {
                SPORT_TIMER_INSTANCE = if active { enabled } else { disabled };
                for lap in [0u32, 86_399_999, 86_400_000, u32::MAX] {
                    let _timer = crate::drivers::timer::configure_usec_timer_for_test(1500, 0);
                    let mut owner = [0xa5a5_a5a5; 18];
                    owner[1] = 500;
                    owner[2] = 10;
                    owner[3] = lap;
                    owner[8] = 1;
                    let mut expected = owner;
                    let submitted = if active { lap.wrapping_add(1).min(86_400_000) } else { lap };
                    if active { expected[1] = 1500; expected[2] = 11; }
                    expected[3] = 0;
                    expected[4] = submitted.wrapping_add(7);
                    expected[5] = submitted;
                    expected[8] = 0;
                    assert_eq!(timed_label_finish_lap(owner.as_mut_ptr()), 1);
                    assert_eq!(owner, expected);
                }
            }
        }
    }
}
