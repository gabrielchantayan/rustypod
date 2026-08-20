//! `wheel_sample_capture` — the lazy capture of the click-wheel event
//! sample the control subsystem hands to UI controllers.
//!
//! Original: `FUN_08292a88` @ 0x08292a88 (64 bytes exactly,
//! 0x08292a88..0x08292ac8 — no literal pool; the next body opens at
//! 0x08292ac8. 54 `bl` call sites).
//!
//! # The object
//!
//! The sample record the caller passes in (a `this`-less out object at
//! every one of the 54 sites — always the enclosing controller method's
//! second argument):
//!
//! ```text
//! +0x08  captured flag byte   0 = not yet sampled, 1 = sampled
//! +0x0c  elapsed word         timer ticks; only the low halfword is
//!                             returned (sign-extended)
//! +0x10  wheel state word     bit 0x40000000 = finger on wheel —
//!                             the gate every consuming site tests
//!                             (`tst r0, #0x40000000`, e.g. 0x0810c9f0)
//! +0x14  wheel rate word      the 16-sample averaged inter-event tick
//!                             delta, the wheel's velocity measure
//! ```
//!
//! # Algorithm
//!
//! ```text
//! if sample.captured == 0:
//!     FUN_080dc8a4(&sample.elapsed, &sample.state)  ; capture elapsed + state
//!     sample.rate     = wheel_sample_rate()         ; averaged wheel rate
//!     sample.captured = 1
//! return (i32)(i16)sample.elapsed    ; ldr + lsl#16 + asr#16
//! ```
//!
//! `FUN_080dc8a4` remains unported and rides the [`WHEEL_SAMPLE_OPS`] seam
//! (the event_list.rs pattern: firmware default on target, panicking default
//! on host, tests install a recording mock). `wheel_sample_rate` is ported
//! below; it uses the same seam only for the ROM tick-deadline check.
//!
//! - `FUN_080dc8a4` @ 0x080dc8a4 latches the system tick source (global
//!   0x089ca550 via `FUN_080e5c64`) into `elapsed`, transforms the wheel
//!   state word (`FUN_080b2a18` of [0x089caedc+0x20], which preserves
//!   exactly the 0x40000000 touch bit plus a converted low byte) into
//!   `state`, and — when the wheel timer object at [0x089caedc+0x10]
//!   exists — accumulates its pending latch delta (`FUN_08282a70`) into
//!   `elapsed` as well.
//! - `wheel_sample_rate` @ 0x080bd8f0 shifts the current deadline-check tick
//!   at 0x089caee0 into its previous slot at +0x08. If the previous tick is
//!   at least 1,000,000 kernel ticks old, it clears the 16 u32 inter-event
//!   deltas at 0x08a755fc and returns zero. Otherwise it returns their
//!   wrapping sum divided by 16. The ring is fed by the wheel position sampler
//!   @ 0x080877a0, whose only caller (0x0809e550) unwraps a 96-count rotary
//!   position delta (`cmp r0, #0x48; subgt r0, #0x60; cmn r0, #0x48; addlt
//!   r0, #0x60`) — the click-wheel evidence: 96-sector rotation, timer
//!   0x3c700000+0xb4 inter-event ticks, per-second rate, touch bit.
//!
//! # Why "capture" and not a getter name
//!
//! **No call site consumes the return value**: at all 54 `bl` sites the
//! very next instruction ignores r0 and re-reads the record's fields
//! directly (`ldr r0, [r5, #0x10]; tst ...`, `ldr r4, [r5, #0xc]`,
//! binary-surveyed). The call's observable job is the lazy fill; the
//! sign-extended halfword return is preserved because the original's
//! `ldr/lsl/asr` produces it, but it is dead at every known site. The
//! sibling @ 0x08292adc (`bl 0x08292a88; ldr r0, [r4, #0x14]`) is the
//! rate getter built on this capture.
//!
//! Consumers are UI controller methods ("EnterVolume"/"EnterDefault"
//! menu handlers, e.g. `FUN_0810c9dc`), reached by vtable — 0x0810c9dc
//! has no direct reference anywhere in the image.

use core::ptr::{addr_of, addr_of_mut};

/// Byte offset of the captured flag (`ldrb r0, [r0, #8]`).
pub const SAMPLE_CAPTURED: usize = 0x08;
/// Byte offset of the elapsed-ticks word (`ldr r0, [r4, #0xc]`).
pub const SAMPLE_ELAPSED: usize = 0x0c;
/// Byte offset of the wheel state word; bit 0x40000000 = touched.
pub const SAMPLE_STATE: usize = 0x10;
/// Byte offset of the averaged wheel-rate word (`str r0, [r4, #0x14]`).
pub const SAMPLE_RATE: usize = 0x14;

/// The touch/active bit in the state word — the gate at every
/// consuming call site (`tst r0, #0x40000000`).
pub const WHEEL_TOUCHED_BIT: u32 = 0x4000_0000;

/// Address of the three wheel timing words read by `wheel_sample_rate`.
///
/// The port only touches +0x04 (current deadline-check tick) and +0x08
/// (previous tick); +0x00 belongs to the unported position sampler.
#[cfg(target_os = "none")]
const WHEEL_TIMING_HISTORY: *mut u32 = 0x089c_aedc as *mut u32;

/// Host backing for the firmware timing words. It replaces the fixed RAM
/// location only in host tests; target code uses [`WHEEL_TIMING_HISTORY`].
#[cfg(not(target_os = "none"))]
static mut WHEEL_TIMING_HISTORY: [u32; 3] = [0; 3];

/// The sixteen u32 inter-event deltas averaged by `wheel_sample_rate`.
#[cfg(target_os = "none")]
const WHEEL_DELTA_RING: *mut u32 = 0x08a7_55fc as *mut u32;

/// Host backing for the firmware delta ring.
#[cfg(not(target_os = "none"))]
static mut WHEEL_DELTA_RING: [u32; 16] = [0; 16];

/// Firmware dependencies needed by the capture and rate helpers.
#[derive(Clone, Copy)]
pub struct WheelSampleOps {
    /// `FUN_080dc8a4` @ 0x080dc8a4: latch elapsed ticks into
    /// `elapsed_out` and the transformed wheel state word into
    /// `state_out`.
    pub capture: unsafe extern "C" fn(elapsed_out: *mut u32, state_out: *mut u32),
    /// ROM 0x22001ee8 via thunk 0x08037eb8: returns nonzero when
    /// `(kernel_ticks() - start) >= span`.
    pub tick_elapsed: unsafe extern "C" fn(start: usize, span: usize) -> usize,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_sample_capture(elapsed_out: *mut u32, state_out: *mut u32) {
    let f: unsafe extern "C" fn(*mut u32, *mut u32) =
        unsafe { core::mem::transmute(0x080d_c8a4usize) };
    unsafe { f(elapsed_out, state_out) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_sample_capture(_elapsed_out: *mut u32, _state_out: *mut u32) {
    panic!("wheel_sample_capture requires sample helper 0x080dc8a4")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_tick_elapsed(_start: usize, _span: usize) -> usize {
    panic!("wheel_sample_rate requires tick_elapsed")
}

/// Active firmware dependencies. retailOS defaults invoke the firmware
/// functions directly; host tests replace the table with recording mocks.
#[cfg(target_os = "none")]
pub static mut WHEEL_SAMPLE_OPS: WheelSampleOps = WheelSampleOps {
    capture: firmware_sample_capture,
    tick_elapsed: crate::kernel::task_lock::tick_elapsed,
};

#[cfg(not(target_os = "none"))]
pub static mut WHEEL_SAMPLE_OPS: WheelSampleOps = WheelSampleOps {
    capture: missing_sample_capture,
    tick_elapsed: missing_tick_elapsed,
};

/// wheel_sample_rate — original: `FUN_080bd8f0` @ 0x080bd8f0 (96 bytes,
/// followed by its 12-byte literal pool at 0x080bd950..0x080bd95c).
///
/// Copies the wheel timing word at +0x04 to +0x08 before testing whether the
/// old +0x08 value has aged by 1,000,000 kernel ticks. An expired history
/// clears all sixteen u32 entries of the delta ring and yields zero; otherwise
/// the function accumulates the entries in wrapping u32 arithmetic and returns
/// `sum >> 4`. It neither samples hardware nor advances the ring cursor.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn wheel_sample_rate() -> u32 {
    #[cfg(target_os = "none")]
    let timing = WHEEL_TIMING_HISTORY;
    #[cfg(not(target_os = "none"))]
    let timing = unsafe { addr_of_mut!(WHEEL_TIMING_HISTORY).cast::<u32>() };
    #[cfg(target_os = "none")]
    let ring = WHEEL_DELTA_RING;
    #[cfg(not(target_os = "none"))]
    let ring = unsafe { addr_of_mut!(WHEEL_DELTA_RING).cast::<u32>() };
    let old_tick = unsafe { timing.add(2).read_volatile() };
    let current_tick = unsafe { timing.add(1).read_volatile() };
    unsafe { timing.add(2).write_volatile(current_tick) };

    let ops = unsafe { core::ptr::read_volatile(addr_of_mut!(WHEEL_SAMPLE_OPS)) };
    if unsafe { (ops.tick_elapsed)(old_tick as usize, 1_000_000) } != 0 {
        for i in 0..16 {
            unsafe { ring.add(i).write_volatile(0) };
        }
        return 0;
    }

    let mut sum = 0u32;
    for i in 0..16 {
        sum = sum.wrapping_add(unsafe { ring.add(i).read_volatile() });
    }
    sum >> 4
}
/// wheel_sample_capture — original: `FUN_08292a88` @ 0x08292a88
/// (64 bytes; 54 `bl` call sites).
///
/// Lazily captures the wheel event sample (elapsed ticks, state flags,
/// averaged rate) on first use — the flag byte at +0x08 gates the fill
/// — and returns the sign-extended low halfword of the elapsed word
/// (the original's `ldr r0, [r4, #0xc]; mov r0, r0, lsl #16; mov r0,
/// r0, asr #16`). See the module header for why the return is dead at
/// every known call site.
///
/// # Safety
///
/// `sample` must point into a writable allocation covering
/// `sample..sample+0x18`; it is dereferenced unchecked, as in the
/// original.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn wheel_sample_capture(sample: *mut u8) -> i32 {
    if sample.add(SAMPLE_CAPTURED).read_volatile() == 0 {
        // Read the dispatch slots on the cold path, where the
        // original's two `bl`s sit (the singletons.rs thunk lesson:
        // hoisting the loads above the flag test would not match the
        // original's shape).
        let ops = unsafe { core::ptr::read_volatile(addr_of_mut!(WHEEL_SAMPLE_OPS)) };
        unsafe {
            (ops.capture)(
                sample.add(SAMPLE_ELAPSED) as *mut u32,
                sample.add(SAMPLE_STATE) as *mut u32,
            );
            let rate = wheel_sample_rate();
            (sample.add(SAMPLE_RATE) as *mut u32).write_volatile(rate);
            sample.add(SAMPLE_CAPTURED).write_volatile(1);
        }
    }
    let elapsed = unsafe { (sample.add(SAMPLE_ELAPSED) as *const u32).read_volatile() };
    ((elapsed << 16) as i32) >> 16
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// Serializes tests that swap the ops table and fixed-address host backing.
    static SAMPLE_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: Vec<&'static str> = Vec::new();
    static mut SAMPLE: [u8; 0x1c] = [0xa5; 0x1c];
    static mut MOCK_ELAPSED: u32 = 0;
    static mut MOCK_STATE: u32 = 0;
    static mut MOCK_TICK_ELAPSED: usize = 0;
    static mut LAST_TICK_ARGS: (usize, usize) = (0, 0);

    unsafe extern "C" fn recording_capture(elapsed_out: *mut u32, state_out: *mut u32) {
        unsafe {
            (*addr_of_mut!(CALLS)).push("capture");
            elapsed_out.write_volatile(core::ptr::read_volatile(addr_of!(MOCK_ELAPSED)));
            state_out.write_volatile(core::ptr::read_volatile(addr_of!(MOCK_STATE)));
        }
    }

    unsafe extern "C" fn recording_tick_elapsed(start: usize, span: usize) -> usize {
        unsafe {
            (*addr_of_mut!(CALLS)).push("tick_elapsed");
            *addr_of_mut!(LAST_TICK_ARGS) = (start, span);
            core::ptr::read_volatile(addr_of!(MOCK_TICK_ELAPSED))
        }
    }

    fn mock(elapsed: u32, state: u32, tick_elapsed: usize) -> MutexGuard<'static, ()> {
        let guard = SAMPLE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            WHEEL_SAMPLE_OPS = WheelSampleOps {
                capture: recording_capture,
                tick_elapsed: recording_tick_elapsed,
            };
            MOCK_ELAPSED = elapsed;
            MOCK_STATE = state;
            MOCK_TICK_ELAPSED = tick_elapsed;
            LAST_TICK_ARGS = (0, 0);
            (*addr_of_mut!(CALLS)).clear();
            (*addr_of_mut!(SAMPLE)).fill(0);
            WHEEL_TIMING_HISTORY = [0; 3];
            WHEEL_DELTA_RING = [0; 16];
        }
        guard
    }

    fn restore(guard: MutexGuard<'static, ()>) {
        unsafe {
            WHEEL_SAMPLE_OPS = WheelSampleOps {
                capture: missing_sample_capture,
                tick_elapsed: missing_tick_elapsed,
            };
        }
        drop(guard);
    }

    fn sample() -> *mut u8 {
        unsafe { addr_of_mut!(SAMPLE) as *mut u8 }
    }

    unsafe fn word(offset: usize) -> u32 {
        unsafe { (sample().add(offset) as *const u32).read_volatile() }
    }

    #[test]
    fn rate_averages_the_ring_and_shifts_the_deadline_tick() {
        let guard = mock(0, 0, 0);
        let deltas = [1, 7, 3, 15, 2, 8, 5, 9, 4, 12, 6, 10, 11, 13, 14, 16];
        unsafe {
            WHEEL_TIMING_HISTORY = [0, 0x1234_5678, 0x8765_4321];
            WHEEL_DELTA_RING = deltas;
            assert_eq!(wheel_sample_rate(), deltas.iter().sum::<u32>() >> 4);
            assert_eq!(WHEEL_TIMING_HISTORY[2], 0x1234_5678, "current tick shifts to +0x08");
            assert_eq!(LAST_TICK_ARGS, (0x8765_4321, 1_000_000));
            assert_eq!(*addr_of!(CALLS), std::vec!["tick_elapsed"]);
            assert_eq!(WHEEL_DELTA_RING, deltas, "live history leaves the ring untouched");
        }
        restore(guard);
    }

    #[test]
    fn expired_history_clears_every_delta_and_returns_zero() {
        let guard = mock(0, 0, 1);
        unsafe {
            WHEEL_TIMING_HISTORY = [0, 0x91, 0x42];
            WHEEL_DELTA_RING = [u32::MAX; 16];
            assert_eq!(wheel_sample_rate(), 0);
            assert_eq!(WHEEL_TIMING_HISTORY[2], 0x91);
            assert_eq!(LAST_TICK_ARGS, (0x42, 1_000_000));
            assert_eq!(WHEEL_DELTA_RING, [0; 16]);
        }
        restore(guard);
    }

    #[test]
    fn rate_sum_wraps_as_the_arm_add_loop_does() {
        let guard = mock(0, 0, 0);
        unsafe {
            WHEEL_DELTA_RING = [u32::MAX; 16];
            assert_eq!(wheel_sample_rate(), 0x0fff_ffff);
        }
        restore(guard);
    }

    #[test]
    fn the_first_call_captures_in_order_and_sets_the_flag() {
        let guard = mock(7, WHEEL_TOUCHED_BIT, 0);
        unsafe {
            wheel_sample_capture(sample());
            assert_eq!(*addr_of!(CALLS), std::vec!["capture", "tick_elapsed"]);
            assert_eq!(word(SAMPLE_ELAPSED), 7);
            assert_eq!(word(SAMPLE_STATE), WHEEL_TOUCHED_BIT);
            assert_eq!(word(SAMPLE_RATE), 0, "the rate() result lands at +0x14");
            assert_eq!(sample().add(SAMPLE_CAPTURED).read_volatile(), 1, "flag set last");
        }
        restore(guard);
    }

    #[test]
    fn the_second_call_skips_the_capture() {
        let guard = mock(3, 0, 0);
        unsafe {
            wheel_sample_capture(sample());
            wheel_sample_capture(sample());
            wheel_sample_capture(sample());
            assert_eq!(*addr_of!(CALLS), std::vec!["capture", "tick_elapsed"]);
        }
        restore(guard);
    }

    #[test]
    fn a_preseeded_flag_skips_the_capture() {
        let guard = mock(0, 0, 0);
        unsafe {
            sample().add(SAMPLE_CAPTURED).write_volatile(1);
            (sample().add(SAMPLE_ELAPSED) as *mut u32).write_volatile(5);
            assert_eq!(wheel_sample_capture(sample()), 5);
            assert!((*addr_of!(CALLS)).is_empty(), "no helper runs");
            assert_eq!(word(SAMPLE_RATE), 0, "untouched");
        }
        restore(guard);
    }

    #[test]
    fn the_return_is_the_sign_extended_low_halfword() {
        let guard = mock(0, 0, 0);
        unsafe {
            sample().add(SAMPLE_CAPTURED).write_volatile(1);
            for (word_value, expected) in [
                (0x0000_0000u32, 0i32),
                (0x0000_7fff, 0x7fff),
                (0x0000_8000, -0x8000),
                (0xffff_8000, -0x8000),
                (0x1234_ffff, -1),
                (0x0001_0000, 0),
            ] {
                (sample().add(SAMPLE_ELAPSED) as *mut u32).write_volatile(word_value);
                assert_eq!(
                    wheel_sample_capture(sample()),
                    expected,
                    "lsl#16/asr#16 of {word_value:#010x}"
                );
            }
        }
        restore(guard);
    }
}
