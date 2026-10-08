//! Polls the timeout of a pending application action.
//!
//! `pending_action_timeout_poll` — original: `FUN_081137a8` @ `0x081137a8`.
//! True extent: 52 bytes, `0x081137a8..0x081137dc`; the next word starts a
//! separate PUSH prologue. Raw aligned-word decoding finds two incoming plain
//! BLs (0x08113cac, 0x081144e8), zero predicated incoming BLs, one outgoing
//! plain BL (the clock at 0x0826c5e8), zero predicated outgoing BLs, and one
//! conditional tail branch to 0x08112bf8. Ghidra's 88-byte extent and inlined
//! completion body are incorrect for this image.
//!
//! Return immediately when the byte at +0x51a is zero. Otherwise sample the
//! millisecond clock once, then load +0x520 and add 250 with u32 wrapping.
//! Only when the sample is unsigned-greater than that deadline, dispatch the
//! original completion routine at 0x08112bf8. Its verified body loads +0x51c,
//! calls 0x08113018, clears +0x51a and sets +0x519; it remains unported.
//! The timer's historic `usec_timer_read_seconds` name is retained despite its
//! /1000 conversion. Deliberate deviation: Rust expresses the tail dispatch
//! as a void call; incidental r0 values on return are not an API result.

#[cfg(target_os = "none")]
use core::mem;

type Clock = unsafe extern "C" fn() -> u32;
type Complete = unsafe extern "C" fn(*mut u8);

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_completion(_: *mut u8) {
    panic!("install pending-action completion seam")
}

/// Host replacements for the clock and the unported completion routine.
#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct PendingActionTimeoutOps {
    pub clock: Clock,
    pub complete: Complete,
}

#[cfg(not(target_os = "none"))]
pub static mut PENDING_ACTION_TIMEOUT_OPS: PendingActionTimeoutOps = PendingActionTimeoutOps {
    clock: crate::drivers::timer::usec_timer_read_seconds,
    complete: missing_completion,
};

/// # Safety
/// `state` must be writable and word-aligned through +0x523. The completion
/// routine requires the full retailOS application object and its interfaces.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn pending_action_timeout_poll(state: *mut u8) {
    if state.add(0x51a).read_volatile() == 0 { return; }
    #[cfg(target_os = "none")]
    let (clock, complete): (Clock, Complete) = (
        crate::drivers::timer::usec_timer_read_seconds,
        mem::transmute(0x0811_2bf8usize),
    );
    #[cfg(not(target_os = "none"))]
    let (clock, complete) = {
        let ops = PENDING_ACTION_TIMEOUT_OPS;
        (ops.clock, ops.complete)
    };
    let now = clock();
    let started = state.add(0x520).cast::<u32>().read_volatile();
    if now > started.wrapping_add(250) { complete(state); }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut NOW: u32 = 0;
    static mut STATE: *mut u32 = core::ptr::null_mut();
    static mut REPLACE_STARTED: Option<u32> = None;

    unsafe extern "C" fn clock() -> u32 {
        if let Some(started) = REPLACE_STARTED { STATE.add(0x520 / 4).write(started); }
        NOW
    }
    unsafe extern "C" fn complete(state: *mut u8) {
        state.add(0x51a).write(0);
        state.add(0x519).write(1);
    }
    unsafe extern "C" fn forbidden_clock() -> u32 { panic!("inactive clock access") }

    #[test]
    fn unsigned_deadline_boundaries_and_wrapping() {
        let _guard = LOCK.lock();
        unsafe {
            let saved = PENDING_ACTION_TIMEOUT_OPS;
            PENDING_ACTION_TIMEOUT_OPS = PendingActionTimeoutOps { clock, complete };
            REPLACE_STARTED = None;
            for (started, now, expires) in [
                (100, 349, false), (100, 350, false), (100, 351, true),
                (0x8000_0000, 0x8000_00fa, false),
                (0x8000_0000, 0xffff_ffff, true),
                (u32::MAX - 249, 0, false), (u32::MAX - 249, 1, true),
                (u32::MAX - 250, u32::MAX, false),
            ] {
                let mut state = [0xa5a5_a5a5u32; 0x524 / 4];
                let bytes = state.as_mut_ptr().cast::<u8>();
                bytes.add(0x51a).write(0x80);
                bytes.add(0x519).write(0);
                state[0x520 / 4] = started;
                let before = state;
                NOW = now;
                pending_action_timeout_poll(bytes);
                let mut expected = before;
                if expires {
                    let p = expected.as_mut_ptr().cast::<u8>();
                    p.add(0x51a).write(0);
                    p.add(0x519).write(1);
                }
                assert_eq!(state, expected, "started={started:#x}, now={now:#x}");
            }
            PENDING_ACTION_TIMEOUT_OPS = saved;
        }
    }

    #[test]
    fn inactive_skips_clock_and_active_loads_timestamp_after_clock() {
        let _guard = LOCK.lock();
        unsafe {
            let saved = PENDING_ACTION_TIMEOUT_OPS;
            let mut state = [0u32; 0x524 / 4];
            let bytes = state.as_mut_ptr().cast::<u8>();
            PENDING_ACTION_TIMEOUT_OPS = PendingActionTimeoutOps { clock: forbidden_clock, complete };
            pending_action_timeout_poll(bytes);
            assert_eq!(state, [0; 0x524 / 4]);
            PENDING_ACTION_TIMEOUT_OPS.clock = clock;
            STATE = state.as_mut_ptr();
            NOW = 500;
            REPLACE_STARTED = Some(500);
            bytes.add(0x51a).write(1);
            pending_action_timeout_poll(bytes);
            assert_eq!(bytes.add(0x51a).read(), 1);
            assert_eq!(bytes.add(0x519).read(), 0);
            assert_eq!(state[0x520 / 4], 500);
            REPLACE_STARTED = None;
            STATE = core::ptr::null_mut();
            PENDING_ACTION_TIMEOUT_OPS = saved;
        }
    }
}
