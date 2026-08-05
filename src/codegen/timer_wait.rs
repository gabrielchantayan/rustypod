//! `cg_timer_wait` — original: `FUN_082bc4fc` @ 0x082bc4fc (96 bytes;
//! **3 `bl` call sites**, all from the same unported caller
//! `FUN_0819d048` @ 0x0819d278/0x0819d284/0x0819d290, which invokes it
//! back-to-back with tick counts 0x4b0, a global, and 0x960 against one
//! event handle).
//!
//! A timed wait on an event handle, built on a hardware timer channel
//! of the S5L8702 timer block at 0x3c700000 (0x20-byte channel stride;
//! channels above 3 are reached through a pointer table):
//!
//! ```text
//! version = board_version()                  // 0x080e624c
//! channel = (version>>16 == 0x10 && (version & 0xffff) >= 6) ? 3 : 0
//! timer_channel_arm(channel, ticks)          // 0x0836dc14
//! notify_wait_enter()                        // 0x0836d854
//! timer_channel_start(channel)               // 0x0836dd90
//! event_wait(event)                          // 0x08037ef0 -> ROM 0x22001f78
//! timer_channel_stop(channel)                // 0x0836ddbc
//! return notify_wait_exit()                  // 0x0836d82c (tail `b`)
//! ```
//!
//! The channel-select condition is exactly the original's
//! `cmp r1, r0, lsr #0x10` / `bne` / low-halfword extract /
//! `cmp r0, #6; movcs r4, #3`: only a version word whose HIGH halfword
//! equals 0x10 and whose LOW halfword is unsigned-`>= 6` selects
//! channel 3; everything else waits on channel 0. `board_version`
//! @ 0x080e624c returns a lazily cached system-info word (field +0x84
//! of the object returned by 0x08369bec, cached behind the 0x7fffffff
//! sentinel), so the channel choice is a board/firmware-revision
//! decision.
//!
//! The callees, named from their disassembly:
//!
//! - `timer_channel_arm` @ 0x0836dc14 stops the channel, then finds the
//!   smallest prescaler multiplier `n <= 0x400` with
//!   `CLK / (ticks * n) <= 0x10000` (integer divide @ 0x08036f14 against
//!   the clock literal at 0x0836dc98), programs the count at channel
//!   +0x08 and `n - 1` at +0x10, writes 0x40 to +0x00 and sets bit 1 of
//!   the command word at +0x04 — armed but not started.
//! - `timer_channel_start` @ 0x0836dd90 sets bit 0 of the channel
//!   command word at +0x04; `timer_channel_stop` @ 0x0836ddbc clears it.
//! - `notify_wait_enter` @ 0x0836d854 and `notify_wait_exit`
//!   @ 0x0836d82c each issue two command words through the mailbox
//!   writer @ 0x0836b5b0 — (6,3,0) then (7,5,0) on entry, (6,1,0) then
//!   (7,1,0) on exit — bracketing the wait.
//! - `event_wait` @ 0x08037ef0 is the ROM veneer to 0x22001f78, the
//!   mirror of osos `FUN_08001f78`, which polls an event service
//!   (struct at 0x080023d0, slot +0xb4) with the handle until it
//!   reports readiness. The timer interrupt armed above is what posts
//!   that handle.
//!
//! The original's last instruction is a tail `b 0x0836d82c`, so the
//! function returns `notify_wait_exit`'s result, which is always 0
//! (the mailbox writer @ 0x0836b5b0 ends `mov r0, #0`).
//!
//! Deviations:
//! - All seven callees are unported and sit behind the
//!   [`CG_TIMER_WAIT_OPS`] `read_volatile` dispatch seam (the house
//!   pattern — see `super::heap::CG_HEAP_OPS`). The defaults are
//!   `missing_*` spin-loop stubs, matching the
//!   `app/node_list.rs` `NODE_LIST_ENQUEUE_OPS` convention for unwired
//!   seams; host tests install recording mocks.
//! - The tail `b` is a plain `return` of the seam call; the observable
//!   behavior (argument state and returned value) is identical.

use core::ffi::c_void;

/// Indirect dispatch for the seven unported callees (see the module
/// header). Host tests replace the whole table.
#[derive(Clone, Copy)]
pub struct CgTimerWaitOps {
    /// `board_version` @ 0x080e624c: the lazily cached system-info word
    /// that selects the timer channel.
    pub board_version: unsafe extern "C" fn() -> u32,
    /// `timer_channel_arm` @ 0x0836dc14: program `channel` for `ticks`,
    /// leaving it stopped.
    pub timer_channel_arm: unsafe extern "C" fn(channel: u32, ticks: u32),
    /// `notify_wait_enter` @ 0x0836d854: the (6,3,0)/(7,5,0) mailbox
    /// pair issued before the wait.
    pub notify_wait_enter: unsafe extern "C" fn(),
    /// `timer_channel_start` @ 0x0836dd90: set bit 0 of the channel
    /// command word.
    pub timer_channel_start: unsafe extern "C" fn(channel: u32),
    /// `event_wait` @ 0x08037ef0 (ROM veneer to 0x22001f78, the mirror
    /// of osos 0x08001f78): block on `event` until it is signalled.
    pub event_wait: unsafe extern "C" fn(event: *mut c_void),
    /// `timer_channel_stop` @ 0x0836ddbc: clear bit 0 of the channel
    /// command word.
    pub timer_channel_stop: unsafe extern "C" fn(channel: u32),
    /// `notify_wait_exit` @ 0x0836d82c: the (6,1,0)/(7,1,0) mailbox
    /// pair issued after the wait — the original's tail call, so its
    /// result (always 0 on target) is the function's return value.
    pub notify_wait_exit: unsafe extern "C" fn() -> u32,
}

unsafe extern "C" fn missing_board_version() -> u32 {
    loop {
        core::hint::spin_loop();
    }
}

unsafe extern "C" fn missing_timer_channel_arm(_channel: u32, _ticks: u32) {
    loop {
        core::hint::spin_loop();
    }
}

unsafe extern "C" fn missing_notify_wait_enter() {
    loop {
        core::hint::spin_loop();
    }
}

unsafe extern "C" fn missing_timer_channel_start(_channel: u32) {
    loop {
        core::hint::spin_loop();
    }
}

unsafe extern "C" fn missing_event_wait(_event: *mut c_void) {
    loop {
        core::hint::spin_loop();
    }
}

unsafe extern "C" fn missing_timer_channel_stop(_channel: u32) {
    loop {
        core::hint::spin_loop();
    }
}

unsafe extern "C" fn missing_notify_wait_exit() -> u32 {
    loop {
        core::hint::spin_loop();
    }
}

/// The active callee bindings. Unwired `missing_*` stubs until the
/// seven callees are ported (see the module header's deviation); host
/// tests replace the table.
pub static mut CG_TIMER_WAIT_OPS: CgTimerWaitOps = CgTimerWaitOps {
    board_version: missing_board_version,
    timer_channel_arm: missing_timer_channel_arm,
    notify_wait_enter: missing_notify_wait_enter,
    timer_channel_start: missing_timer_channel_start,
    event_wait: missing_event_wait,
    timer_channel_stop: missing_timer_channel_stop,
    notify_wait_exit: missing_notify_wait_exit,
};

/// Volatile read of the ops table — without it LLVM constant-folds the
/// indirect calls back to the defaults.
#[inline(always)]
fn cg_timer_wait_ops() -> CgTimerWaitOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(CG_TIMER_WAIT_OPS)) }
}

/// High halfword of the version word that gates channel 3
/// (`mov r1, #0x10; cmp r1, r0, lsr #0x10`).
const CHANNEL3_VERSION_MAJOR: u32 = 0x10;
/// Low halfword threshold for channel 3 (`cmp r0, #6; movcs r4, #3` —
/// unsigned `>=`).
const CHANNEL3_VERSION_MINOR_MIN: u32 = 6;
/// The channel the threshold selects (`movcs r4, #3`).
const CHANNEL_FOR_NEW_BOARDS: u32 = 3;
/// The channel everything else waits on (`mov r4, #0`).
const CHANNEL_DEFAULT: u32 = 0;

/// cg_timer_wait — original: `FUN_082bc4fc` @ 0x082bc4fc (96 bytes,
/// 3 `bl` call sites).
///
/// Arms hardware timer `channel` for `ticks`, brackets a blocking wait
/// on `event` with the enter/exit mailbox pairs, and stops the channel
/// afterwards. `channel` is 3 when the board version word's high
/// halfword is 0x10 and its low halfword is at least 6, otherwise 0.
/// Returns the exit notification's result (always 0 on target).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cg_timer_wait(ticks: u32, event: *mut c_void) -> u32 {
    let ops = cg_timer_wait_ops();
    let version = (ops.board_version)();
    let mut channel = CHANNEL_DEFAULT;
    if version >> 16 == CHANNEL3_VERSION_MAJOR
        && version & 0xffff >= CHANNEL3_VERSION_MINOR_MIN
    {
        channel = CHANNEL_FOR_NEW_BOARDS;
    }
    (ops.timer_channel_arm)(channel, ticks);
    (ops.notify_wait_enter)();
    (ops.timer_channel_start)(channel);
    (ops.event_wait)(event);
    (ops.timer_channel_stop)(channel);
    (ops.notify_wait_exit)()
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// Serializes the shared ops table across tests.
    static LOCK: Mutex<()> = Mutex::new(());

    /// One recorded seam call: a tag plus its two scalar arguments
    /// (pointers passed as integers).
    type Record = (&'static str, u32, usize);

    static mut CALLS: Vec<Record> = Vec::new();
    static mut VERSION: u32 = 0;
    static mut EXIT_RESULT: u32 = 0;

    unsafe fn record(tag: &'static str, a0: u32, a1: usize) {
        (*core::ptr::addr_of_mut!(CALLS)).push((tag, a0, a1));
    }

    unsafe extern "C" fn mock_board_version() -> u32 {
        record("version", 0, 0);
        *core::ptr::addr_of!(VERSION)
    }

    unsafe extern "C" fn mock_timer_channel_arm(channel: u32, ticks: u32) {
        record("arm", channel, ticks as usize);
    }

    unsafe extern "C" fn mock_notify_wait_enter() {
        record("enter", 0, 0);
    }

    unsafe extern "C" fn mock_timer_channel_start(channel: u32) {
        record("start", channel, 0);
    }

    unsafe extern "C" fn mock_event_wait(event: *mut c_void) {
        record("wait", 0, event as usize);
    }

    unsafe extern "C" fn mock_timer_channel_stop(channel: u32) {
        record("stop", channel, 0);
    }

    unsafe extern "C" fn mock_notify_wait_exit() -> u32 {
        record("exit", 0, 0);
        *core::ptr::addr_of!(EXIT_RESULT)
    }

    const MOCK_OPS: CgTimerWaitOps = CgTimerWaitOps {
        board_version: mock_board_version,
        timer_channel_arm: mock_timer_channel_arm,
        notify_wait_enter: mock_notify_wait_enter,
        timer_channel_start: mock_timer_channel_start,
        event_wait: mock_event_wait,
        timer_channel_stop: mock_timer_channel_stop,
        notify_wait_exit: mock_notify_wait_exit,
    };

    fn setup(version: u32) -> MutexGuard<'static, ()> {
        let guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            (*core::ptr::addr_of_mut!(CALLS)).clear();
            core::ptr::addr_of_mut!(VERSION).write(version);
            core::ptr::addr_of_mut!(EXIT_RESULT).write(0);
            core::ptr::addr_of_mut!(CG_TIMER_WAIT_OPS).write(MOCK_OPS);
        }
        guard
    }

    fn teardown() {
        unsafe {
            core::ptr::addr_of_mut!(CG_TIMER_WAIT_OPS).write(CgTimerWaitOps {
                board_version: missing_board_version,
                timer_channel_arm: missing_timer_channel_arm,
                notify_wait_enter: missing_notify_wait_enter,
                timer_channel_start: missing_timer_channel_start,
                event_wait: missing_event_wait,
                timer_channel_stop: missing_timer_channel_stop,
                notify_wait_exit: missing_notify_wait_exit,
            });
        }
    }

    fn calls() -> Vec<Record> {
        unsafe { (*core::ptr::addr_of!(CALLS)).clone() }
    }

    /// The channel handed to `timer_channel_arm` for a given version
    /// word — the whole point of the first ten instructions.
    fn channel_for(version: u32) -> u32 {
        let _g = setup(version);
        let channel = unsafe {
            cg_timer_wait(7, core::ptr::null_mut());
            calls()
                .iter()
                .find(|(tag, _, _)| *tag == "arm")
                .map(|(_, channel, _)| *channel)
                .expect("arm must be called")
        };
        teardown();
        channel
    }

    #[test]
    fn channel_is_3_only_for_version_10_6_or_later() {
        // High halfword != 0x10: always channel 0, whatever the low half.
        assert_eq!(channel_for(0x0000_0000), 0);
        assert_eq!(channel_for(0x000f_0006), 0);
        assert_eq!(channel_for(0x0011_0006), 0);
        assert_eq!(channel_for(0x0010_0000 - 1), 0); // 0x000f_ffff
        // High halfword == 0x10, low < 6: channel 0.
        assert_eq!(channel_for(0x0010_0000), 0);
        assert_eq!(channel_for(0x0010_0005), 0);
        // Boundary: low == 6 is the first channel-3 version (`movcs`).
        assert_eq!(channel_for(0x0010_0006), 3);
        assert_eq!(channel_for(0x0010_0007), 3);
        assert_eq!(channel_for(0x0010_ffff), 3);
    }

    #[test]
    fn runs_the_fixed_sequence_in_order() {
        let _g = setup(0x0010_0006);
        unsafe { cg_timer_wait(0x4b0, 0x1234usize as *mut c_void) };
        let tags: Vec<&'static str> = calls().iter().map(|(tag, _, _)| *tag).collect();
        assert_eq!(
            tags,
            std::vec!["version", "arm", "enter", "start", "wait", "stop", "exit"],
            "arm, enter-notify, start, wait, stop, exit-notify"
        );
        teardown();
    }

    #[test]
    fn forwards_ticks_event_and_channel_verbatim() {
        let event = 0xdead_beefusize as *mut c_void;
        {
            let _g = setup(0x000f_ffff); // channel 0 path
            unsafe { cg_timer_wait(0x960, event) };
            let log = calls();
            assert_eq!(log[1], ("arm", 0, 0x960), "channel 0, ticks to arm");
            assert_eq!(log[3], ("start", 0, 0), "channel 0 to start");
            assert_eq!(log[4], ("wait", 0, event as usize), "event to the wait");
            assert_eq!(log[5], ("stop", 0, 0), "channel 0 to stop");
            teardown();
        }
        {
            let _g = setup(0x0010_0006); // channel 3 path
            unsafe { cg_timer_wait(0x4b0, event) };
            let log = calls();
            assert_eq!(log[1], ("arm", 3, 0x4b0), "channel 3, ticks to arm");
            assert_eq!(log[3], ("start", 3, 0), "channel 3 to start");
            assert_eq!(log[5], ("stop", 3, 0), "channel 3 to stop");
            teardown();
        }
    }

    #[test]
    fn returns_the_exit_notifications_result() {
        // The original tail-branches into 0x0836d82c, so its return
        // value IS the function's (0 on target; a sentinel here proves
        // the tail-call value is propagated, not recomputed).
        let _g = setup(0x0010_0006);
        unsafe { core::ptr::addr_of_mut!(EXIT_RESULT).write(0xc0ff_ee01) };
        let result = unsafe { cg_timer_wait(1, core::ptr::null_mut()) };
        assert_eq!(result, 0xc0ff_ee01);
        teardown();
    }
}
