//! `app_command_63800021_dispatch` — original: `FUN_081161d8` @
//! **0x081161d8** (196 bytes exactly, 0x081161d8..0x0811629c, including its
//! literal pool). The next independently linked function begins with `push
//! {r4-r6,lr}` at 0x081162bc; the intervening words are this routine's literal
//! pool.
//!
//! Raw A32 decoding finds one unconditional direct `bl` to 0x08114d30, seven
//! `blx r3` virtual calls, and one `bx r3` virtual tail call. A whole-image
//! branch decode finds three inbound plain `bl` calls (0x081115bc, 0x08115cac,
//! and 0x08116354) and no predicated plain `bl` calls.
//!
//! ## Algorithm
//!
//! Dispatch a fixed sequence of seven `(group, command)` pairs through the
//! receiver's vtable slot `+0x58`. Between the fourth and fifth pairs, call
//! the unported direct helper at 0x08114d30. RetailOS tail-dispatches the final
//! pair.
//!
//! ## Deliberate deviation
//!
//! Rust expresses the tail dispatch as a normal call. The helper's identity is
//! not established by its address, so it remains a fixed-address target on
//! firmware and a replaceable host seam; host builds similarly use a seam for
//! the target-width vtable function word.

#[cfg(not(target_os = "none"))]
use core::ptr::addr_of;

const DISPATCH_SLOT_WORD: usize = 0x58 / 4;
const COMMAND_GROUP_NONE: u32 = 0x4e6f_6e65;
const COMMAND_GROUP_STR: u32 = 0x5374_7220;
const COMMAND_GROUP_CONTROL: u32 = 0x436e_746c;
const COMMANDS: [(u32, u32); 7] = [
    (COMMAND_GROUP_NONE, 0x0000_6408),
    (COMMAND_GROUP_NONE, 0x0000_6409),
    (COMMAND_GROUP_NONE, 0x0000_640a),
    (COMMAND_GROUP_STR, COMMAND_GROUP_CONTROL),
    (COMMAND_GROUP_CONTROL, COMMAND_GROUP_CONTROL - 3),
    (COMMAND_GROUP_NONE, 0x0000_808f),
    (COMMAND_GROUP_NONE, 0x0000_808e),
];

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn firmware_dispatch(receiver: *mut u8, group: u32, command: u32) {
    let vtable = unsafe { receiver.cast::<u32>().read_volatile() } as usize;
    let address = unsafe { (vtable as *const u32).add(DISPATCH_SLOT_WORD).read_volatile() } as usize;
    let dispatch: unsafe extern "C" fn(*mut u8, u32, u32) = unsafe { core::mem::transmute(address) };
    unsafe { dispatch(receiver, group, command) };
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn dispatch_conditional_app_command(receiver: *mut u8) {
    let helper: unsafe extern "C" fn(*mut u8) -> u32 = unsafe { core::mem::transmute(0x0811_4d30usize) };
    unsafe { helper(receiver) };
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_dispatch(_receiver: *mut u8, _group: u32, _command: u32) {
    panic!("app_command_63800021_dispatch requires installed firmware ops")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_conditional_command(_receiver: *mut u8) {
    panic!("app_command_63800021_dispatch requires installed firmware ops")
}

#[cfg(not(target_os = "none"))]
pub static mut APP_COMMAND_63800021_DISPATCH: unsafe extern "C" fn(*mut u8, u32, u32) = missing_dispatch;
#[cfg(not(target_os = "none"))]
pub static mut APP_COMMAND_63800021_CONDITIONAL_COMMAND: unsafe extern "C" fn(*mut u8) = missing_conditional_command;

/// Dispatches the fixed command sequence selected by application command
/// `0x63800021`.
///
/// # Safety
///
/// `receiver` must be a valid retail object with a callable vtable slot
/// `+0x58`; the stock routine performs no NULL checks.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn app_command_63800021_dispatch(receiver: *mut u8) {
    #[cfg(target_os = "none")]
    {
        unsafe { firmware_dispatch(receiver, COMMANDS[0].0, COMMANDS[0].1) };
        unsafe { firmware_dispatch(receiver, COMMANDS[1].0, COMMANDS[1].1) };
        unsafe { firmware_dispatch(receiver, COMMANDS[2].0, COMMANDS[2].1) };
        unsafe { firmware_dispatch(receiver, COMMANDS[3].0, COMMANDS[3].1) };
        unsafe { dispatch_conditional_app_command(receiver) };
        unsafe { firmware_dispatch(receiver, COMMANDS[4].0, COMMANDS[4].1) };
        unsafe { firmware_dispatch(receiver, COMMANDS[5].0, COMMANDS[5].1) };
        unsafe { firmware_dispatch(receiver, COMMANDS[6].0, COMMANDS[6].1) };
    }
    #[cfg(not(target_os = "none"))]
    {
        let dispatch = unsafe { addr_of!(APP_COMMAND_63800021_DISPATCH).read_volatile() };
        let conditional_command = unsafe { addr_of!(APP_COMMAND_63800021_CONDITIONAL_COMMAND).read_volatile() };
        unsafe { dispatch(receiver, COMMANDS[0].0, COMMANDS[0].1) };
        unsafe { dispatch(receiver, COMMANDS[1].0, COMMANDS[1].1) };
        unsafe { dispatch(receiver, COMMANDS[2].0, COMMANDS[2].1) };
        unsafe { dispatch(receiver, COMMANDS[3].0, COMMANDS[3].1) };
        unsafe { conditional_command(receiver) };
        unsafe { dispatch(receiver, COMMANDS[4].0, COMMANDS[4].1) };
        unsafe { dispatch(receiver, COMMANDS[5].0, COMMANDS[5].1) };
        unsafe { dispatch(receiver, COMMANDS[6].0, COMMANDS[6].1) };
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    static EVENTS: Mutex<Vec<(u32, u32)>> = Mutex::new(Vec::new());
    static OPS_TEST_LOCK: Mutex<()> = Mutex::new(());

    unsafe extern "C" fn record_dispatch(_receiver: *mut u8, group: u32, command: u32) {
        EVENTS.lock().unwrap_or_else(|poison| poison.into_inner()).push((group, command));
    }

    unsafe extern "C" fn record_conditional_command(_receiver: *mut u8) {
        EVENTS.lock().unwrap_or_else(|poison| poison.into_inner()).push((0, 0));
    }

    struct OpsGuard {
        dispatch: unsafe extern "C" fn(*mut u8, u32, u32),
        conditional_command: unsafe extern "C" fn(*mut u8),
        _lock: MutexGuard<'static, ()>,
    }

    impl Drop for OpsGuard {
        fn drop(&mut self) {
            unsafe {
                ptr::addr_of_mut!(APP_COMMAND_63800021_DISPATCH).write_volatile(self.dispatch);
                ptr::addr_of_mut!(APP_COMMAND_63800021_CONDITIONAL_COMMAND).write_volatile(self.conditional_command);
            }
            EVENTS.lock().unwrap_or_else(|poison| poison.into_inner()).clear();
        }
    }

    fn install() -> OpsGuard {
        let lock = OPS_TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let dispatch = unsafe { ptr::addr_of!(APP_COMMAND_63800021_DISPATCH).read_volatile() };
        let conditional_command = unsafe { ptr::addr_of!(APP_COMMAND_63800021_CONDITIONAL_COMMAND).read_volatile() };
        unsafe {
            ptr::addr_of_mut!(APP_COMMAND_63800021_DISPATCH).write_volatile(record_dispatch);
            ptr::addr_of_mut!(APP_COMMAND_63800021_CONDITIONAL_COMMAND).write_volatile(record_conditional_command);
        }
        EVENTS.lock().unwrap_or_else(|poison| poison.into_inner()).clear();
        OpsGuard { dispatch, conditional_command, _lock: lock }
    }

    #[test]
    fn dispatches_sequence_with_conditional_helper_between_pairs() {
        let _guard = install();
        unsafe { app_command_63800021_dispatch(0x1234usize as *mut u8) };
        assert_eq!(
            *EVENTS.lock().unwrap_or_else(|poison| poison.into_inner()),
            [
                COMMANDS[0], COMMANDS[1], COMMANDS[2], COMMANDS[3], (0, 0), COMMANDS[4], COMMANDS[5], COMMANDS[6],
            ],
        );
    }
}
