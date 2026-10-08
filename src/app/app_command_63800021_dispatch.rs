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
//! `app_dispatch_if_global_flag` port. RetailOS tail-dispatches the final
//! pair.
//!
//! ## Deliberate deviation
//!
//! Rust expresses the tail dispatch as a normal call. The conditional helper
//! uses the canonical Rust port; host builds retain a replaceable seam for
//! this routine's target-width virtual dispatch.

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

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_dispatch(_receiver: *mut u8, _group: u32, _command: u32) {
    panic!("app_command_63800021_dispatch requires installed firmware ops")
}

#[cfg(not(target_os = "none"))]
pub static mut APP_COMMAND_63800021_DISPATCH: unsafe extern "C" fn(*mut u8, u32, u32) = missing_dispatch;

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
        unsafe { super::app_dispatch_if_global_flag::app_dispatch_if_global_flag(receiver) };
        unsafe { firmware_dispatch(receiver, COMMANDS[4].0, COMMANDS[4].1) };
        unsafe { firmware_dispatch(receiver, COMMANDS[5].0, COMMANDS[5].1) };
        unsafe { firmware_dispatch(receiver, COMMANDS[6].0, COMMANDS[6].1) };
    }
    #[cfg(not(target_os = "none"))]
    {
        let dispatch = unsafe { addr_of!(APP_COMMAND_63800021_DISPATCH).read_volatile() };
        unsafe { dispatch(receiver, COMMANDS[0].0, COMMANDS[0].1) };
        unsafe { dispatch(receiver, COMMANDS[1].0, COMMANDS[1].1) };
        unsafe { dispatch(receiver, COMMANDS[2].0, COMMANDS[2].1) };
        unsafe { dispatch(receiver, COMMANDS[3].0, COMMANDS[3].1) };
        unsafe { super::app_dispatch_if_global_flag::app_dispatch_if_global_flag(receiver) };
        unsafe { dispatch(receiver, COMMANDS[4].0, COMMANDS[4].1) };
        unsafe { dispatch(receiver, COMMANDS[5].0, COMMANDS[5].1) };
        unsafe { dispatch(receiver, COMMANDS[6].0, COMMANDS[6].1) };
    }
}

