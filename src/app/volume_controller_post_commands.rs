//! `volume_controller_post_commands` — original: `FUN_081f9354` @
//! **0x081f9354** (104 bytes exactly, 0x081f9354..0x081f93bc, including its
//! literal pool).
//!
//! The next independently linked function starts with `push {r4-r8,lr}` at
//! 0x081f93bc. Raw A32 decoding finds no direct `bl` instructions in this
//! function: it performs two `blx r3` virtual calls followed by one `bx r3`
//! virtual tail call; none is predicated. A whole-image branch decode finds
//! four incoming plain `bl` calls and no predicated `bl` calls.
//!
//! ## Algorithm
//!
//! Load the receiver's vtable slot +0x58 and invoke it with the receiver and
//! the command pairs `(0x44726177, 0x00007f0c)`, `(0x44726177, 0x00007f0d)`,
//! and `(0x44726177, 0x00007f0e)`. The final invocation is a tail branch in
//! retailOS.
//!
//! ## Deliberate deviation
//!
//! Rust expresses the final tail branch as a normal call. Host builds use a
//! swappable operation seam because target-width vtable pointers cannot be
//! represented by host pointers.

#[cfg(not(target_os = "none"))]
use core::ptr::addr_of;

const COMMAND_GROUP: u32 = 0x4472_6177;
const FIRST_COMMAND: u32 = 0x0000_7f0c;
const LAST_COMMAND: u32 = 0x0000_7f0e;
const DISPATCH_SLOT: usize = 0x58;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe extern "C" fn firmware_dispatch(receiver: *mut u8, command: u32, argument: u32) {
    let vtable = unsafe { receiver.cast::<u32>().read_volatile() } as usize;
    let slot = unsafe { (vtable as *const u32).add(DISPATCH_SLOT / 4).read_volatile() } as usize;
    let method: unsafe extern "C" fn(*mut u8, u32, u32) = unsafe { core::mem::transmute(slot) };
    unsafe { method(receiver, command, argument) };
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_dispatch(_receiver: *mut u8, _command: u32, _argument: u32) {
    panic!("volume_controller_post_commands requires installed firmware ops")
}

#[cfg(not(target_os = "none"))]
pub static mut VOLUME_CONTROLLER_POST_COMMANDS_DISPATCH: unsafe extern "C" fn(*mut u8, u32, u32) = missing_dispatch;

/// Dispatches the three fixed post-operation commands through vtable slot
/// +0x58.
///
/// # Safety
///
/// `volume_controller` must be a valid retail object with a callable vtable
/// entry at +0x58. The stock routine has no NULL checks.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn volume_controller_post_commands(volume_controller: *mut u8) {
    #[cfg(target_os = "none")]
    unsafe { firmware_dispatch(volume_controller, COMMAND_GROUP, FIRST_COMMAND) };
    #[cfg(target_os = "none")]
    unsafe { firmware_dispatch(volume_controller, COMMAND_GROUP, FIRST_COMMAND + 1) };
    #[cfg(target_os = "none")]
    unsafe { firmware_dispatch(volume_controller, COMMAND_GROUP, LAST_COMMAND) };
    #[cfg(not(target_os = "none"))]
    {
        let dispatch = unsafe { addr_of!(VOLUME_CONTROLLER_POST_COMMANDS_DISPATCH).read_volatile() };
        unsafe { dispatch(volume_controller, COMMAND_GROUP, FIRST_COMMAND) };
        unsafe { dispatch(volume_controller, COMMAND_GROUP, FIRST_COMMAND + 1) };
        unsafe { dispatch(volume_controller, COMMAND_GROUP, LAST_COMMAND) };
    }
}
#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    static DISPATCHES: Mutex<Vec<(usize, u32, u32)>> = Mutex::new(Vec::new());
    static OPS_TEST_LOCK: Mutex<()> = Mutex::new(());

    unsafe extern "C" fn record_dispatch(receiver: *mut u8, command: u32, argument: u32) {
        DISPATCHES.lock().unwrap_or_else(|poison| poison.into_inner()).push((receiver as usize, command, argument));
    }

    struct DispatchGuard {
        saved: unsafe extern "C" fn(*mut u8, u32, u32),
        _lock: MutexGuard<'static, ()>,
    }

    impl Drop for DispatchGuard {
        fn drop(&mut self) {
            unsafe { ptr::addr_of_mut!(VOLUME_CONTROLLER_POST_COMMANDS_DISPATCH).write_volatile(self.saved) };
            DISPATCHES.lock().unwrap_or_else(|poison| poison.into_inner()).clear();
        }
    }

    fn install() -> DispatchGuard {
        let lock = OPS_TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let saved = unsafe { ptr::addr_of!(VOLUME_CONTROLLER_POST_COMMANDS_DISPATCH).read_volatile() };
        unsafe { ptr::addr_of_mut!(VOLUME_CONTROLLER_POST_COMMANDS_DISPATCH).write_volatile(record_dispatch) };
        DISPATCHES.lock().unwrap_or_else(|poison| poison.into_inner()).clear();
        DispatchGuard { saved, _lock: lock }
    }

    #[test]
    fn dispatches_all_fixed_commands_in_order() {
        let _guard = install();
        let receiver = 0x1234usize as *mut u8;

        unsafe { volume_controller_post_commands(receiver) };

        assert_eq!(
            *DISPATCHES.lock().unwrap_or_else(|poison| poison.into_inner()),
            [
                (receiver as usize, COMMAND_GROUP, FIRST_COMMAND),
                (receiver as usize, COMMAND_GROUP, FIRST_COMMAND + 1),
                (receiver as usize, COMMAND_GROUP, LAST_COMMAND),
            ],
        );
    }
}
