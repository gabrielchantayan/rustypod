//! `input_state_transition` — original: `FUN_080a8e10` @ **0x080a8e10**
//! (**72 bytes**, `0x080a8e10..0x080a8e54`; the next distinct function starts
//! at `0x080a8e58`).
//!
//! Raw ARM words establish five incoming plain `bl` call sites
//! (`0x08084bc4`, `0x08084cac`, `0x08084ccc`, `0x08084cec`, and
//! `0x08084d0c`), no incoming predicated `bl` forms, and one outbound
//! predicated `blne` to the unresolved `FUN_080921dc`; the final outbound
//! transfer is a tail `b` to that same function.
//!
//! # Algorithm
//!
//! A transition from state 3 emits command 0 unless the destination is 1,
//! then always emits command 1. Other unchanged states emit nothing; changed
//! odd states emit command 0 before command 1, while changed even states emit
//! only command 1.
//!
//! Deliberate deviation: `FUN_080921dc` has no recovered identity in
//! `names.yaml`. Target builds call its fixed retailOS address; host builds
//! use a recording seam so the observable command sequence can be tested.

const RETAIL_STATE_COMMAND_DISPATCH: usize = 0x0809_21dc;

/// ABI observed at the unresolved retail command-dispatch entry.
pub type StateCommandDispatch = unsafe extern "C" fn(u32, u32);

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn dispatch_state_command(slot: u32, command: u32) {
    let dispatch: StateCommandDispatch = unsafe { core::mem::transmute(RETAIL_STATE_COMMAND_DISPATCH) };
    unsafe { dispatch(slot, command) };
}

/// Host seam for the unresolved retail command dispatcher.
#[cfg(not(target_os = "none"))]
pub static mut INPUT_STATE_TRANSITION_DISPATCH: StateCommandDispatch = missing_state_command_dispatch;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_state_command_dispatch(_slot: u32, _command: u32) {}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn dispatch_state_command(slot: u32, command: u32) {
    let dispatch = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(INPUT_STATE_TRANSITION_DISPATCH)) };
    unsafe { dispatch(slot, command) };
}

/// Emits retailOS state-transition commands for `slot`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn input_state_transition(slot: u32, previous_state: u32, next_state: u32) {
    if previous_state == 3 {
        if next_state != 1 {
            unsafe { dispatch_state_command(slot, 0) };
        }
        unsafe { dispatch_state_command(slot, 1) };
        return;
    }

    if previous_state == next_state {
        return;
    }

    if previous_state & 1 != 0 {
        unsafe { dispatch_state_command(slot, 0) };
    }
    unsafe { dispatch_state_command(slot, 1) };
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::Mutex;
    use std::vec::Vec;

    static DISPATCH_LOCK: Mutex<()> = Mutex::new(());
    static mut COMMANDS: Option<Vec<(u32, u32)>> = None;

    unsafe extern "C" fn record_state_command(slot: u32, command: u32) {
        unsafe { COMMANDS.as_mut().unwrap().push((slot, command)) };
    }

    fn commands_for(previous_state: u32, next_state: u32) -> Vec<(u32, u32)> {
        let _guard = DISPATCH_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            COMMANDS = Some(Vec::new());
            INPUT_STATE_TRANSITION_DISPATCH = record_state_command;
            input_state_transition(4, previous_state, next_state);
            INPUT_STATE_TRANSITION_DISPATCH = missing_state_command_dispatch;
            COMMANDS.take().unwrap()
        }
    }

    #[test]
    fn unchanged_nonterminal_state_emits_no_commands() {
        assert_eq!(commands_for(2, 2), []);
    }

    #[test]
    fn changed_even_state_emits_only_command_one() {
        assert_eq!(commands_for(2, 0), [(4, 1)]);
    }

    #[test]
    fn changed_odd_state_emits_reset_then_command_one() {
        assert_eq!(commands_for(1, 2), [(4, 0), (4, 1)]);
    }

    #[test]
    fn terminal_state_skips_reset_only_when_entering_one() {
        assert_eq!(commands_for(3, 1), [(4, 1)]);
        assert_eq!(commands_for(3, 3), [(4, 0), (4, 1)]);
    }
}
