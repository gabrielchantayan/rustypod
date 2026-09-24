//! `input_command_dispatch` — original: `FUN_080921dc` @ **0x080921dc**
//! (**72 code bytes**, `0x080921dc..0x08092220`; the next function begins at
//! `0x08092230`; `0x08092224..0x0809222c` is this function's literal pool).
//!
//! Raw ARM has one outbound plain `bl` (to `0x080e2ef4`), one inbound plain
//! `bl` (`0x080e183c`), and one inbound predicated `blne` (`0x080a8e2c`). The
//! mode-one path is a predicated tail `b` to `0x080e2ef4`, not a `bl`.
//!
//! # Algorithm
//!
//! Mode zero dispatches selector `0x0003_0004` with a zero middle argument and
//! `slot` as the final argument, then records the low byte of `slot`. Mode one
//! tail-dispatches selector `0x0003_0003` with the same arguments. Other modes
//! return without observable effects.
//!
//! Deliberate deviation: the `0x080e2ef4` dispatcher has no recovered identity
//! in `names.yaml`; target builds call its fixed retailOS address, while host
//! builds use explicit dispatcher and last-slot seams.

const RETAIL_INPUT_COMMAND_DISPATCHER: usize = 0x080e_2ef4;
const MODE_ONE_SELECTOR: u32 = 0x0003_0003;
const MODE_ZERO_SELECTOR: u32 = 0x0003_0004;

/// ABI observed at the unresolved retail command dispatcher.
pub type InputCommandDispatcher = unsafe extern "C" fn(u32, u32, u32);

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn dispatch_input_command(selector: u32, slot: u32) {
    let dispatch: InputCommandDispatcher = unsafe { core::mem::transmute(RETAIL_INPUT_COMMAND_DISPATCHER) };
    unsafe { dispatch(selector, 0, slot) };
}

/// Host seam for the unresolved retail command dispatcher.
#[cfg(not(target_os = "none"))]
pub static mut INPUT_COMMAND_DISPATCHER: InputCommandDispatcher = missing_input_command_dispatcher;

#[cfg(not(target_os = "none"))]
static mut LAST_MODE_ZERO_SLOT: u8 = 0;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_input_command_dispatcher(_selector: u32, _zero: u32, _slot: u32) {}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn dispatch_input_command(selector: u32, slot: u32) {
    let dispatch = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(INPUT_COMMAND_DISPATCHER)) };
    unsafe { dispatch(selector, 0, slot) };
}

/// Dispatches a retailOS input command for `slot`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn input_command_dispatch(slot: u32, mode: u32) {
    if mode == 0 {
        unsafe { dispatch_input_command(MODE_ZERO_SELECTOR, slot) };
        #[cfg(target_os = "none")]
        unsafe { core::ptr::write_volatile(0x089d_05c4 as *mut u8, slot as u8) };
        #[cfg(not(target_os = "none"))]
        unsafe { LAST_MODE_ZERO_SLOT = slot as u8 };
    } else if mode == 1 {
        unsafe { dispatch_input_command(MODE_ONE_SELECTOR, slot) };
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::Mutex;
    use std::vec::Vec;

    static DISPATCH_LOCK: Mutex<()> = Mutex::new(());
    static mut DISPATCHES: Option<Vec<(u32, u32, u32)>> = None;

    unsafe extern "C" fn record_dispatch(selector: u32, zero: u32, slot: u32) {
        unsafe { DISPATCHES.as_mut().unwrap().push((selector, zero, slot)) };
    }

    fn dispatches_for(slot: u32, mode: u32) -> (Vec<(u32, u32, u32)>, u8) {
        let _guard = DISPATCH_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            DISPATCHES = Some(Vec::new());
            LAST_MODE_ZERO_SLOT = 0xa5;
            INPUT_COMMAND_DISPATCHER = record_dispatch;
            input_command_dispatch(slot, mode);
            INPUT_COMMAND_DISPATCHER = missing_input_command_dispatcher;
            (DISPATCHES.take().unwrap(), LAST_MODE_ZERO_SLOT)
        }
    }

    #[test]
    fn mode_zero_dispatches_then_records_slot_low_byte() {
        assert_eq!(dispatches_for(0x1234_56ab, 0), (std::vec![(MODE_ZERO_SELECTOR, 0, 0x1234_56ab)], 0xab));
    }

    #[test]
    fn mode_one_dispatches_without_touching_mode_zero_slot() {
        assert_eq!(dispatches_for(0x1234_56ab, 1), (std::vec![(MODE_ONE_SELECTOR, 0, 0x1234_56ab)], 0xa5));
    }

    #[test]
    fn other_modes_have_no_effect() {
        assert_eq!(dispatches_for(9, 2), (std::vec![], 0xa5));
    }
}
