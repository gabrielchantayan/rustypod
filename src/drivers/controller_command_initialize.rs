//! Controller command-word initializer — `FUN_0836dde8` @ `0x0836dde8` (64
//! bytes including its four literal-pool words; Ghidra reports only the
//! 48-byte instruction span; 2 verified unconditional `bl` call sites,
//! no predicated `bl`).
//!
//! Selects one of four controller blocks. Selector zero maps to
//! `0x3cc00000`, one to `0x3cc04000`, two to `0x3cc08000`, and every other
//! value to `0x3cc0c000`. It writes `0x00015c85` to the selected block's
//! command word at offset four. The store is volatile because these are MMIO
//! registers. Host builds use backing words to exercise the selector mapping.
//!
//! Deliberate deviation: the host backing array replaces the fixed MMIO
//! addresses; target builds use the exact addresses and command value decoded
//! from the raw ARM literal pool.

const CONTROLLER_BASE_0: usize = 0x3cc0_0000;
const CONTROLLER_BASE_1: usize = 0x3cc0_4000;
const CONTROLLER_BASE_2: usize = 0x3cc0_8000;
const CONTROLLER_BASE_OTHER: usize = 0x3cc0_c000;
const COMMAND_OFFSET: usize = 4;
const INITIAL_COMMAND: u32 = 0x0001_5c85;

#[cfg(not(target_os = "none"))]
static mut HOST_CONTROLLER_COMMANDS: [u32; 4] = [0; 4];

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn command_word(selector: u32) -> *mut u32 {
    let base = match selector {
        0 => CONTROLLER_BASE_0,
        1 => CONTROLLER_BASE_1,
        2 => CONTROLLER_BASE_2,
        _ => CONTROLLER_BASE_OTHER,
    };
    base.wrapping_add(COMMAND_OFFSET) as *mut u32
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn command_word(selector: u32) -> *mut u32 {
    let index = match selector {
        0 => 0,
        1 => 1,
        2 => 2,
        _ => 3,
    };
    unsafe { core::ptr::addr_of_mut!(HOST_CONTROLLER_COMMANDS[index]) }
}

/// Writes the retailOS initial command value to a selected controller block.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn controller_command_initialize(selector: u32) {
    unsafe { command_word(selector).write_volatile(INITIAL_COMMAND) };
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn initializes_each_explicit_controller() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            HOST_CONTROLLER_COMMANDS = [0; 4];
            for selector in 0..3 {
                controller_command_initialize(selector);
            }
            assert_eq!(HOST_CONTROLLER_COMMANDS, [INITIAL_COMMAND, INITIAL_COMMAND, INITIAL_COMMAND, 0]);
        }
    }

    #[test]
    fn aliases_all_other_selectors_to_the_fourth_controller() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            HOST_CONTROLLER_COMMANDS = [0; 4];
            controller_command_initialize(3);
            controller_command_initialize(u32::MAX);
            assert_eq!(HOST_CONTROLLER_COMMANDS, [0, 0, 0, INITIAL_COMMAND]);
        }
    }
}
