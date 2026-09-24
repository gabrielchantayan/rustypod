//! Panel format-register updater — original: `FUN_08076cbc` @ 0x08076cbc.
//!
//! Raw `osos.dec` words establish a 168-byte A32 body
//! `0x08076cbc..0x08076d64`; `0x08076d64..0x08076d6c` is its three-word literal
//! pool, and the next real function starts at `0x08076d70`. The body has one
//! unconditional `bl` and no predicated calls (and three incoming `bl` call
//! sites). It combines panel state bytes 6 and 7 with the incoming `r0`, adds
//! the 14-bit check field computed by `0x080e75f0`, then writes duplicated
//! format words to the LCD controller registers at offsets 0x3c4/0x3cc and
//! 0x3c8/0x3d4, plus 0x440c at offset 0x14.
//!
//! Deliberate deviation: the otherwise-unidentified leaf callee at
//! `0x080e75f0` is kept as a private, descriptively named helper rather than
//! creating an unverified public seam. The exported ABI retains `r0` because
//! raw code preserves it when state byte 7 is outside 0..=3, despite Ghidra's
//! `void` callers.

const PANEL_STATE_ADDRESS: usize = 0x089c_c9b4;
const LCD_CONTROLLER_ADDRESS: usize = 0x3930_0000;
const PANEL_CONFIGURATION_WORD: u32 = 0x0000_440c;

#[cfg(not(target_os = "none"))]
static mut PANEL_STATE: *mut u8 = PANEL_STATE_ADDRESS as *mut u8;
#[cfg(not(target_os = "none"))]
static mut LCD_CONTROLLER: *mut u8 = LCD_CONTROLLER_ADDRESS as *mut u8;

#[inline(always)]
unsafe fn panel_state() -> *mut u8 {
    #[cfg(target_os = "none")]
    { PANEL_STATE_ADDRESS as *mut u8 }
    #[cfg(not(target_os = "none"))]
    { core::ptr::read_volatile(core::ptr::addr_of!(PANEL_STATE)) }
}

#[inline(always)]
unsafe fn lcd_controller() -> *mut u8 {
    #[cfg(target_os = "none")]
    { LCD_CONTROLLER_ADDRESS as *mut u8 }
    #[cfg(not(target_os = "none"))]
    { core::ptr::read_volatile(core::ptr::addr_of!(LCD_CONTROLLER)) }
}

/// Reproduces the 14-round check-field encoder at 0x080e75f0.
#[inline(always)]
fn panel_format_check_bits(mut value: u32) -> u32 {
    let mut check_bits = 0x1f;
    let mut previous_sum = 1;
    let mut sum = 0;
    let mut bit = 0;
    while bit < 14 {
        sum = (check_bits & 1) + (value & 1);
        if sum == 2 {
            sum = 0;
        }
        previous_sum += sum;
        if previous_sum == 2 {
            previous_sum = 0;
        }
        check_bits >>= 1;
        if previous_sum != 0 {
            check_bits |= 0x10;
        }
        value >>= 1;
        previous_sum = sum;
        bit += 1;
    }
    check_bits + sum * 0x20
}

/// Refreshes LCD panel format registers from the shared panel state.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn panel_refresh_format_registers(input: u32) {
    let state = panel_state();
    let selector = match state.add(7).read() {
        0 => 0,
        1 => 1,
        2 => 2,
        3 => 3,
        _ => input,
    };
    let mode_is_set = u32::from(state.add(6).read() != 0);
    let format = mode_is_set | (selector << 6);
    let controller = lcd_controller();
    let checked_format = format | (panel_format_check_bits(format) << 14);
    controller.add(0x3c4).cast::<u32>().write(checked_format);
    controller.add(0x3cc).cast::<u32>().write(checked_format);

    let register_mode = match state.add(6).read() {
        0 => 8,
        1 => 7,
        2 => 1,
        _ => mode_is_set,
    } | if state.add(7).read() != 0 { 3 << 12 } else { 0 };
    controller.add(0x3c8).cast::<u32>().write(register_mode);
    controller.add(0x3d4).cast::<u32>().write(register_mode);
    controller.add(0x14).cast::<u32>().write(PANEL_CONFIGURATION_WORD);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use core::ptr;
    use std::sync::{Mutex, MutexGuard};

    use super::*;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    struct Restore {
        state: *mut u8,
        controller: *mut u8,
        _lock: MutexGuard<'static, ()>,
    }

    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe {
                PANEL_STATE = self.state;
                LCD_CONTROLLER = self.controller;
            }
        }
    }

    fn install(state: *mut u8, controller: *mut u8) -> Restore {
        let lock = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            let old_state = PANEL_STATE;
            let old_controller = LCD_CONTROLLER;
            PANEL_STATE = state;
            LCD_CONTROLLER = controller;
            Restore { state: old_state, controller: old_controller, _lock: lock }
        }
    }

    fn reference_check_bits(mut value: u32) -> u32 {
        let mut shift_register = 0x1f;
        let mut carry = 1;
        for _ in 0..14 {
            let bit_sum = (shift_register & 1) ^ (value & 1);
            carry ^= bit_sum;
            shift_register = (shift_register >> 1) | if carry != 0 { 0x10 } else { 0 };
            value >>= 1;
            carry = bit_sum;
        }
        shift_register | (carry << 5)
    }

    #[test]
    fn known_selectors_update_all_duplicate_registers() {
        for (mode, selector) in [(0, 0), (1, 1), (2, 2), (9, 3)] {
            let mut state = [0u8; 8];
            let mut controller = [0xa5u8; 0x3d8];
            state[6] = mode;
            state[7] = selector;
            let _restore = install(state.as_mut_ptr(), controller.as_mut_ptr());

            unsafe { panel_refresh_format_registers(0xffff_ffff) };

            let format = u32::from(mode != 0) | (u32::from(selector) << 6);
            let checked = format | (reference_check_bits(format) << 14);
            unsafe {
                assert_eq!(ptr::read(controller.as_ptr().add(0x3c4).cast::<u32>()), checked);
                assert_eq!(ptr::read(controller.as_ptr().add(0x3cc).cast::<u32>()), checked);
                assert_eq!(ptr::read(controller.as_ptr().add(0x3c8).cast::<u32>()), match mode { 0 => 8, 1 => 7, 2 => 1, _ => 1 } | if selector != 0 { 3 << 12 } else { 0 });
                assert_eq!(ptr::read(controller.as_ptr().add(0x3d4).cast::<u32>()), match mode { 0 => 8, 1 => 7, 2 => 1, _ => 1 } | if selector != 0 { 3 << 12 } else { 0 });
                assert_eq!(ptr::read(controller.as_ptr().add(0x14).cast::<u32>()), PANEL_CONFIGURATION_WORD);
            }
        }
    }

    #[test]
    fn out_of_range_selector_preserves_input_register() {
        let mut state = [0u8; 8];
        let mut controller = [0u8; 0x3d8];
        state[6] = 4;
        state[7] = 9;
        let _restore = install(state.as_mut_ptr(), controller.as_mut_ptr());

        unsafe { panel_refresh_format_registers(0x1234_5678) };

        let format = 1 | (0x1234_5678 << 6);
        let checked = format | (reference_check_bits(format) << 14);
        unsafe {
            assert_eq!(ptr::read(controller.as_ptr().add(0x3c4).cast::<u32>()), checked);
            assert_eq!(ptr::read(controller.as_ptr().add(0x3c8).cast::<u32>()), 0x3001);
        }
    }
}
