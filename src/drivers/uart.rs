//! `uart_set_recovery_control_if_clear` — original: `FUN_0836e0a8` @
//! 0x0836e0a8 (104 bytes of code, followed by two literal words; the next
//! function begins at 0x0836e118). Raw `osos.dec` decoding finds five direct
//! `bl` callers: four unconditional (`0x080c9ca0`, `0x080c9cd4`,
//! `0x080cb6a0`, and `0x0836dfd4`) and one `blne` (`0x0836debc`).
//!
//! Selects one of the S5L8702 UARTC's four 0x4000-byte port blocks. If the
//! port control word at offset four does not have bit 17 set, writes the
//! retailOS recovery-control word `0x0003_5c85`; otherwise leaves it intact.
//! Values other than 0, 1, and 2 deliberately select port 3, exactly as the
//! ARM compare chain does. Deliberate deviations: named control bits are still
//! unknown, so the port only preserves the observed read-test-write behavior.

use core::ptr;

const UARTC_BASE: usize = 0x3cc0_0000;
const UARTC_PORT_STRIDE: usize = 0x4000;
const UARTC_CONTROL_OFFSET: usize = 4;
const UARTC_RECOVERY_CONTROL: u32 = 0x0003_5c85;
const UARTC_RECOVERY_CONTROL_SET: u32 = 1 << 17;

/// Returns the UARTC register-block base selected by retailOS's comparison
/// chain. Any value beyond port 2 maps to port 3.
#[inline]
pub const fn uartc_port_base(port: u32) -> usize {
    UARTC_BASE + match port {
        0 => 0,
        1 => UARTC_PORT_STRIDE,
        2 => UARTC_PORT_STRIDE * 2,
        _ => UARTC_PORT_STRIDE * 3,
    }
}

/// Applies the original read-test-write rule to a UARTC control word.
#[inline]
pub const fn uart_recovery_control(current_control: u32) -> u32 {
    if current_control & UARTC_RECOVERY_CONTROL_SET != 0 {
        current_control
    } else {
        UARTC_RECOVERY_CONTROL
    }
}

/// `FUN_0836e0a8` @ 0x0836e0a8. Enables the observed UART recovery-control
/// state only when bit 17 is currently clear.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn uart_set_recovery_control_if_clear(port: u32) {
    let control = uartc_port_base(port) + UARTC_CONTROL_OFFSET;
    let current = uart_control_read(control);
    if current & UARTC_RECOVERY_CONTROL_SET == 0 {
        uart_control_write(control, UARTC_RECOVERY_CONTROL);
    }
}

#[cfg(target_arch = "arm")]
#[inline(always)]
unsafe fn uart_control_read(control: usize) -> u32 {
    ptr::read_volatile(control as *const u32)
}

#[cfg(target_arch = "arm")]
#[inline(always)]
unsafe fn uart_control_write(control: usize, value: u32) {
    ptr::write_volatile(control as *mut u32, value);
}

#[cfg(not(target_arch = "arm"))]
static mut HOST_UART_CONTROL: [u32; 4] = [0; 4];

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
unsafe fn uart_control_read(control: usize) -> u32 {
    let port = (control - UARTC_BASE - UARTC_CONTROL_OFFSET) / UARTC_PORT_STRIDE;
    ptr::read_volatile(core::ptr::addr_of!(HOST_UART_CONTROL[port]))
}

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
unsafe fn uart_control_write(control: usize, value: u32) {
    let port = (control - UARTC_BASE - UARTC_CONTROL_OFFSET) / UARTC_PORT_STRIDE;
    ptr::write_volatile(core::ptr::addr_of_mut!(HOST_UART_CONTROL[port]), value);
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static UART_TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn recovery_control_replaces_a_clear_control_word() {
        assert_eq!(uart_recovery_control(0), UARTC_RECOVERY_CONTROL);
        assert_eq!(
            uart_recovery_control(0xffff_ffff & !UARTC_RECOVERY_CONTROL_SET),
            UARTC_RECOVERY_CONTROL
        );
    }

    #[test]
    fn recovery_control_preserves_an_already_recovering_port() {
        let control = UARTC_RECOVERY_CONTROL_SET | 0x4d85;
        assert_eq!(uart_recovery_control(control), control);
    }

    #[test]
    fn exported_function_selects_each_port_and_defaults_to_port_three() {
        let _lock = UART_TEST_LOCK.lock();
        unsafe {
            HOST_UART_CONTROL = [0, UARTC_RECOVERY_CONTROL_SET | 0x11, 0, 0];
            uart_set_recovery_control_if_clear(0);
            uart_set_recovery_control_if_clear(1);
            uart_set_recovery_control_if_clear(2);
            uart_set_recovery_control_if_clear(u32::MAX);
            assert_eq!(
                HOST_UART_CONTROL,
                [
                    UARTC_RECOVERY_CONTROL,
                    UARTC_RECOVERY_CONTROL_SET | 0x11,
                    UARTC_RECOVERY_CONTROL,
                    UARTC_RECOVERY_CONTROL,
                ]
            );
        }
    }

    #[test]
    fn port_bases_follow_the_firmware_comparison_chain() {
        assert_eq!(uartc_port_base(0), 0x3cc0_0000);
        assert_eq!(uartc_port_base(1), 0x3cc0_4000);
        assert_eq!(uartc_port_base(2), 0x3cc0_8000);
        assert_eq!(uartc_port_base(3), 0x3cc0_c000);
        assert_eq!(uartc_port_base(99), 0x3cc0_c000);
    }
}
