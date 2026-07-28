//! `gpio_pin_configure` — original: `FUN_0836b5b0` @ 0x0836b5b0
//! (72 bytes: 68 code + the literal 0x3cf00000; 100 `bl` + 5 tail `b`
//! call sites, binary-scanned).
//!
//! The single choke point through which all of retailOS configures
//! S5L8702 GPIO pins. It writes one packed command word to the GPIO
//! controller's command register:
//!
//! ```text
//! GPIOCMD (0x3cf00000 + 0x200)  =  port << 16 | pin << 8 | function
//! ```
//!
//! `pin_id` is the flat pin number the rest of the firmware passes
//! around, split here into `port = pin_id >> 3` and `pin = pin_id & 7`
//! (8 pins per port, matching the S5L8702 GPIO grouping). Observed call
//! sites use ids 0x72/0x73/0x74 — port 14, pins 2/3/4.
//!
//! `mode` is the raw pin-function code, passed through masked to 8 bits,
//! with one special case: `mode == 1` means "drive as an output", and
//! then `level` selects the function code that also latches the output
//! level — 14 for low, 15 for high. Any other `level` with `mode == 1`
//! falls through to the plain `mode & 0xff` path and programs function
//! 1. That fall-through is the original's control flow, not a
//! simplification: the two `moveq`/`beq` pairs skip the mask, everything
//! else reaches it.
//!
//! Returns 0 unconditionally (the original's `mov r0, #0`); no caller
//! checks it.
//!
//! Structure: the packing is a pure function ([`gpio_command_word`]) so
//! it can be tested exhaustively on the host; only the register store
//! touches hardware, and that store is mocked off-target the same way
//! `kernel/csem.rs` mocks the cpsr.

/// S5L8702 GPIO controller base.
pub const GPIO_BASE: usize = 0x3cf0_0000;

/// Command register: one write configures one pin.
pub const GPIOCMD: usize = GPIO_BASE + 0x200;

/// `mode` value meaning "drive this pin as an output".
pub const MODE_OUTPUT: u32 = 1;

/// Function code for an output driven low (`mode == 1`, `level == 0`).
pub const FUNCTION_OUTPUT_LOW: u32 = 14;

/// Function code for an output driven high (`mode == 1`, `level == 1`).
pub const FUNCTION_OUTPUT_HIGH: u32 = 15;

/// Packs a GPIOCMD word. See the module header for the `mode`/`level`
/// rules; this is the whole of the original's logic bar the store.
#[inline]
pub fn gpio_command_word(pin_id: u32, mode: u32, level: i32) -> u32 {
    let port = pin_id >> 3;
    let pin = pin_id & 7;
    let function = match (mode, level) {
        (MODE_OUTPUT, 0) => FUNCTION_OUTPUT_LOW,
        (MODE_OUTPUT, 1) => FUNCTION_OUTPUT_HIGH,
        _ => mode & 0xff,
    };
    port << 16 | pin << 8 | function
}

/// gpio_pin_configure — original @ 0x0836b5b0. Programs one GPIO pin's
/// function (and, for outputs, its level) and returns 0.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn gpio_pin_configure(pin_id: u32, mode: u32, level: i32) -> u32 {
    gpiocmd_write(gpio_command_word(pin_id, mode, level));
    0
}

/// The hardware store (host: records the word instead).
#[cfg(target_arch = "arm")]
#[inline(always)]
unsafe fn gpiocmd_write(command: u32) {
    core::ptr::write_volatile(GPIOCMD as *mut u32, command);
}

/// Host-side stand-in for the GPIO command register.
#[cfg(not(target_arch = "arm"))]
pub(crate) mod host_gpiocmd {
    /// Last word written by [`super::gpio_pin_configure`].
    pub static mut LAST_COMMAND: u32 = 0;
    /// Number of writes since the process started.
    pub static mut WRITE_COUNT: usize = 0;
}

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
unsafe fn gpiocmd_write(command: u32) {
    use core::ptr::{addr_of, addr_of_mut};
    core::ptr::write_volatile(addr_of_mut!(host_gpiocmd::LAST_COMMAND), command);
    let count = core::ptr::read_volatile(addr_of!(host_gpiocmd::WRITE_COUNT));
    core::ptr::write_volatile(addr_of_mut!(host_gpiocmd::WRITE_COUNT), count + 1);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Independent reference: the packing as the disassembly spells it.
    fn reference(pin_id: u32, mode: u32, level: i32) -> u32 {
        let mut function = mode;
        let mut masked = true;
        if mode == 1 {
            if level == 0 {
                function = 14;
                masked = false;
            } else if level == 1 {
                function = 15;
                masked = false;
            }
        }
        if masked {
            function &= 0xff;
        }
        ((pin_id >> 3) << 16) | ((pin_id & 7) << 8) | function
    }

    #[test]
    fn matches_reference_over_the_whole_input_space() {
        for pin_id in 0..=0xffu32 {
            for mode in [0u32, 1, 2, 3, 13, 14, 15, 0xff, 0x100, 0x1ff, 0xffff_ffff] {
                for level in [-2i32, -1, 0, 1, 2, 0x7fff_ffff] {
                    assert_eq!(
                        gpio_command_word(pin_id, mode, level),
                        reference(pin_id, mode, level),
                        "pin_id={pin_id:#x} mode={mode:#x} level={level}"
                    );
                }
            }
        }
    }

    /// The three call-site shapes actually present in osos.
    #[test]
    fn known_call_sites() {
        // 0x08078a78: alternate function 2 on port 14 pins 2/3/4.
        assert_eq!(gpio_command_word(0x72, 2, 0), 0x0e_02_02);
        assert_eq!(gpio_command_word(0x73, 2, 0), 0x0e_03_02);
        assert_eq!(gpio_command_word(0x74, 2, 0), 0x0e_04_02);
        // 0x08060a34: output low on port 14 pin 4.
        assert_eq!(gpio_command_word(0x74, 1, 0), 0x0e_04_0e);
    }

    #[test]
    fn output_mode_folds_the_level_into_the_function_code() {
        assert_eq!(gpio_command_word(0, 1, 0) & 0xff, FUNCTION_OUTPUT_LOW);
        assert_eq!(gpio_command_word(0, 1, 1) & 0xff, FUNCTION_OUTPUT_HIGH);
        // Any other level with mode 1 programs function 1 verbatim.
        assert_eq!(gpio_command_word(0, 1, 2) & 0xff, 1);
        assert_eq!(gpio_command_word(0, 1, -1) & 0xff, 1);
    }

    #[test]
    fn other_modes_are_masked_to_eight_bits_and_ignore_level() {
        for level in [-1i32, 0, 1, 5] {
            assert_eq!(gpio_command_word(0x3f, 0x1_07, level), 0x07_07_07);
        }
    }

    #[test]
    fn port_and_pin_split_at_three_bits() {
        assert_eq!(gpio_command_word(0x00, 0, 9), 0x00_00_00);
        assert_eq!(gpio_command_word(0x07, 0, 9), 0x00_07_00);
        assert_eq!(gpio_command_word(0x08, 0, 9), 0x01_00_00);
        assert_eq!(gpio_command_word(0xff, 0, 9), 0x1f_07_00);
    }

    #[test]
    fn entry_point_stores_the_word_and_returns_zero() {
        use core::ptr::addr_of;
        unsafe {
            let before = core::ptr::read_volatile(addr_of!(host_gpiocmd::WRITE_COUNT));
            assert_eq!(gpio_pin_configure(0x72, 2, 0), 0);
            assert_eq!(
                core::ptr::read_volatile(addr_of!(host_gpiocmd::LAST_COMMAND)),
                0x0e_02_02
            );
            assert_eq!(
                core::ptr::read_volatile(addr_of!(host_gpiocmd::WRITE_COUNT)),
                before + 1
            );
        }
    }
}
