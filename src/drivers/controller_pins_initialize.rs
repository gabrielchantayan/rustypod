//! Controller pin and register initialization.
//!
//! Original: `FUN_08078a78` @ `0x08078a78`; true extent 200 bytes
//! (`0x08078a78..0x08078b40`: 192 code bytes, two literals). Raw aligned
//! A32 decoding verifies two inbound plain BL calls (0x0836db54 and
//! 0x0836dba4), zero predicated inbound calls, and five plain outbound BLs.
//! Configures GPIO 0x72 in function 2, waits one millisecond, configures
//! GPIOs 0x73..0x75 likewise, then clears the controller's low control
//! fields, acknowledges status with 7, enables command bit 0, sets the
//! timer to 240000, and asserts control bits 20 and 21. Returns zero.
//!
//! Deliberate deviations: LLVM register allocation differs; volatile accesses
//! preserve every separate MMIO read/write. Host builds reuse the existing
//! controller register storage and GPIO/Timer E seams, not physical MMIO.

use super::controller_request_submit_wait::controller_words;
use super::gpio_cmd::gpio_pin_configure;
use super::timer::iram_msec_delay_veneer;

#[inline(always)]
unsafe fn initialize_registers(controller: *mut u32) {
    unsafe {
        controller.write_volatile(controller.read_volatile() & 0xffff_0000);
        controller.write_volatile(controller.read_volatile() & !0x0007_0000);
        controller.write_volatile(controller.read_volatile() & !0x0008_0000);
        controller.write_volatile(controller.read_volatile() & !0x0040_0000);
        controller.add(5).write_volatile(7);
        controller.add(4).write_volatile(controller.add(4).read_volatile() | 1);
        controller.add(2).write_volatile(240_000);
        controller.write_volatile(controller.read_volatile() | 0x0010_0000);
        controller.write_volatile(controller.read_volatile() | 0x0020_0000);
    }
}

/// Initializes the controller pins and registers; ignores GPIO/delay results
/// just as the original does. Caller must serialize access to the controller.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn controller_pins_initialize() -> u32 {
    unsafe {
        gpio_pin_configure(0x72, 2, 0);
        iram_msec_delay_veneer(1);
        gpio_pin_configure(0x73, 2, 0);
        gpio_pin_configure(0x74, 2, 0);
        gpio_pin_configure(0x75, 2, 0);
        initialize_registers(controller_words());
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clears_selected_fields_and_preserves_unrelated_registers() {
        for control in [0, u32::MAX, 0xaaaa_5555, 0x5555_aaaa, 0x004f_ffff] {
            for command in [0, u32::MAX, 0xaaaa_aaaa] {
                let mut words = [control, 0x1234_5678, u32::MAX, 0x8765_4321,
                    command, u32::MAX, 0xfeed_beef, 0xcafe_babe];
                unsafe { initialize_registers(words.as_mut_ptr()) };
                assert_eq!(words, [
                    (control & 0xffb0_0000) | 0x0030_0000,
                    0x1234_5678, 240_000, 0x8765_4321,
                    command | 1, 7, 0xfeed_beef, 0xcafe_babe,
                ]);
                // Reinitialization must preserve the same unrelated state.
                let initialized = words;
                unsafe { initialize_registers(words.as_mut_ptr()) };
                assert_eq!(words, initialized);
            }
        }
    }
}
