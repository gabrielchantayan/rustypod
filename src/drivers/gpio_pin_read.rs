//! `gpio_pin_read` — original: `FUN_0836b6cc` @ 0x0836b6cc
//! (44 bytes; literal 0x3cf00000 follows at 0x0836b6f8; 13 unconditional
//! `bl` call sites, zero predicated forms, binary-scanned).
//!
//! Reads one S5L8702 GPIO pin level. The controller has eight pins per port:
//! `pin_id >> 3` selects a 0x20-byte port register block and `pin_id & 7`
//! selects its bit in the data word at offset 4. The result is normalized to
//! 0 or 1, written through `out`, and the function returns 0 unconditionally.
//!
//! On-device the port data register is read with one volatile word load. The
//! host build deliberately substitutes one volatile data word so tests can
//! exercise the exported entry point without mapping MMIO.

use super::gpio_cmd::GPIO_BASE;

/// Byte distance between successive eight-pin GPIO port register blocks.
const GPIO_PORT_STRIDE: u32 = 0x20;
/// Offset of a port's data word within its register block.
const GPIO_DATA_OFFSET: u32 = 4;

/// Address of the GPIO data word containing `pin_id`.
#[inline]
pub const fn gpio_data_address(pin_id: u32) -> usize {
    GPIO_BASE.wrapping_add(
        (pin_id >> 3)
            .wrapping_mul(GPIO_PORT_STRIDE)
            .wrapping_add(GPIO_DATA_OFFSET) as usize,
    )
}

/// Normalizes `pin_id`'s bit in a GPIO port data word to 0 or 1.
#[inline]
pub const fn gpio_pin_level(data_word: u32, pin_id: u32) -> u32 {
    ((data_word & (1 << (pin_id & 7))) != 0) as u32
}

/// gpio_pin_read — original @ 0x0836b6cc. Reads a GPIO pin level into `out`
/// and returns 0. `out` must point to one writable `u32`, as in retailOS.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn gpio_pin_read(pin_id: u32, out: *mut u32) -> u32 {
    core::ptr::write(out, gpio_pin_level(gpio_data_read(pin_id), pin_id));
    0
}

#[cfg(target_arch = "arm")]
#[inline(always)]
unsafe fn gpio_data_read(pin_id: u32) -> u32 {
    core::ptr::read_volatile(gpio_data_address(pin_id) as *const u32)
}

/// Host-side stand-in for the selected GPIO port's data word.
#[cfg(not(target_arch = "arm"))]
pub(crate) mod host_gpio_data {
    pub static mut DATA_WORD: u32 = 0;
}

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
unsafe fn gpio_data_read(_pin_id: u32) -> u32 {
    core::ptr::read_volatile(core::ptr::addr_of!(host_gpio_data::DATA_WORD))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Independent spelling of the ARM `ands` followed by `movne` sequence.
    fn reference(data_word: u32, pin_id: u32) -> u32 {
        if data_word & (1u32 << (pin_id & 7)) == 0 { 0 } else { 1 }
    }

    #[test]
    fn normalizes_each_bit_for_representative_port_data() {
        for pin_id in 0..=0xffu32 {
            for data_word in [0, 1, 0x80, 0xa5, 0xffff_ff00, 0xffff_ffff] {
                assert_eq!(gpio_pin_level(data_word, pin_id), reference(data_word, pin_id));
            }
        }
    }

    #[test]
    fn port_data_address_advances_every_eight_pins() {
        assert_eq!(gpio_data_address(0), GPIO_BASE + 4);
        assert_eq!(gpio_data_address(7), GPIO_BASE + 4);
        assert_eq!(gpio_data_address(8), GPIO_BASE + 0x24);
        assert_eq!(gpio_data_address(0xff), GPIO_BASE + 0x3e4);
    }

    #[test]
    fn entry_point_writes_normalized_level_and_returns_zero() {
        unsafe {
            core::ptr::write_volatile(core::ptr::addr_of_mut!(host_gpio_data::DATA_WORD), 0x80);
            let mut out = 0xffff_ffff;
            assert_eq!(gpio_pin_read(7, &mut out), 0);
            assert_eq!(out, 1);
            assert_eq!(gpio_pin_read(6, &mut out), 0);
            assert_eq!(out, 0);
        }
    }
}
