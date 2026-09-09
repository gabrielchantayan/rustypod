//! `gpio_pin_write` — original: `FUN_0836b744` @ 0x0836b744
//! (52 bytes: 48 code + the literal 0x3cf00000 at 0x0836b778; the next
//! function starts at 0x0836b77c. 12 unconditional `bl` + 2 tail `b`
//! call sites, binary-scanned; zero predicated forms).
//!
//! Drives one S5L8702 GPIO output pin. The controller has eight pins per
//! port: `pin_id >> 3` selects a 0x20-byte port register block and
//! `pin_id & 7` selects the bit in the data word at offset 4 — the exact
//! geometry of the already-ported `gpio_pin_read` @ 0x0836b6cc, which
//! this function is the write sibling of. `level == 0` clears the pin's
//! bit (`biceq`), any other value sets it (`orrne`), and the function
//! returns 0 unconditionally.
//!
//! On-device the port data register is updated with a volatile
//! read-modify-write. The host build deliberately substitutes one
//! volatile data word so tests can exercise the exported entry point
//! without mapping MMIO.

use super::gpio_pin_read::gpio_data_address;

/// Applies `level` to `pin_id`'s bit of a GPIO port data word:
/// `level == 0` clears the bit, anything else sets it.
#[inline]
pub const fn gpio_pin_drive(data_word: u32, pin_id: u32, level: i32) -> u32 {
    let mask = 1u32 << (pin_id & 7);
    if level == 0 { data_word & !mask } else { data_word | mask }
}

/// gpio_pin_write — original @ 0x0836b744. Sets or clears one GPIO pin
/// and returns 0. As in retailOS, any nonzero `level` means high.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn gpio_pin_write(pin_id: u32, level: i32) -> u32 {
    gpio_data_write(pin_id, gpio_pin_drive(gpio_data_read(pin_id), pin_id, level));
    0
}

#[cfg(target_arch = "arm")]
#[inline(always)]
unsafe fn gpio_data_read(pin_id: u32) -> u32 {
    core::ptr::read_volatile(gpio_data_address(pin_id) as *const u32)
}

#[cfg(target_arch = "arm")]
#[inline(always)]
unsafe fn gpio_data_write(pin_id: u32, data_word: u32) {
    core::ptr::write_volatile(gpio_data_address(pin_id) as *mut u32, data_word);
}

/// Host-side stand-in for the selected GPIO port's data word, shared
/// with `gpio_pin_read` so a write here is observable there.
#[cfg(not(target_arch = "arm"))]
pub(crate) mod host_gpio_out {
    pub static mut DATA_WORD: u32 = 0;
}

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
unsafe fn gpio_data_read(_pin_id: u32) -> u32 {
    core::ptr::read_volatile(core::ptr::addr_of!(host_gpio_out::DATA_WORD))
}

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
unsafe fn gpio_data_write(_pin_id: u32, data_word: u32) {
    core::ptr::write_volatile(core::ptr::addr_of_mut!(host_gpio_out::DATA_WORD), data_word);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Independent spelling of the ARM `cmp` + `biceq`/`orrne` pair.
    fn reference(data_word: u32, pin_id: u32, level: i32) -> u32 {
        let mask = 1u32 << (pin_id & 7);
        if level == 0 { data_word & !mask } else { data_word | mask }
    }

    #[test]
    fn drives_each_bit_for_representative_port_data() {
        for pin_id in 0..=0xffu32 {
            for data_word in [0, 1, 0x80, 0xa5, 0xffff_ff00, 0xffff_ffff] {
                for level in [i32::MIN, -1, 0, 1, 2, i32::MAX] {
                    assert_eq!(
                        gpio_pin_drive(data_word, pin_id, level),
                        reference(data_word, pin_id, level),
                        "data_word={data_word:#x} pin_id={pin_id:#x} level={level}"
                    );
                }
            }
        }
    }

    #[test]
    fn set_and_clear_leave_the_other_bits_untouched() {
        assert_eq!(gpio_pin_drive(0, 0x1b, 1), 0x08); // port 3 pin 3
        assert_eq!(gpio_pin_drive(0xff, 0x1b, 0), 0xf7);
        assert_eq!(gpio_pin_drive(0xa5a5_a5a5, 0x61, 1), 0xa5a5_a5a7);
        assert_eq!(gpio_pin_drive(0xa5a5_a5a5, 0x61, 0), 0xa5a5_a5a5);
    }

    #[test]
    fn entry_point_updates_the_data_word_and_returns_zero() {
        unsafe {
            let word = core::ptr::addr_of_mut!(host_gpio_out::DATA_WORD);
            core::ptr::write_volatile(word, 0);
            assert_eq!(gpio_pin_write(7, 1), 0);
            assert_eq!(core::ptr::read_volatile(word), 0x80);
            // Any nonzero level sets; the bit stays set on repeat writes.
            assert_eq!(gpio_pin_write(7, -3), 0);
            assert_eq!(core::ptr::read_volatile(word), 0x80);
            assert_eq!(gpio_pin_write(7, 0), 0);
            assert_eq!(core::ptr::read_volatile(word), 0);
        }
    }
}
