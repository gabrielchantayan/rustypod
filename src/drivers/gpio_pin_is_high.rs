//! `gpio_pin_is_high` — original: `FUN_082743a0` @ `0x082743a0`.
//! Raw extent: 60 bytes (`0x082743a0..0x082743db`); the next independently
//! entered function begins at `0x082743dc`. Raw ARM scan finds three direct,
//! plain unconditional `bl` callers and zero predicated `bl` callers.
//!
//! Returns false for the `0xc8` no-pin sentinel. Otherwise reads the selected
//! GPIO pin through `gpio_pin_read` and normalizes its result to false or true.
//!
//! Deliberate deviation: Rust retains the callee's output as a local `u32`
//! rather than spelling the ARM stack slot; its observable value and call are
//! unchanged.

use super::gpio_pin_read::gpio_pin_read;

/// Returns whether `pin_id` is high. `0xc8` is retailOS's no-pin sentinel.
///
/// Original: `FUN_082743a0` @ `0x082743a0`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn gpio_pin_is_high(pin_id: u32) -> u32 {
    if pin_id == 0xc8 {
        return 0;
    }

    let mut level = 0;
    gpio_pin_read(pin_id, &mut level);
    (level != 0) as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drivers::gpio_pin_read::host_gpio_data;

    #[test]
    fn returns_false_for_no_pin_without_observing_gpio() {
        unsafe {
            core::ptr::write_volatile(core::ptr::addr_of_mut!(host_gpio_data::DATA_WORD), 0xff);
            assert_eq!(gpio_pin_is_high(0xc8), 0);
        }
    }

    #[test]
    fn normalizes_gpio_read_result_for_set_and_clear_bits() {
        unsafe {
            core::ptr::write_volatile(core::ptr::addr_of_mut!(host_gpio_data::DATA_WORD), 0x80);
            assert_eq!(gpio_pin_is_high(7), 1);
            assert_eq!(gpio_pin_is_high(6), 0);
        }
    }
}
