//! `lcd_command_mode_get` — original: `FUN_080a3f48` @ 0x080a3f48.
//! True extent: 72 bytes (68 code + cache-address literal at 0x080a3f8c);
//! next function begins at 0x080a3f90. Full-image ARM word decoding finds
//! 2 unconditional inbound BL sites, zero predicated; the body likewise has
//! 2 unconditional outbound BLs, both to `gpio_pin_read` @ 0x0836b6cc.
//!
//! Returns the word cached at 0x089cab64. Only sentinel 4 samples GPIO 0x34
//! then 0x35, combining their normalized levels as low | (high << 1) and
//! storing the mode. Other cache values pass through unchanged. Callers
//! select LCD command timing and display configuration from modes 0..3.
//! Ghidra's four arguments are saved scratch registers, not inputs.
//!
//! Deliberate deviations: volatile cache accesses preserve the final reload;
//! scratch locals start at zero because the verified GPIO callee overwrites
//! them. Host builds substitute a cache word and the existing GPIO fixture.

use super::gpio_pin_read::gpio_pin_read;

#[cfg(not(target_arch = "arm"))]
static mut HOST_LCD_MODE_CACHE: u32 = 4;

#[inline(always)]
unsafe fn mode_cache() -> *mut u32 {
    #[cfg(target_arch = "arm")]
    { 0x089c_ab64 as *mut u32 }
    #[cfg(not(target_arch = "arm"))]
    { core::ptr::addr_of_mut!(HOST_LCD_MODE_CACHE) }
}

/// # Safety
/// Device cache and GPIO registers must be accessible. Like retailOS, this
/// query is unsynchronized; callers must serialize cache initialization.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn lcd_command_mode_get() -> u32 {
    let cache = mode_cache();
    if core::ptr::read_volatile(cache) == 4 {
        let mut low = 0;
        let mut high = 0;
        gpio_pin_read(0x34, &mut low);
        gpio_pin_read(0x35, &mut high);
        core::ptr::write_volatile(cache, low | (high << 1));
    }
    core::ptr::read_volatile(cache)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drivers::gpio_pin_read::host_gpio_data;
    use core::ptr::{addr_of_mut, read_volatile, write_volatile};

    #[test]
    fn sentinel_samples_both_bits_once_and_retains_mode_when_gpio_changes() {
        let _guard = host_gpio_data::LOCK.lock();
        unsafe {
            let cache = mode_cache();
            let saved_cache = read_volatile(cache);
            let gpio = addr_of_mut!(host_gpio_data::DATA_WORD);
            let saved_gpio = read_volatile(gpio);
            for (data, expected) in [(0xcf, 0), (0xdf, 1), (0xef, 2), (0xff, 3)] {
                write_volatile(cache, 4);
                write_volatile(gpio, data);
                assert_eq!(lcd_command_mode_get(), expected);
                assert_eq!(read_volatile(cache), expected);
                write_volatile(gpio, !data);
                assert_eq!(lcd_command_mode_get(), expected);
            }
            write_volatile(cache, saved_cache);
            write_volatile(gpio, saved_gpio);
        }
    }

    #[test]
    fn every_non_sentinel_cache_value_passes_through_without_reclassification() {
        let _guard = host_gpio_data::LOCK.lock();
        unsafe {
            let cache = mode_cache();
            let saved = read_volatile(cache);
            for value in [0, 1, 2, 3, 5, 0x8000_0000, u32::MAX] {
                write_volatile(cache, value);
                assert_eq!(lcd_command_mode_get(), value);
                assert_eq!(read_volatile(cache), value);
            }
            write_volatile(cache, saved);
        }
    }
}
