//! `storage_backend_pin_89_status` — original: `FUN_082bc488` @ `0x082bc488`.
//! True extent: 48 bytes (`0x082bc488..0x082bc4b7`); the next independently
//! called function starts at `0x082bc4b8`. Full raw ARM scan finds two plain
//! unconditional BL callers and zero predicated BL callers; one outgoing BL.
//!
//! Reads GPIO pin 0x59 through `gpio_pin_read`. A failed read returns 0;
//! otherwise a zero level returns 2 and any nonzero level returns 3.
//! Deliberate deviation: initialize the local level to zero instead of saving
//! incoming r3 in the stack slot. The verified callee always overwrites that
//! slot before returning, so incoming r3 is not an argument. No other changes.

use super::gpio_pin_read::gpio_pin_read;

#[inline]
fn state_from_read(status: u32, level: u32) -> u32 {
    if status != 0 { 0 } else if level == 0 { 2 } else { 3 }
}

/// Returns the retailOS state code for GPIO pin 0x59.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn storage_backend_pin_89_status() -> u32 {
    let mut level = 0;
    let status = gpio_pin_read(0x59, &mut level);
    state_from_read(status, level)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn successful_reads_distinguish_zero_from_any_nonzero_level() {
        for level in [0, 1, 2, 0x8000_0000, u32::MAX] {
            let expected = if level == 0 { 2 } else { 3 };
            assert_eq!(state_from_read(0, level), expected);
        }
    }

    #[test]
    fn read_failure_takes_precedence_over_the_level() {
        for status in [1, 2, 0x8000_0000, u32::MAX] {
            for level in [0, 1, u32::MAX] {
                assert_eq!(state_from_read(status, level), 0);
            }
        }
    }
}
