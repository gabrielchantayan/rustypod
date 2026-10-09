//! Board GPIO pin identifier — `FUN_080e3254` @ 0x080e3254.
//! True extent: 8 bytes, ending before independently called `cff_lookup_glyph`
//! at 0x080e325c. Raw words: e3a00056 (`mov r0,#0x56`), e12fff1e (`bx lr`).
//! Verified inbound calls: two unconditional BLs at 0x080bd960 and 0x08393a50;
//! zero predicated BLs and no outgoing calls.
//!
//! Returns pin 86 (GPIO port 10, bit 6), without arguments or memory access.
//! The first caller passes the identifier to `gpio_pin_read`; the second
//! compares it to the 0xc8 no-pin sentinel. The board signal's role is not
//! identified. No deliberate behavioral deviations.
//! ARM codegen keeps `mov r0,#86`; LLVM adds a frame-pointer push/setup/pop
//! instead of the original `bx lr`. The result and calling convention agree.

/// Returns the board's fixed GPIO pin identifier (not its current level).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub extern "C" fn board_gpio_pin_86() -> u32 {
    0x56
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drivers::gpio_pin_read::{gpio_data_address, gpio_pin_read, host_gpio_data};

    #[test]
    fn caller_reads_only_port_10_bit_6() {
        let _guard = host_gpio_data::LOCK.lock();
        let pin_id = board_gpio_pin_86();
        assert_eq!(gpio_data_address(pin_id), 0x3cf0_0144);
        unsafe {
            let saved = core::ptr::read_volatile(core::ptr::addr_of!(host_gpio_data::DATA_WORD));
            for (data, expected) in [
                (0, 0), (0x40, 1), (0x20, 0), (0x80, 0),
                (0xffff_ffbf, 0), (0xffff_ffff, 1),
            ] {
                core::ptr::write_volatile(core::ptr::addr_of_mut!(host_gpio_data::DATA_WORD), data);
                let mut level = u32::MAX;
                assert_eq!(gpio_pin_read(pin_id, &mut level), 0);
                assert_eq!(level, expected);
            }
            core::ptr::write_volatile(core::ptr::addr_of_mut!(host_gpio_data::DATA_WORD), saved);
        }
    }
}
