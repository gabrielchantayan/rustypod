//! Returns an address only when it lies in a non-wrapping half-open range.

/// `address_in_range_or_zero` — original: `FUN_0839bab8` @ `0x0839bab8`
/// (20 bytes; source: `ipod-decomp/decomp/c/034/0839bab8_FUN_0839bab8.c`).
///
/// Raw `osos.dec` words establish the complete body from `0x0839bab8` through
/// `0x0839bacc`; `cmp r0, r1` at `0x0839bacc` starts the next independently
/// linked function. It has no outgoing calls. Raw caller decoding finds three
/// inbound plain `bl` calls (0x080f405c, 0x080f4098, and 0x080f4214) and zero
/// predicated `bl` calls.
///
/// Returns `address` when `start <= address < start + length`, using the
/// original ARM unsigned comparisons. A wrapping `start + length` therefore
/// rejects every address, including when `length` is zero; otherwise it
/// returns zero.
///
/// Deliberate deviations: none.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub extern "C" fn address_in_range_or_zero(mut address: u32, mut start: u32, length: u32) -> u32 {
    if address >= start {
        start = start.wrapping_add(length);
        if start <= address {
            address = 0;
        }
    } else {
        address = 0;
    }
    address
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_addresses_inside_the_half_open_range() {
        assert_eq!(address_in_range_or_zero(0x1000, 0x1000, 0x20), 0x1000);
        assert_eq!(address_in_range_or_zero(0x101f, 0x1000, 0x20), 0x101f);
    }

    #[test]
    fn rejects_addresses_outside_or_at_the_end() {
        assert_eq!(address_in_range_or_zero(0x0fff, 0x1000, 0x20), 0);
        assert_eq!(address_in_range_or_zero(0x1020, 0x1000, 0x20), 0);
        assert_eq!(address_in_range_or_zero(0x1000, 0x1000, 0), 0);
    }

    #[test]
    fn rejects_a_range_that_wraps_past_u32_max() {
        assert_eq!(address_in_range_or_zero(u32::MAX, 0xffff_fff0, 0x20), 0);
        assert_eq!(address_in_range_or_zero(0, 0xffff_fff0, 0x20), 0);
    }
}
