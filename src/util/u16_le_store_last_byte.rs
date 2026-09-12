//! Little-endian halfword store with the retail post-increment return register.

/// `store_u16_le_last_byte` — original: `FUN_080eda28` @ `0x080eda28` (16 bytes;
/// 8 verified direct inbound calls: 7 unconditional `bl`, 1 predicated `bllt`).
///
/// Raw ARM establishes the exact extent `0x080eda28..0x080eda34`: it writes the
/// low byte of `value`, shifts `value` right by eight, then writes that byte.
/// The first store uses post-index addressing, so `r0` returns `dst + 1`, the
/// address of the final byte. The routine has no NULL, alignment, or bounds guard.
/// Deliberate deviations: none.
///
/// # Safety
/// `dst` must be valid for two writable bytes.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.store_u16_le_last_byte")]
#[inline(never)]
pub unsafe extern "C" fn store_u16_le_last_byte(dst: *mut u8, value: u32) -> *mut u8 {
    dst.write(value as u8);
    let dst = dst.add(1);
    dst.write((value >> 8) as u8);
    dst
}

#[cfg(test)]
mod tests {
    use super::store_u16_le_last_byte;

    #[test]
    fn writes_low_half_little_endian_and_returns_final_byte_address() {
        let mut bytes = [0xa5u8; 5];
        let dst = unsafe { bytes.as_mut_ptr().add(1) };

        let returned = unsafe { store_u16_le_last_byte(dst, 0x89ab_4567) };

        assert_eq!(bytes, [0xa5, 0x67, 0x45, 0xa5, 0xa5]);
        assert_eq!(returned, unsafe { dst.add(1) });
    }

    #[test]
    fn stores_exactly_two_bytes_for_boundary_values_at_unaligned_offsets() {
        for value in [0, 1, 0x0100, 0xffff, 0x8000_0001, u32::MAX] {
            for offset in 0..=3 {
                let mut bytes = [0xa5u8; 6];
                let dst = unsafe { bytes.as_mut_ptr().add(offset) };
                let returned = unsafe { store_u16_le_last_byte(dst, value) };

                assert_eq!(&bytes[offset..offset + 2], &value.to_le_bytes()[..2]);
                assert!(bytes[..offset].iter().all(|&byte| byte == 0xa5));
                assert!(bytes[offset + 2..].iter().all(|&byte| byte == 0xa5));
                assert_eq!(returned, unsafe { dst.add(1) });
            }
        }
    }
}
