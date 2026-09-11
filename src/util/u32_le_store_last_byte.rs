//! Little-endian word store with the retail post-increment return register.

/// `store_u32_le_last_byte` — original: `FUN_080eda38` @ 0x080eda38 (28 bytes;
/// 10 verified unconditional `bl` call sites, no predicated `bl` forms).
///
/// Raw ARM establishes the exact extent 0x080eda38..0x080eda54: it derives
/// bits 8, 16, and 24 of `value`, writes four alignment-free bytes in
/// little-endian order, and uses post-index addressing for the first three
/// stores. Consequently, r0 returns `dst + 3`, the address of the final byte;
/// all ten direct callers discard it. The routine has no NULL or bounds guard.
/// Deliberate deviations: none.
///
/// # Safety
/// `dst` must be valid for four writable bytes.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.store_u32_le_last_byte")]
#[inline(never)]
pub unsafe extern "C" fn store_u32_le_last_byte(dst: *mut u8, value: u32) -> *mut u8 {
    dst.write(value as u8);
    let dst = dst.add(1);
    dst.write((value >> 8) as u8);
    let dst = dst.add(1);
    dst.write((value >> 16) as u8);
    let dst = dst.add(1);
    dst.write((value >> 24) as u8);
    dst
}

#[cfg(test)]
mod tests {
    use super::store_u32_le_last_byte;

    #[test]
    fn writes_little_endian_bytes_and_returns_final_byte_address() {
        let mut bytes = [0xa5u8; 6];
        let dst = unsafe { bytes.as_mut_ptr().add(1) };

        let returned = unsafe { store_u32_le_last_byte(dst, 0x0123_4567) };

        assert_eq!(bytes, [0xa5, 0x67, 0x45, 0x23, 0x01, 0xa5]);
        assert_eq!(returned, unsafe { dst.add(3) });
    }

    #[test]
    fn stores_exactly_four_bytes_for_boundary_values_at_unaligned_offsets() {
        for value in [0, 1, 0x0100, 0x8000_0001, 0x89ab_cdef, u32::MAX] {
            for offset in 0..=3 {
                let mut bytes = [0xa5u8; 8];
                let dst = unsafe { bytes.as_mut_ptr().add(offset) };
                let returned = unsafe { store_u32_le_last_byte(dst, value) };

                assert_eq!(&bytes[offset..offset + 4], value.to_le_bytes());
                assert!(bytes[..offset].iter().all(|&byte| byte == 0xa5));
                assert!(bytes[offset + 4..].iter().all(|&byte| byte == 0xa5));
                assert_eq!(returned, unsafe { dst.add(3) });
            }
        }
    }
}
