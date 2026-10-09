//! TrueType format-2 cmap subheader selection — `FUN_080c9cf0` at
//! 0x080c9cf0, 108 bytes, extent [0x080c9cf0, 0x080c9d5c).
//! Raw A32 decoding verifies two incoming plain BLs (0x08394b9c and
//! 0x08394c48), zero predicated incoming BLs, and zero outgoing BLs.
//! The next function starts with PUSH at 0x080c9d5c. Callers use the
//! returned big-endian firstCode, entryCount, idDelta and idRangeOffset.
//!
//! Reject codes above 0xffff. For single-byte codes, return subheader zero
//! only when their subHeaderKey is exactly zero. For two-byte codes, read
//! the high-byte key, clear its low three bits, and reject offset zero;
//! otherwise return that offset from the subheader array at table +0x206.
//! Deliberate deviations: native-width pointers on hosts; no target behavior
//! changes. Byte reads preserve the original's unaligned big-endian access.

/// Selects a subheader in a TrueType format-2 character map.
///
/// # Safety
/// For codes below 0x10000, `table` must reference a readable format-2
/// header and its 256 big-endian keys. The allocation must also contain
/// the selected subheader. Out-of-range codes do not access `table`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn tt_cmap2_subheader(table: *const u8, char_code: u32) -> *const u8 {
    if char_code >= 0x10000 {
        return core::ptr::null();
    }
    let high_byte = char_code >> 8;
    let key_index = if high_byte == 0 { char_code } else { high_byte };
    let key_bytes = table.add(6 + key_index as usize * 2);
    let key = u16::from_be_bytes([key_bytes.read(), key_bytes.add(1).read()]);
    if high_byte == 0 {
        if key != 0 {
            return core::ptr::null();
        }
        table.add(0x206)
    } else {
        let offset = key & !7;
        if offset == 0 {
            return core::ptr::null();
        }
        table.add(0x206 + offset as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::tt_cmap2_subheader;

    #[test]
    fn single_byte_keys_require_exact_zero() {
        let mut storage = [0u8; 0x220];
        // Deliberately odd table address: the firmware uses LDRB, not LDRH.
        let table = &mut storage[1..];
        for code in [0u32, 1, 127, 255] {
            for key in [0u16, 1, 7, 8, 0xffff] {
                let index = 6 + code as usize * 2;
                table[index..index + 2].copy_from_slice(&key.to_be_bytes());
                let expected = if key == 0 { unsafe { table.as_ptr().add(0x206) } }
                    else { core::ptr::null() };
                assert_eq!(unsafe { tt_cmap2_subheader(table.as_ptr(), code) }, expected);
            }
        }
    }

    #[test]
    fn double_byte_keys_mask_flags_and_ignore_low_byte() {
        let mut table = [0u8; 0x10206];
        for high in [1u32, 127, 255] {
            for key in [0u16, 1, 7, 8, 15, 0x108, 0x123f, 0xffff] {
                let index = 6 + high as usize * 2;
                table[index..index + 2].copy_from_slice(&key.to_be_bytes());
                let offset = (key as usize / 8) * 8;
                let expected = if offset == 0 { core::ptr::null() }
                    else { unsafe { table.as_ptr().add(0x206 + offset) } };
                for low in [0, 1, 127, 255] {
                    assert_eq!(unsafe { tt_cmap2_subheader(table.as_ptr(), high * 256 + low) }, expected);
                }
            }
        }
    }

    #[test]
    fn non_bmp_codes_do_not_read_table() {
        for code in [0x10000, 0x10001, 0x10ffff, u32::MAX] {
            assert!(unsafe { tt_cmap2_subheader(core::ptr::null(), code) }.is_null());
        }
    }
}
