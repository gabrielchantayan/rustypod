//! Retail word-table first-match lookup, FUN_080c6294 @ 0x080c6294.
//! True extent: 80 bytes (76 code + table-pointer literal at 0x080c62e0),
//! next real function at 0x080c62e4. Whole-image aligned A32 decoding:
//! two inbound plain BLs (0x08051c08, 0x08179098), zero predicated BLs;
//! zero outbound plain or predicated BLs.
//! NULL output returns -50 without reading the table. Otherwise scan exactly
//! 23 aligned words at 0x083e2568, returning the first matching index and zero.
//! No match writes UINT32_MAX and returns -50. Table identity is not inferred:
//! the supplied firmware bytes at that address decode as code, so retain the
//! runtime address rather than reconstructing or embedding table contents.
//! Deviation: host tests supply aligned storage to the inlined implementation;
//! the exported function retains the original address and behavior.

#[inline(always)]
unsafe fn find_word(value: u32, output: *mut u32, table: *const u32) -> i32 {
    if output.is_null() {
        return -50;
    }
    for index in 0..23usize {
        if table.add(index).read() == value {
            output.write(index as u32);
            return 0;
        }
    }
    output.write(u32::MAX);
    -50
}

/// Output must be NULL or writable and word-aligned. The 23-word retail
/// table must be readable; output may alias table storage.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn retail_word_index(value: u32, output: *mut u32) -> i32 {
    find_word(value, output, 0x083e2568usize as *const u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_output_does_not_read_table() {
        unsafe {
            assert_eq!(retail_word_index(u32::MAX, core::ptr::null_mut()), -50);
            assert_eq!(find_word(0, core::ptr::null_mut(), core::ptr::null()), -50);
        }
    }

    #[test]
    fn every_position_and_full_width_values() {
        let table: [u32; 23] = core::array::from_fn(|index| {
            if index == 0 { 0 } else if index == 22 { u32::MAX }
            else { 0x80000000 + index as u32 }
        });
        for (index, &value) in table.iter().enumerate() {
            let mut output = [0xa5a5a5a5; 3];
            let status = unsafe { find_word(value, output.as_mut_ptr().add(1), table.as_ptr()) };
            assert_eq!(status, 0);
            assert_eq!(output, [0xa5a5a5a5, index as u32, 0xa5a5a5a5]);
        }
    }

    #[test]
    fn duplicate_returns_first_and_output_can_alias_table() {
        let mut table = [7u32; 23];
        table[0] = 9;
        unsafe {
            assert_eq!(find_word(7, table.as_mut_ptr().add(22), table.as_ptr()), 0);
        }
        assert_eq!(table[22], 1);
        assert_eq!(table[0], 9);
        assert!(table[1..22].iter().all(|&word| word == 7));
    }

    #[test]
    fn miss_writes_sentinel_and_does_not_search_word_24() {
        let mut table = [11u32; 24];
        table[23] = 12;
        let mut output = [99u32; 3];
        unsafe {
            assert_eq!(find_word(12, output.as_mut_ptr().add(1), table.as_ptr()), -50);
        }
        assert_eq!(output, [99, u32::MAX, 99]);
    }
}
