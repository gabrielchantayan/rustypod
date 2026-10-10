//! Retail word-table indexed accessor, FUN_08086dd0 @ 0x08086dd0.
//! True extent: 32 bytes (28 code + pointer literal at 0x08086dec),
//! ending at the next real function at 0x08086df0. Raw A32 census:
//! two incoming plain BLs (0x08066f64, 0x081894e0), zero predicated;
//! zero outgoing plain or predicated BLs.
//! NULL output returns -50 without accessing the table. Otherwise read
//! one aligned word at 0x083e2568 + wrapping(index * 4), write output,
//! and return zero. This is the inverse accessor of retail_word_index;
//! callers truncate the returned word for stored/virtual-method identifiers.
//! No bounds check or table-content reconstruction. No target deviations;
//! host tests inject aligned table storage into the inlined implementation.

#[inline(always)]
unsafe fn word_at(index: u32, output: *mut u32, table: *const u32) -> i32 {
    if output.is_null() {
        return -50;
    }
    let source = table.cast::<u8>().wrapping_add(index.wrapping_mul(4) as usize).cast::<u32>();
    output.write(source.read());
    0
}

/// Output must be NULL or writable and word-aligned. The indexed retail
/// word must be readable and aligned; output may alias table storage.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn retail_word_at(index: u32, output: *mut u32) -> i32 {
    word_at(index, output, 0x083e2568usize as *const u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_output_bypasses_invalid_table_and_index() {
        unsafe {
            assert_eq!(retail_word_at(u32::MAX, core::ptr::null_mut()), -50);
            assert_eq!(word_at(u32::MAX, core::ptr::null_mut(), core::ptr::null()), -50);
        }
    }

    #[test]
    fn copies_full_words_with_wrapping_index_scale_and_no_neighbor_writes() {
        let table = [0, 0x80000000, u32::MAX, 0x12345678];
        for index in [0, 1, 2, 3, 0x40000000, 0x80000001, 0xc0000003] {
            let mut output = [0xa5a5a5a5; 3];
            unsafe {
                assert_eq!(word_at(index, output.as_mut_ptr().add(1), table.as_ptr()), 0);
            }
            assert_eq!(output, [0xa5a5a5a5, table[(index & 3) as usize], 0xa5a5a5a5]);
        }
    }

    #[test]
    fn output_can_alias_selected_or_other_table_word() {
        let mut table = [11, 22, 33];
        unsafe {
            assert_eq!(word_at(1, table.as_mut_ptr().add(1), table.as_ptr()), 0);
            assert_eq!(word_at(2, table.as_mut_ptr(), table.as_ptr()), 0);
        }
        assert_eq!(table, [33, 22, 33]);
    }
}
