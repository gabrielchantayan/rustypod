//! Indexed resource-word lookup, retailOS FUN_080d8840 @ 0x080d8840.
//! True extent: 32 bytes (28 code + literal at 0x080d885c), ending at
//! the next function's push at 0x080d8860. Raw A32 census: zero outbound
//! plain/predicated BLs; two inbound plain BLs, zero predicated BLs
//! (0x0813e10c and 0x081723c4).
//! NULL output returns -50 without reading the table. Otherwise copy the
//! word at 0x083e250c + (index << 2) to output and return zero. Callers use
//! the result as a resource identifier; table length/content is not inferred.
//! No bounds check is present. Preserve 32-bit wrapping index scaling.
//! Deviation: tests supply ordinary aligned word storage to the inlined
//! implementation; the exported function retains the retail table address.

#[inline(always)]
unsafe fn lookup_word(index: u32, output: *mut u32, table: *const u32) -> i32 {
    if output.is_null() {
        return -50;
    }
    let source = table.cast::<u8>().wrapping_add(index.wrapping_mul(4) as usize).cast::<u32>();
    output.write(source.read());
    0
}

/// Output must be NULL or writable and word-aligned; the indexed retail
/// table address must be readable and aligned. No index validation is done.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn indexed_resource_word(index: u32, output: *mut u32) -> i32 {
    lookup_word(index, output, 0x083e250cusize as *const u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_output_never_reads_table_even_for_extreme_index() {
        unsafe {
            assert_eq!(indexed_resource_word(u32::MAX, core::ptr::null_mut()), -50);
            assert_eq!(lookup_word(0, core::ptr::null_mut(), core::ptr::null()), -50);
        }
    }

    #[test]
    fn word_stride_bit_patterns_and_wrapping_scale() {
        let table = [0, 0x80000000, u32::MAX, 0x12345678];
        for index in 0..4u32 {
            let mut output = [0xa5a5a5a5; 3];
            unsafe {
                assert_eq!(lookup_word(index, output.as_mut_ptr().add(1), table.as_ptr()), 0);
            }
            assert_eq!(output, [0xa5a5a5a5, table[index as usize], 0xa5a5a5a5]);
        }
        let mut output = 1;
        unsafe {
            assert_eq!(lookup_word(0x40000001, &mut output, table.as_ptr()), 0);
        }
        assert_eq!(output, 0x80000000);
    }

    #[test]
    fn output_may_alias_selected_word() {
        let mut table = [11, 22, 33];
        unsafe {
            assert_eq!(lookup_word(1, table.as_mut_ptr().add(1), table.as_ptr()), 0);
        }
        assert_eq!(table, [11, 22, 33]);
    }
}
