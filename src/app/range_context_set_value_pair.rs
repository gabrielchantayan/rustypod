//! `range_context_set_value_pair` — `FUN_08140454` @ 0x08140454.
//!
//! True extent: 16 bytes [0x08140454,0x08140464). Raw words e8910006,
//! e5801024, e5802028, e12fff1e decode as ldmia r1,{r1,r2};
//! str r1,[r0,#0x24]; str r2,[r0,#0x28]; bx lr. The next independent
//! function at 0x08140464 starts with push {r0-r6,lr}.
//! Whole-image A32 decoding finds two incoming plain BLs at 0x081dc68c
//! and 0x081e8698, zero predicated BLs, and zero outgoing calls.
//!
//! Load both opaque value words before storing them to range-context words
//! 9 and 10. Callers supply pairs copied from larger range records; the
//! numeric interpretation is not established. Deliberate deviations: none.
//! Volatile word accesses preserve load-before-store overlap semantics and
//! avoid LLVM copy intrinsics. Target word indices remain correct on hosts.

/// # Safety
/// `context` must be four-byte aligned and writable through word 10;
/// `value` must be four-byte aligned and readable for two words. Neither
/// pointer is NULL-checked. Overlap is supported, including self-assignment.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn range_context_set_value_pair(context: *mut u32, value: *const u32) {
    let first = value.read_volatile();
    let second = value.add(1).read_volatile();
    context.add(9).write_volatile(first);
    context.add(10).write_volatile(second);
}

#[cfg(test)]
mod tests {
    use super::range_context_set_value_pair;

    #[test]
    fn replaces_only_value_pair_without_numeric_conversion() {
        for value in [[0, u32::MAX], [0x8000_0000, 0x7fff_ffff], [0x1122_3344, 0x5566_7788]] {
            let mut context = [0xa5a5_a5a5; 12];
            unsafe { range_context_set_value_pair(context.as_mut_ptr(), value.as_ptr()); }
            let mut expected = [0xa5a5_a5a5; 12];
            expected[9..11].copy_from_slice(&value);
            assert_eq!(context, expected);
        }
    }

    #[test]
    fn overlapping_source_is_snapshotted_before_writes() {
        for source_word in [8, 9, 10] {
            let mut context = [0, 1, 2, 3, 4, 5, 6, 7, 0x1122_3344, 0x5566_7788, 0x99aa_bbcc, 0xddee_ff00];
            let mut expected = context;
            expected[9] = context[source_word];
            expected[10] = context[source_word + 1];
            unsafe {
                let base = context.as_mut_ptr();
                range_context_set_value_pair(base, base.add(source_word));
            }
            assert_eq!(context, expected);
        }
    }
}
