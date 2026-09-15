//! `cg_dependency_mask_lookup` — original: `FUN_082d07f8` @ `0x082d07f8`
//! (64 bytes, all code; five direct `bl` call sites, all unconditional).
//!
//! Raw `osos.dec` establishes the exact extent from `0x082d07f8` through
//! `bx lr` at `0x082d0834`; the next separately linked function begins at
//! `0x082d0838`.
//!
//! ## Algorithm
//!
//! Treats `context` as an aligned target-word table: word zero is a signed
//! count and subsequent words are identifiers. It scans for `identifier` and
//! returns a 64-bit mask with the matching index set, or zero when no entry
//! matches. The stock tail branch is the ARM ADS 64-bit left-shift helper.
//!
//! ## Deviations
//!
//! None. Shifts of 64 or more return zero, matching the ADS helper.

/// Looks up `identifier` in the target-word dependency table at `context`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cg_dependency_mask_lookup(context: *const u32, identifier: u32) -> u64 {
    let count = context.read() as i32;
    if count <= 0 {
        return 0;
    }

    let mut index = 0u32;
    while index < count as u32 {
        if context.add(index as usize + 1).read() == identifier {
            return if index < 64 { 1u64 << index } else { 0 };
        }
        index += 1;
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_first_and_high_half_entries() {
        let table = [64, 0x10, 0x20, 0x30];
        unsafe {
            assert_eq!(cg_dependency_mask_lookup(table.as_ptr(), 0x10), 1);
            assert_eq!(cg_dependency_mask_lookup(table.as_ptr(), 0x20), 2);
        }

        let mut high_table = [0u32; 65];
        high_table[0] = 64;
        high_table[64] = 0xfeed_face;
        assert_eq!(unsafe { cg_dependency_mask_lookup(high_table.as_ptr(), 0xfeed_face) }, 1u64 << 63);
    }

    #[test]
    fn rejects_missing_negative_and_out_of_range_matches() {
        let missing = [2, 0x10, 0x20];
        let negative = [u32::MAX, 0x10];
        let mut out_of_range = [0u32; 66];
        out_of_range[0] = 65;
        out_of_range[65] = 0xdead_beef;

        unsafe {
            assert_eq!(cg_dependency_mask_lookup(missing.as_ptr(), 0x30), 0);
            assert_eq!(cg_dependency_mask_lookup(negative.as_ptr(), 0x10), 0);
            assert_eq!(cg_dependency_mask_lookup(out_of_range.as_ptr(), 0xdead_beef), 0);
        }
    }
}
