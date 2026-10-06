//! Select the count for a runtime active-entry table.
//!
//! FUN_08165e0c @ 0x08165e0c: true size 40 bytes, ending at the next
//! function's cmp r1,#0 at 0x08165e34. Raw A32 verifies zero outgoing
//! plain/predicated BLs and two incoming plain BLs at 0x081537bc and
//! 0x081537d0, with no predicated incoming BLs.
//! Nonzero enabled selects owner halfwords 1/3; zero selects 2/4.
//! Nonzero primary selects the first count in each pair. The caller sums
//! primary and secondary counts to size its serialized-entry buffer.
//! Deliberate deviations: none; use aligned unsigned halfword reads and
//! preserve all nonzero flag values as true. No callee seam is needed.

/// # Safety
/// `owner` must be halfword-aligned and readable at the selected halfword
/// index (1, 2, 3, or 4). No other halfword is read.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn active_entry_count(
    owner: *const u16, enabled: u32, primary: u32,
) -> u32 {
    let index = if enabled != 0 {
        if primary != 0 { 1 } else { 3 }
    } else if primary != 0 {
        2
    } else {
        4
    };
    owner.add(index).read() as u32
}

#[cfg(test)]
mod tests {
    use super::active_entry_count;

    #[test]
    fn selects_unsigned_counts_for_all_flag_classes() {
        for counts in [
            [0xdead, 0, 1, 0x8000, 0xffff],
            [0xbeef, 0xffff, 0x8000, 1, 0],
        ] {
            for enabled in [0, 1, 2, 0x8000_0000, u32::MAX] {
                for primary in [0, 1, 2, 0x8000_0000, u32::MAX] {
                    // Reference: byte offsets of the original conditional LDRHs.
                    let offset = match (enabled != 0, primary != 0) {
                        (true, true) => 2,
                        (true, false) => 6,
                        (false, true) => 4,
                        (false, false) => 8,
                    };
                    let expected = u32::from(counts[offset / 2]);
                    assert_eq!(unsafe {
                        active_entry_count(counts.as_ptr(), enabled, primary)
                    }, expected);
                }
            }
        }
    }
}
