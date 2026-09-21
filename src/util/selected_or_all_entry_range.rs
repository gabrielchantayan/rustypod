//! Selected-or-all entry index range.

/// selected_or_all_entry_range — original: `FUN_08299700` @ **0x08299700**
/// (**56 bytes exactly**, `0x08299700..0x08299737`; the separately linked next
/// function begins at `0x08299738`).
///
/// Raw A32 words decode to one outbound unconditional `bl` (and zero
/// predicated `bl` instructions), plus the three inbound plain `bl` call sites
/// identified by whole-image branch decoding; no predicated inbound calls.
/// When `owner + 0xf4` is not `u32::MAX`, it writes that selected index to both
/// outputs. Otherwise it writes zero as the first index and the entry-list
/// count minus one as the last index. The retail helper at `0x08299d78` only
/// reads the list word at `+8`, so its body is deliberately inlined instead of
/// introducing an unverified callee seam.
///
/// # Safety
/// `owner` must be valid for aligned reads at offsets `0xbc` and `0xf4`; when
/// the selected word is `u32::MAX`, the list pointer at `owner + 0xbc` must be
/// valid for an aligned read at offset `+8`. `first` and `last` must be valid
/// aligned output words.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn selected_or_all_entry_range(owner: *const u32, first: *mut u32, last: *mut u32) {
    let selected = owner.add(0xf4 / 4).read();

    if selected == u32::MAX {
        first.write(0);
        let entries = owner.add(0xbc / 4).read() as *const u32;
        last.write(entries.add(8 / 4).read().wrapping_sub(1));
    } else {
        first.write(selected);
        last.write(selected);
    }
}

#[cfg(test)]
mod tests {
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    use super::selected_or_all_entry_range;

    #[test]
    fn selected_index_becomes_a_single_entry_range() {
        let mut owner = [0u32; 0xf4 / 4 + 1];
        owner[0xf4 / 4] = 37;
        let mut first = u32::MAX;
        let mut last = u32::MAX;

        unsafe { selected_or_all_entry_range(owner.as_ptr(), &mut first, &mut last) };

        assert_eq!((first, last), (37, 37));
    }

    #[test]
    fn unselected_range_covers_all_entries_and_wraps_empty_count() {
        let Some(slab) = try_map_u32_slab(hints::SELECTED_OR_ALL_ENTRY_RANGE, 0x1000) else {
            assert!(note_missing_u32_fixture("util::selected_or_all_entry_range"));
            return;
        };

        let owner = slab as *mut u32;
        let entries = unsafe { slab.add(0x400) as *mut u32 };
        for count in [0, 1, 0x1234_5678] {
            unsafe {
                owner.add(0xf4 / 4).write(u32::MAX);
                owner.add(0xbc / 4).write(entries as usize as u32);
                entries.add(8 / 4).write(count);
            }
            let mut first = u32::MAX;
            let mut last = 0;

            unsafe { selected_or_all_entry_range(owner, &mut first, &mut last) };

            assert_eq!((first, last), (0, count.wrapping_sub(1)));
        }
    }
}

