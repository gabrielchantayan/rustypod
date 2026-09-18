//! Assign consecutive labels to active entries in a sentinel-terminated table.

/// assign_active_entry_labels — original: `FUN_08165dd0` @ **0x08165dd0**
/// (**60 bytes exactly**, `0x08165dd0..0x08165e0c`; the next distinct function
/// starts at `0x08165e0c`).
///
/// Raw osos.dec establishes no outgoing `bl` instructions: 0 plain and 0
/// predicated. Four inbound plain `bl` sites occur in `FUN_08165f6c`
/// (0x08165f94, 0x08165fa8, 0x08165fbc, and 0x08165fd0); none is predicated.
/// Starting at `entries`, the routine stops at the first record whose aligned
/// active word at +4 is zero. It stores the current 16-bit label at +0,
/// increments the caller-owned label, and returns the number of labels written
/// with bit 16 cleared after every increment.
///
/// Deliberate deviations: the unused first ABI argument is represented by
/// `_owner`; the retail object's identity is unknown. `wrapping_add` and the
/// explicit bit clear retain the ARM counter behavior at the 16-bit rollover.
/// Volatile record accesses retain the firmware's ordered halfword/word loads
/// and stores.
///
/// # Safety
///
/// When `entries` is non-null, it must point to writable eight-byte records
/// terminated by a record with a zero `active` word. `next_label` must point to
/// a writable, aligned `u16` for every active record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
struct ActiveEntry {
    label: u16,
    _reserved: u16,
    active: u32,
}

#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn assign_active_entry_labels(
    _owner: *mut core::ffi::c_void,
    mut entries: *mut ActiveEntry,
    next_label: *mut u16,
) -> u32 {
    let mut assigned = 0u32;
    if entries.is_null() {
        return assigned;
    }

    while core::ptr::read_volatile(core::ptr::addr_of!((*entries).active)) != 0 {
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!((*entries).label),
            core::ptr::read_volatile(next_label),
        );
        core::ptr::write_volatile(
            next_label,
            core::ptr::read_volatile(next_label).wrapping_add(1),
        );
        assigned = assigned.wrapping_add(1) & !0x0001_0000;
        entries = entries.add(1);
    }
    assigned
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::{assign_active_entry_labels, ActiveEntry};

    fn reference_assign(entries: &mut [ActiveEntry], next_label: &mut u16) -> u32 {
        let mut assigned = 0u32;
        for entry in entries {
            if entry.active == 0 {
                break;
            }
            entry.label = *next_label;
            *next_label = next_label.wrapping_add(1);
            assigned = assigned.wrapping_add(1) & !0x0001_0000;
        }
        assigned
    }

    #[test]
    fn labels_active_prefix_and_leaves_sentinel_untouched() {
        let initial = [
            ActiveEntry { label: 0xaaaa, _reserved: 0x1111, active: 7 },
            ActiveEntry { label: 0xbbbb, _reserved: 0x2222, active: 1 },
            ActiveEntry { label: 0xcccc, _reserved: 0x3333, active: 0 },
            ActiveEntry { label: 0xdddd, _reserved: 0x4444, active: 9 },
        ];
        let mut expected = initial;
        let mut actual = initial;
        let mut expected_next = 0xfffe;
        let mut actual_next = expected_next;

        let expected_count = reference_assign(&mut expected, &mut expected_next);
        let actual_count = unsafe {
            assign_active_entry_labels(core::ptr::null_mut(), actual.as_mut_ptr(), &mut actual_next)
        };

        assert_eq!(actual_count, expected_count);
        assert_eq!(actual_next, expected_next);
        assert_eq!(actual[0].label, 0xfffe);
        assert_eq!(actual[1].label, 0xffff);
        assert_eq!(actual[2].label, 0xcccc);
        assert_eq!(actual, expected);
    }

    #[test]
    fn null_entries_returns_zero_without_accessing_label_pointer() {
        let result = unsafe {
            assign_active_entry_labels(core::ptr::null_mut(), core::ptr::null_mut(), 1usize as *mut u16)
        };
        assert_eq!(result, 0);
    }

    #[test]
    fn assigned_count_clears_bit_sixteen_after_65536_entries() {
        let mut entries = std::vec![
            ActiveEntry { label: 0, _reserved: 0, active: 1 };
            0x1_0000
        ];
        entries.push(ActiveEntry { label: 0xfeed, _reserved: 0, active: 0 });
        let mut next_label = 0;
        let result = unsafe {
            assign_active_entry_labels(core::ptr::null_mut(), entries.as_mut_ptr(), &mut next_label)
        };

        assert_eq!(result, 0);
        assert_eq!(next_label, 0);
        assert_eq!(entries[0].label, 0);
        assert_eq!(entries[0xffff].label, 0xffff);
        assert_eq!(entries[0x1_0000].label, 0xfeed);
    }
}
