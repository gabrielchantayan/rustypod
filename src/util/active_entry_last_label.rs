//! Last assigned label in a selected active-entry table.
//!
//! FUN_08165e6c @ 0x08165e6c: true extent 92 bytes, ending at the next
//! function's PUSH at 0x08165ec8 (76 code bytes, 16 literal bytes).
//! Raw A32: zero outgoing plain BLs, zero predicated BLs; two inbound
//! plain BLs at 0x081e1b0c and 0x081e1b4c, no predicated inbound BLs.
//! Select the mode's primary/secondary table and its stored u16 count;
//! return the low halfword of the aligned word at table + count*8 - 4.
//! Counts are produced by assign_active_entry_labels during construction.
//! Deliberate deviations: semantic fixed-width fields replace byte offsets;
//! volatile accesses preserve runtime-mutated table reads. Host-only table
//! bases permit fixtures without treating the firmware's resource bytes as
//! immutable data. Zero count retains the original preceding-word access.

#[repr(C)]
pub struct ActiveEntrySelection {
    pub mode: u8,
    pub reserved: u8,
    pub enabled_primary_count: u16,
    pub disabled_primary_count: u16,
    pub enabled_secondary_count: u16,
    pub disabled_secondary_count: u16,
}

// Order: disabled secondary, disabled primary, enabled secondary, enabled primary.
#[cfg(target_os = "none")]
const TABLE_BASES: [usize; 4] = [0x08a0_e818, 0x08a0_e7f0, 0x08a0_e7a0, 0x08a0_e738];
#[cfg(not(target_os = "none"))]
static mut TABLE_BASES: [usize; 4] = [0x08a0_e818, 0x08a0_e7f0, 0x08a0_e7a0, 0x08a0_e738];

/// # Safety
/// `selection` must be readable and halfword-aligned. The selected runtime
/// table must contain a readable aligned word at base + count*8 - 4,
/// including the preceding word for count zero. Host base replacement
/// requires exclusive access.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn active_entry_last_label(
    selection: *const ActiveEntrySelection, primary: u32,
) -> u32 {
    let enabled = core::ptr::read_volatile(core::ptr::addr_of!((*selection).mode)) != 0;
    let primary = primary != 0;
    let count_ptr = match (enabled, primary) {
        (true, true) => core::ptr::addr_of!((*selection).enabled_primary_count),
        (false, true) => core::ptr::addr_of!((*selection).disabled_primary_count),
        (true, false) => core::ptr::addr_of!((*selection).enabled_secondary_count),
        (false, false) => core::ptr::addr_of!((*selection).disabled_secondary_count),
    };
    let count = core::ptr::read_volatile(count_ptr) as usize;
    let index = (enabled as usize) * 2 + primary as usize;
    #[cfg(target_os = "none")]
    let base = TABLE_BASES[index];
    #[cfg(not(target_os = "none"))]
    let base = core::ptr::addr_of!(TABLE_BASES).cast::<usize>().add(index).read_volatile();
    let address = base.wrapping_add(count * 8).wrapping_sub(4);
    core::ptr::read_volatile(address as *const u32) & 0xffff
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec;

    #[test]
    fn selects_all_tables_and_counts_with_zero_and_maximum_boundaries() {
        // The sole host user of this private seam; restore even on assertion failure.
        struct Restore([usize; 4]);
        impl Drop for Restore {
            fn drop(&mut self) { unsafe { TABLE_BASES = self.0; } }
        }
        let mut tables = [vec![0u32; 131071], vec![0u32; 131071],
                          vec![0u32; 131071], vec![0u32; 131071]];
        for (table_index, table) in tables.iter_mut().enumerate() {
            for count in 0..=u16::MAX as usize {
                table[count * 2] = 0xa5a5_0000 | ((count as u32 ^ (0x1111 * (table_index as u32 + 1))) & 0xffff);
            }
        }
        unsafe {
            let _restore = Restore(TABLE_BASES);
            for i in 0..4 { TABLE_BASES[i] = tables[i].as_ptr().add(1) as usize; }
            for mode in [0, 1, 2, 255] {
                for primary in [0, 1, 2, u32::MAX] {
                    for count in [0u16, 1, 2, 32768, 65535] {
                        let mut selection = ActiveEntrySelection {
                            mode, reserved: 0xff,
                            enabled_primary_count: 3, disabled_primary_count: 4,
                            enabled_secondary_count: 5, disabled_secondary_count: 6,
                        };
                        let index = usize::from(mode != 0) * 2 + usize::from(primary != 0);
                        match index {
                            0 => selection.disabled_secondary_count = count,
                            1 => selection.disabled_primary_count = count,
                            2 => selection.enabled_secondary_count = count,
                            _ => selection.enabled_primary_count = count,
                        }
                        let expected = (count as u32 ^ (0x1111 * (index as u32 + 1))) & 0xffff;
                        assert_eq!(active_entry_last_label(&selection, primary), expected);
                    }
                }
            }
        }
    }
}
