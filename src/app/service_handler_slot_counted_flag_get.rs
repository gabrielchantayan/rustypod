//! Service-handler slot counted flag query.
//!
//! Original: `FUN_08193f9c` @ 0x08193f9c; true extent
//! [0x08193f9c, 0x08193fb8), 28 bytes, no literals. Whole-image aligned
//! ARM decoding finds two incoming plain BLs (0x08194140, 0x08194164),
//! zero predicated incoming BLs. Outbound: zero plain BLs and one signed
//! `blge` to heap_panic @ 0x08030f44.
//!
//! Reject signed slots >= 3, select the 32-byte record, and return word
//! +0xc bit 1 normalized to 0 or 1. Negative slots remain unchecked.
//! No deliberate behavioral deviations; word indexing preserves target
//! record layout on hosts with wider pointers. LLVM supplies a return frame
//! for the non-returning panic call rather than retaining the original leaf.

use crate::heap::veneers::heap_panic;
use core::ptr;

/// Read a slot's counted flag without changing its record.
///
/// # Safety
/// `slot_table` must be word-aligned and the selected status word readable.
/// Negative slots require preceding storage in the same allocation.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn service_handler_slot_counted_flag_get(
    slot_table: *const u32,
    slot: i32,
) -> u32 {
    if slot >= 3 {
        heap_panic();
    }
    let record = slot_table.wrapping_offset(slot.wrapping_shl(3) as isize);
    (ptr::read(record.add(3)) & 2) >> 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selects_each_record_and_normalizes_only_bit_one() {
        for slot in 0..3 {
            for status in [0, 1, 2, 3, 4, 0x8000_0000, 0xffff_fffd, u32::MAX] {
                let mut table = [0x5555_5555u32; 24];
                table[slot as usize * 8 + 3] = status;
                let before = table;
                let actual = unsafe { service_handler_slot_counted_flag_get(table.as_ptr(), slot) };
                assert_eq!(actual, (status / 2) % 2, "slot={slot}, status={status:#x}");
                assert_eq!(table, before);
            }
        }
    }

    #[test]
    fn signed_negative_slots_read_preceding_records() {
        let mut storage = [0u32; 24];
        storage[3] = 0xffff_fffd;
        storage[11] = 0x8000_0002;
        let table = unsafe { storage.as_ptr().add(16) };
        assert_eq!(unsafe { service_handler_slot_counted_flag_get(table, -2) }, 0);
        assert_eq!(unsafe { service_handler_slot_counted_flag_get(table, -1) }, 1);
    }
}
