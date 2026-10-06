//! Service-handler slot counted flag update.
//!
//! Original: `FUN_08194120` @ 0x08194120; true extent
//! [0x08194120, 0x08194190), 112 bytes, no literals. Whole-image aligned
//! ARM decoding finds two incoming plain BLs (0x081d70b8, 0x081d7178),
//! zero predicated incoming BLs. Outbound: two plain BLs to 0x08193f9c
//! and one signed `blge` to heap_panic @ 0x08030f44.
//!
//! Select an eight-word slot record, set/clear status bit 1 on transitions,
//! and adjust the byte counter at table+0xc8. Enable wraps at 255; disable
//! clears the flag even when the counter is zero, but never underflows it.
//! Repeated requests leave both fields unchanged; any nonzero enables.
//!
//! Deliberate deviation: inline the raw-verified query @ 0x08193f9c
//! (signed slot guard, word +0xc bit 1), rather than introducing a seam or
//! separately porting that function. Ghidra incorrectly omits its r1 argument.

use crate::heap::veneers::heap_panic;
use core::ptr;

/// Update a slot's counted flag, preserving unrelated status bits.
///
/// # Safety
/// `slot_table` must be word-aligned, with writable slot records and a byte
/// at +0xc8. Signed slots below three are accepted just as in retailOS;
/// negative slots require a valid preceding record in the same allocation.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn service_handler_slot_counted_flag_set(
    slot_table: *mut u32,
    slot: i32,
    enabled: u32,
) {
    if slot >= 3 {
        heap_panic();
    }
    let record = slot_table.wrapping_offset(slot.wrapping_shl(3) as isize);
    let status = ptr::read(record.add(3));
    let was_enabled = status & 2 != 0;
    let count = slot_table.cast::<u8>().add(0xc8);
    if enabled != 0 {
        if was_enabled {
            return;
        }
        ptr::write(record.add(3), status | 2);
        ptr::write(count, ptr::read(count).wrapping_add(1));
    } else {
        if !was_enabled {
            return;
        }
        ptr::write(record.add(3), status & !2);
        let old_count = ptr::read(count);
        if old_count != 0 {
            ptr::write(count, old_count - 1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_counter_values_and_transitions_preserve_other_records_and_bits() {
        for slot in 0..3 {
            for initial_flag in [false, true] {
                for enabled in [0, 1, 0x8000_0000, u32::MAX] {
                    for count in 0..=255u32 {
                        let mut table = [0xa5a5_5a5au32; 51];
                        let index = slot as usize * 8 + 3;
                        table[index] = (table[index] & !2) | if initial_flag { 2 } else { 0 };
                        table[50] = 0x1234_5600 | count;
                        let mut expected = table;
                        // Independent reference: only an actual flag transition
                        // changes status/count; disable at zero still clears status.
                        if initial_flag != (enabled != 0) {
                            expected[index] ^= 2;
                            let next = if enabled != 0 {
                                (count + 1) & 255
                            } else {
                                count.saturating_sub(1)
                            };
                            expected[50] = 0x1234_5600 | next;
                        }
                        unsafe { service_handler_slot_counted_flag_set(table.as_mut_ptr(), slot, enabled) };
                        assert_eq!(table, expected, "slot={slot}, flag={initial_flag}, enabled={enabled}, count={count}");
                    }
                }
            }
        }
    }

    #[test]
    fn signed_negative_slot_uses_preceding_record() {
        let mut storage = [0u32; 59];
        storage[3] = 0xfeed_0000;
        storage[58] = 7;
        unsafe { service_handler_slot_counted_flag_set(storage.as_mut_ptr().add(8), -1, 9) };
        assert_eq!(storage[3], 0xfeed_0002);
        assert_eq!(storage[58], 8);
        unsafe { service_handler_slot_counted_flag_set(storage.as_mut_ptr().add(8), -1, 0) };
        assert_eq!(storage[3], 0xfeed_0000);
        assert_eq!(storage[58], 7);
    }
}
