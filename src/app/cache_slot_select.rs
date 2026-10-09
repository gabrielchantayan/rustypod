//! `cache_slot_select` — `FUN_080fde38` @ 0x080fde38.
//! True extent [0x080fde38, 0x080fdf08): 208 bytes, no literals.
//! Raw A32 decoding verifies two incoming plain BLs (0x080f9968,
//! 0x080f9fb0), zero incoming predicated BLs, and no outgoing BLs.
//!
//! Scan 60-byte cache records, returning the first invalid or zero-age slot.
//! Otherwise prefer the smallest unsigned age among clean slots, then dirty
//! slots. Notification-requested slots with negative age instead increment
//! their cooldown and compete for the greatest updated value above -13.
//! Strict comparisons preserve first-index ties; no candidate returns zero.
//! Callers reuse the selected record for block transfers and flush dirty data.
//! Deliberate deviation: volatile field accesses retain the retail scan/write
//! order; the opaque manager is addressed with target byte offsets, not host
//! pointer sizes. No callee seam or allocation is needed.

use core::ptr;

/// Select a replacement slot, advancing negative notification cooldowns.
///
/// # Safety
/// `manager` must be four-byte aligned and writable, with a count word at
/// +0x468 and that many 60-byte records beginning at +0x480. Each record
/// has age at +0, dirty at +4, valid at +5, and notification request at +0x24.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn cache_slot_select(manager: *mut u8) -> u32 {
    let mut index = 0u32;
    let mut clean_age = u32::MAX;
    let mut dirty_age = u32::MAX;
    let mut clean_index = u32::MAX;
    let mut dirty_index = u32::MAX;
    let mut cooldown_index = 0;
    let mut greatest_cooldown = -13i32;

    while index < unsafe { ptr::read_volatile(manager.add(0x468).cast::<u32>()) } {
        let record = unsafe { manager.add(0x480 + index as usize * 0x3c) };
        let age_ptr = record.cast::<u32>();
        let notification = unsafe { ptr::read_volatile(record.add(0x24)) };
        let cooldown = if notification == 1 {
            (unsafe { ptr::read_volatile(age_ptr) }) as i32
        } else { 0 };
        if notification == 1 && cooldown < 0 {
            let age = cooldown + 1;
            if age > greatest_cooldown {
                greatest_cooldown = age;
                cooldown_index = index;
            }
            unsafe { ptr::write_volatile(age_ptr, age as u32) };
        } else {
            if unsafe { ptr::read_volatile(record.add(5)) } == 0 {
                return index;
            }
            let age = unsafe { ptr::read_volatile(age_ptr) };
            if age == 0 {
                return index;
            }
            match unsafe { ptr::read_volatile(record.add(4)) } {
                1 if age < dirty_age => {
                    dirty_age = age;
                    dirty_index = index;
                }
                0 if age < clean_age => {
                    clean_age = age;
                    clean_index = index;
                }
                _ => {}
            }
        }
        index += 1;
    }
    if clean_index != u32::MAX { clean_index }
    else if dirty_index != u32::MAX { dirty_index }
    else { cooldown_index }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    fn run(records: &mut [[u32; 15]]) -> (u32, std::vec::Vec<u32>) {
        let mut object = std::vec![0xa5a5a5a5u32; 0x480 / 4 + records.len() * 15 + 1];
        object[0x468 / 4] = records.len() as u32;
        for (index, record) in records.iter().enumerate() {
            object[0x480 / 4 + index * 15..0x480 / 4 + (index + 1) * 15]
                .copy_from_slice(record);
        }
        let result = unsafe { cache_slot_select(object.as_mut_ptr().cast()) };
        for (index, record) in records.iter_mut().enumerate() {
            record.copy_from_slice(&object[0x480 / 4 + index * 15..0x480 / 4 + (index + 1) * 15]);
        }
        (result, object)
    }

    fn slot(age: i32, dirty: u8, valid: u8, notification: u8) -> [u32; 15] {
        let mut record = [0xcccccccc; 15];
        record[0] = age as u32;
        record[1] = u32::from_le_bytes([dirty, valid, 0xcc, 0xcc]);
        record[9] = u32::from_le_bytes([notification, 0xcc, 0xcc, 0xcc]);
        record
    }

    #[test]
    fn empty_and_no_candidate_return_zero() {
        assert_eq!(run(&mut []).0, 0);
        assert_eq!(run(&mut [slot(-1, 2, 1, 0), slot(4, 2, 1, 0)]).0, 0);
    }

    #[test]
    fn clean_precedes_dirty_and_ties_keep_first() {
        assert_eq!(run(&mut [slot(1, 1, 1, 0), slot(9, 0, 1, 0),
            slot(3, 0, 1, 0), slot(3, 0, 1, 0)]).0, 2);
        assert_eq!(run(&mut [slot(8, 1, 1, 0), slot(2, 1, 1, 0),
            slot(2, 1, 1, 0)]).0, 1);
    }

    #[test]
    fn unsigned_age_and_max_sentinel_are_preserved() {
        assert_eq!(run(&mut [slot(-1, 0, 1, 0), slot(-2, 1, 1, 0)]).0, 1);
        assert_eq!(run(&mut [slot(-2, 0, 1, 0), slot(1, 0, 1, 2)]).0, 1);
    }

    #[test]
    fn cooldown_threshold_ties_and_clean_precedence() {
        let mut records = [slot(-14, 0, 0, 1), slot(-13, 0, 0, 1),
            slot(-1, 1, 0, 1), slot(-1, 0, 0, 1)];
        let before = records;
        let (selected, object) = run(&mut records);
        assert_eq!(selected, 2);
        for index in 0..records.len() {
            assert_eq!(records[index][0], before[index][0].wrapping_add(1));
            assert_eq!(records[index][1..], before[index][1..]);
        }
        assert_eq!(object.last(), Some(&0xa5a5a5a5));
        assert_eq!(run(&mut [slot(-100, 0, 0, 1), slot(-14, 0, 0, 1)]).0, 0);
        assert_eq!(run(&mut [slot(-1, 0, 0, 1), slot(9, 0, 1, 0)]).0, 1);
    }

    #[test]
    fn early_return_advances_only_preceding_cooldowns() {
        for reusable in [slot(9, 2, 0, 0), slot(0, 2, 7, 1)] {
            let mut records = [slot(-2, 0, 0, 1), reusable, slot(-2, 0, 0, 1)];
            assert_eq!(run(&mut records).0, 1);
            assert_eq!(records[0][0], (-1i32) as u32);
            assert_eq!(records[1], reusable);
            assert_eq!(records[2][0], (-2i32) as u32);
        }
    }
}
