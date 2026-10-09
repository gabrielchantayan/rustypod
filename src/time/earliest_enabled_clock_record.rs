//! Earliest enabled clock record — `FUN_080caa28` @ `0x080caa28`.
//!
//! True extent: 92 bytes, `0x080caa28..0x080caa84`: 88 executable bytes
//! through POP PC at 0x080caa7c, then the table literal at 0x080caa80.
//! The next function starts with LDR at 0x080caa84 followed by PUSH.
//! Whole-image aligned A32 decoding finds two incoming plain BLs
//! (0x08044a4c, 0x080e1d20), zero predicated BLs. The body has one plain BL
//! to compare_clock_records @ 0x0808cde4 and zero predicated BLs.
//!
//! Scan five 20-byte records at 0x08a662ec. Any nonzero byte at +14 enables
//! a record; select it if no record is selected or its clock key compares
//! exactly -1 against the current selection. Return -1 if all are disabled;
//! equal keys retain the first enabled index. No writes or validation.
//!
//! Deliberate deviations: none on target. A private pointer-taking core lets
//! host tests use aligned local records instead of firmware RAM.

use super::compare_clock_records::compare_clock_records;

/// Returns the index of the earliest enabled firmware clock record.
///
/// # Safety
/// Firmware RAM at 0x08a662ec must contain five readable 20-byte records.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn earliest_enabled_clock_record() -> i32 {
    select_earliest(0x08a6_62ec as *const u8)
}

unsafe fn select_earliest(records: *const u8) -> i32 {
    let mut selected = -1;
    for index in 0..5 {
        let candidate = records.add(index * 20);
        if candidate.add(14).read() != 0 &&
            (selected == -1 || compare_clock_records(candidate, records.add(selected as usize * 20)) == -1) {
            selected = index as i32;
        }
    }
    selected
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(align(4))]
    struct Records([[u8; 20]; 5]);

    fn record(high: u16, low: u16, time: [u8; 3], enabled: u8) -> [u8; 20] {
        let mut bytes = [0xa5; 20];
        bytes[0..2].copy_from_slice(&high.to_le_bytes());
        bytes[4..6].copy_from_slice(&low.to_le_bytes());
        bytes[8..11].copy_from_slice(&time);
        bytes[14] = enabled;
        bytes
    }

    fn select(records: &Records) -> i32 {
        unsafe { select_earliest(records.0.as_ptr().cast()) }
    }

    #[test]
    fn disabled_and_single_enabled_slots() {
        let mut records = Records([record(0xffff, 0xffff, [255; 3], 0); 5]);
        assert_eq!(select(&records), -1);
        for index in 0..5 {
            records.0[index][14] = 0x80;
            assert_eq!(select(&records), index as i32);
            records.0[index][14] = 0;
        }
    }

    #[test]
    fn unsigned_date_precedes_time_and_disabled_earlier_keys_are_ignored() {
        let records = Records([
            record(0xffff, 0, [0; 3], 1),
            record(0x8000, 2, [0; 3], 1),
            record(0x8000, 1, [255; 3], 2),
            record(0, 0, [0; 3], 0),
            record(0x8000, 1, [255, 255, 254], 255),
        ]);
        let before = records.0;
        assert_eq!(select(&records), 4);
        assert_eq!(records.0, before);
    }

    #[test]
    fn all_enable_masks_and_ties_match_key_order() {
        let keys = [(2u16, 0u16, [0, 0, 0]), (1, 3, [4, 5, 6]),
                    (1, 3, [4, 5, 6]), (1, 3, [4, 5, 7]), (1, 4, [0, 0, 0])];
        for mask in 0..32 {
            let mut records = Records([[0; 20]; 5]);
            for (index, &(high, low, time)) in keys.iter().enumerate() {
                records.0[index] = record(high, low, time, if mask & (1 << index) != 0 { 7 } else { 0 });
                records.0[index][2] = index as u8;
            }
            let expected = (0..5).filter(|&i| mask & (1 << i) != 0)
                .min_by_key(|&i| (keys[i], i)).map_or(-1, |i| i as i32);
            assert_eq!(select(&records), expected, "enable mask {mask:#x}");
        }
    }
}
