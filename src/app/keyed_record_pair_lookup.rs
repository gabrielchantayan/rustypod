//! Keyed record-pair lookup — original: `FUN_0807f1e8` @ `0x0807f1e8`
//! (76 bytes).
//!
//! Raw ARM decoding establishes the exact extent `0x0807f1e8..0x0807f234`:
//!
//! ```text
//! push {r4,r5,lr}; load fifth ABI argument from [sp,#12]
//! index = 0
//! while (index < record_count) {
//!     record = records + index * 16
//!     if (record->key == key) {
//!         *first_value_out = record->first_value
//!         *second_value_out = record->second_value
//!         return 1
//!     }
//!     ++index
//! }
//! return 0
//! ```
//!
//! A binary scan of every ARM `B`/`BL` immediate in `osos.dec` finds nine
//! direct inbound calls: all are unconditional plain `bl` instructions, with
//! no predicated calls or tail branches. Every call is from the resource
//! parsing body at `0x0828fbac` and supplies valid output slots; the retail
//! helper itself deliberately has no NULL guards.
//!
//! # Algorithm
//!
//! Scan `record_count` packed 16-byte records in order for the first exact
//! 32-bit key match. On a match, copy only the two trailing payload words at
//! offsets `+8` and `+12` to the caller's output slots and return one. On a
//! miss, return zero without touching either output slot. The word at `+4` is
//! not read by the retail body and remains an opaque reserved word here.
//!
//! # Deliberate deviations
//!
//! None. `KeyedRecordPair` is `repr(C)` and exactly four target words, so its
//! field offsets remain the retail `0`, `4`, `8`, and `12` on host and device.

/// The packed 16-byte record searched by [`keyed_record_pair_lookup`].
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyedRecordPair {
    /// +0x00: lookup selector.
    pub key: u32,
    /// +0x04: not inspected by this helper.
    pub reserved: u32,
    /// +0x08: first output word.
    pub first_value: u32,
    /// +0x0c: second output word.
    pub second_value: u32,
}

/// `keyed_record_pair_lookup` — original: `FUN_0807f1e8` @ `0x0807f1e8`
/// (76 bytes; 9 direct unconditional `bl` call sites, binary-scanned).
///
/// Returns one and writes the first matching record's two payload words, or
/// returns zero without modifying either output word when no key matches.
/// Duplicate keys resolve to the lowest-indexed record.
///
/// # Safety
///
/// When `record_count` is nonzero, `records` must address that many readable
/// `KeyedRecordPair` values. `first_value_out` and `second_value_out` must be
/// valid writable, non-overlapping `u32` slots whenever a matching key exists.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn keyed_record_pair_lookup(
    records: *const KeyedRecordPair,
    record_count: u32,
    key: u32,
    first_value_out: *mut u32,
    second_value_out: *mut u32,
) -> u32 {
    let mut index = 0u32;
    while index < record_count {
        let record = unsafe { records.add(index as usize) };
        if unsafe { (*record).key } == key {
            unsafe {
                first_value_out.write((*record).first_value);
                second_value_out.write((*record).second_value);
            }
            return 1;
        }
        index = index.wrapping_add(1);
    }
    0
}

#[cfg(test)]
mod tests {
    use super::{keyed_record_pair_lookup, KeyedRecordPair};

    fn reference_lookup(records: &[KeyedRecordPair], key: u32, first_out: &mut u32, second_out: &mut u32) -> u32 {
        if let Some(record) = records.iter().find(|record| record.key == key) {
            *first_out = record.first_value;
            *second_out = record.second_value;
            1
        } else {
            0
        }
    }

    #[test]
    fn finds_first_duplicate_and_copies_only_its_payload_pair() {
        let mut records = [
            KeyedRecordPair { key: 0x1357_9bdf, reserved: 0xaaaa_aaaa, first_value: 0x1111_2222, second_value: 0x3333_4444 },
            KeyedRecordPair { key: 0x2468_ace0, reserved: 0xbbbb_bbbb, first_value: 0x5555_6666, second_value: 0x7777_8888 },
            KeyedRecordPair { key: 0x1357_9bdf, reserved: 0xcccc_cccc, first_value: 0x9999_aaaa, second_value: 0xbbbb_cccc },
        ];
        let mut expected_first = 0xdeaf_beef;
        let mut expected_second = 0xcafe_babe;
        let expected_status = reference_lookup(&records, 0x1357_9bdf, &mut expected_first, &mut expected_second);
        let mut actual_first = 0xdeaf_beef;
        let mut actual_second = 0xcafe_babe;

        let actual_status = unsafe {
            keyed_record_pair_lookup(
                records.as_mut_ptr(),
                records.len() as u32,
                0x1357_9bdf,
                &mut actual_first,
                &mut actual_second,
            )
        };

        assert_eq!(actual_status, expected_status);
        assert_eq!((actual_first, actual_second), (expected_first, expected_second));
    }

    #[test]
    fn miss_and_empty_table_leave_output_slots_unchanged() {
        let mut records = [KeyedRecordPair { key: 7, reserved: 0, first_value: 8, second_value: 9 }];
        let mut first = 0x1111_1111;
        let mut second = 0x2222_2222;

        assert_eq!(unsafe {
            keyed_record_pair_lookup(records.as_mut_ptr(), 1, 8, &mut first, &mut second)
        }, 0);
        assert_eq!((first, second), (0x1111_1111, 0x2222_2222));

        assert_eq!(unsafe {
            keyed_record_pair_lookup(core::ptr::null(), 0, 7, &mut first, &mut second)
        }, 0);
        assert_eq!((first, second), (0x1111_1111, 0x2222_2222));
    }

    #[test]
    fn finds_final_record_after_nonmatching_prefix() {
        let mut records = [
            KeyedRecordPair { key: 1, reserved: 0, first_value: 2, second_value: 3 },
            KeyedRecordPair { key: 4, reserved: 0, first_value: 5, second_value: 6 },
        ];
        let mut first = 0;
        let mut second = 0;

        assert_eq!(unsafe {
            keyed_record_pair_lookup(records.as_mut_ptr(), 2, 4, &mut first, &mut second)
        }, 1);
        assert_eq!((first, second), (5, 6));
    }
}
