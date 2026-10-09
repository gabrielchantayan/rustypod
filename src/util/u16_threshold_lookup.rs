//! Threshold-to-value upper-bound lookup — `FUN_080cab1c` @ `0x080cab1c`.
//!
//! True extent: 64 bytes, `[0x080cab1c, 0x080cab5c)`; next entry starts
//! with PUSH. Raw aligned-word scan: two incoming plain BLs (0x080dc8e8,
//! 0x080dc900), zero predicated BLs; body has zero BL/BLX calls.
//! Binary-search sorted four-byte (u16 threshold, u16 value) records with
//! unsigned comparisons. Return the value of the last threshold <= key,
//! including the last duplicate. Bounds and midpoint use wrapping u32 math.
//! An empty range or key below every threshold reads the preceding value;
//! there is deliberately no guard or invented fallback.
//!
//! Deliberate deviation: host pointers retain native width, with wrapped
//! 32-bit byte offsets sign-extended so the preceding-record read is testable.
//! The caller's unrecovered text-classification table is not embedded here.

/// Four-byte firmware record; no host-width pointer fields.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct U16ThresholdRecord {
    pub threshold: u16,
    pub value: u16,
}

/// The table must be halfword-aligned and readable at every visited offset,
/// including the preceding record's value if no threshold qualifies.
/// Thresholds must be nondecreasing; bounds must allow the search to terminate.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn u16_threshold_lookup(
    key: u32,
    table: *const U16ThresholdRecord,
    count: u32,
) -> u16 {
    let mut low = 0u32;
    let mut high = count;
    while low < high {
        let midpoint = low.wrapping_add(high) >> 1;
        let offset = midpoint.wrapping_mul(4) as i32 as isize;
        let threshold = unsafe { table.cast::<u8>().wrapping_offset(offset).cast::<u16>().read() };
        if threshold as u32 > key {
            high = midpoint;
        } else {
            low = midpoint.wrapping_add(1);
        }
    }
    let offset = high.wrapping_sub(1).wrapping_mul(4).wrapping_add(2) as i32 as isize;
    unsafe { table.cast::<u8>().wrapping_offset(offset).cast::<u16>().read() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_linear_predecessor_with_duplicates_and_unsigned_keys() {
        let thresholds = [0, 1, 1, 7, 100, 0x8000, 0xffff];
        let records: [U16ThresholdRecord; 7] = core::array::from_fn(|i| U16ThresholdRecord {
            threshold: thresholds[i], value: 0x8000 + i as u16,
        });
        assert_eq!(core::mem::size_of::<U16ThresholdRecord>(), 4);
        for count in 1..=records.len() {
            for key in (0..=0x10000u32).chain([0x8000_0000, u32::MAX]) {
                let expected = records[..count].iter().rev()
                    .find(|record| record.threshold as u32 <= key).unwrap().value;
                let actual = unsafe { u16_threshold_lookup(key, records.as_ptr(), count as u32) };
                assert_eq!(actual, expected, "count={count}, key={key}");
            }
        }
    }

    #[test]
    fn empty_and_below_first_read_preceding_value() {
        let records = [
            U16ThresholdRecord { threshold: 0, value: 0xfedc },
            U16ThresholdRecord { threshold: 10, value: 123 },
            U16ThresholdRecord { threshold: 20, value: 456 },
        ];
        let table = unsafe { records.as_ptr().add(1) };
        for key in [0, 9, 10, u32::MAX] {
            assert_eq!(unsafe { u16_threshold_lookup(key, table, 0) }, 0xfedc);
        }
        for key in [0, 9] {
            assert_eq!(unsafe { u16_threshold_lookup(key, table, 2) }, 0xfedc);
        }
        assert_eq!(unsafe { u16_threshold_lookup(10, table, 2) }, 123);
        assert_eq!(unsafe { u16_threshold_lookup(20, table, 2) }, 456);
    }
}
