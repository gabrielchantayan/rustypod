//! Search the eight-byte records ordered by `record_u16_casefold_compare`.
//!
//! Original: `FUN_0815f214` @ **0x0815f214**, 124 bytes, ending before the
//! real function prologue at 0x0815f290. Raw ARM words verify two inbound
//! plain BL calls (0x0815f400, 0x0815f64c), zero predicated inbound BL calls,
//! and one outbound plain BL to 0x080be778, with zero predicated outbound BL.
//! Start with low=0 and the caller's last index as high. While low < high,
//! compare the midpoint record: positive moves high to midpoint-1, negative
//! moves low to midpoint+1, and zero returns the midpoint with result 1.
//! Otherwise write low and return 0; the final remaining slot is NOT compared.
//! Signed midpoint addition wraps before arithmetic shift, as on ARM.
//! Deliberate deviations: the owner prefix uses repr(C), so its record pointer
//! follows host pointer alignment in host fixtures (target offset remains +12).
//! No algorithmic deviations; the existing comparator is reused directly.

use crate::cxx::record_u16_casefold_compare::record_u16_casefold_compare;
use crate::cxx::string_object::StringObject;

#[repr(C)]
pub struct CasefoldRecordArray {
    pub header: [u32; 3],
    pub records: *const u8,
}

#[inline(always)]
fn search(mut high: i32, mut compare: impl FnMut(i32) -> i32) -> (i32, i32) {
    let mut low = 0i32;
    while low < high {
        let middle = low.wrapping_add(high) >> 1;
        let order = compare(middle);
        if order > 0 {
            high = middle.wrapping_sub(1);
        } else if order == 0 {
            return (1, middle);
        } else {
            low = middle.wrapping_add(1);
        }
    }
    (0, low)
}

/// `last_index` is a signed upper index, not a count.
///
/// # Safety
/// `index_out` must be writable. When `last_index > 0`, `owner` must be valid
/// and each visited record and the comparator's key/text arguments must meet
/// `record_u16_casefold_compare`'s requirements.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn record_u16_casefold_search(
    owner: *const CasefoldRecordArray,
    last_index: i32,
    key: *const u8,
    key_text: *const StringObject,
    index_out: *mut i32,
) -> i32 {
    let (found, index) = search(last_index, |middle| {
        let records = (*owner).records;
        let record = records.wrapping_offset((middle as isize).wrapping_mul(8));
        record_u16_casefold_compare(record, key, key_text)
    });
    index_out.write(index);
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_singleton_and_negative_bounds_do_not_read_inputs() {
        for high in [i32::MIN, -1, 0] {
            let mut index = -99;
            let found = unsafe {
                record_u16_casefold_search(core::ptr::null(), high, core::ptr::null(),
                    core::ptr::null(), &mut index)
            };
            assert_eq!((found, index), (0, 0));
        }
    }

    #[test]
    fn equality_and_terminal_slot_semantics() {
        let values = [10, 20, 30, 40, 50];
        // This is intentionally NOT a conventional inclusive binary search.
        for (key, expected) in [(5, (0, 0)), (10, (1, 0)), (20, (0, 1)),
            (30, (1, 2)), (40, (1, 3)), (50, (0, 4)), (60, (0, 4))] {
            assert_eq!(search(4, |i| values[i as usize] - key), expected);
        }
        assert_eq!(search(1, |_| 0), (1, 0));
        assert_eq!(search(1, |_| i32::MIN), (0, 1));
        assert_eq!(search(1, |_| i32::MAX), (0, 0));
    }

    #[test]
    fn real_comparator_reads_eight_byte_stride_and_owner_pointer() {
        // Unequal u16 keys use the real comparator without its global formatter.
        let records = [0x0046_0000_0000_0000u64, 0x0032_0000_0000_0000,
            0x001e_0000_0000_0000, 0x000a_0000_0000_0000];
        let owner = CasefoldRecordArray { header: [0, 4, 0], records: records.as_ptr().cast() };
        for (key_value, expected) in [(5u16, 3), (20, 3), (40, 2), (80, 0)] {
            let key = (u64::from(key_value) << 48).to_le_bytes();
            let mut index = -1;
            let found = unsafe { record_u16_casefold_search(&owner, 3, key.as_ptr(),
                core::ptr::null(), &mut index) };
            assert_eq!((found, index), (0, expected));
        }
    }
}
