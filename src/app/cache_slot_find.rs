//! `cache_slot_find` — `FUN_080fae44` @ 0x080fae44.
//! Raw extent [0x080fae44, 0x080faec0): 124 bytes, no literals; the next
//! function begins with a push. Whole-image A32 decoding verifies two
//! incoming plain BLs (0x080f9950, 0x080f9e9c), zero predicated incoming
//! BLs, and two outgoing plain BLs, zero predicated outgoing BLs.
//!
//! Initialize a local parser result, snapshot the manager's slot count,
//! and scan 60-byte records for the first nonzero valid byte whose block
//! key equals the requested block rounded down to a 128-block boundary.
//! Return the index with bit 31 set on a hit, zero on a miss, then destroy
//! the local result. The read/write callers use the flag to distinguish a
//! resident slot from a replacement selected by `cache_slot_select`.
//! Deliberate deviations: omit unused incoming r2/r3 from the signature;
//! r3 is only saved to reserve the local record, then overwritten. Volatile
//! reads preserve the original count snapshot and valid-before-key order.
//! Existing parser-result seams are reused; the empty destructor may be
//! optimized away. Target byte offsets do not depend on host pointer size.

use core::ptr;
use super::parse_result::{parse_result_init, parse_result_destroy};

/// Find the first valid slot for a 128-block-aligned cache key.
///
/// # Safety
/// `manager` must be four-byte aligned and readable through the count at
/// +0x468 and all counted 60-byte records beginning at +0x46c. Each record
/// has its aligned key at +0 and its valid byte at +0x19.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn cache_slot_find(manager: *const u8, block: u32) -> u32 {
    let mut result_record = 0u32;
    let record = ptr::addr_of_mut!(result_record).cast::<u8>();
    unsafe { parse_result_init(record, 0, 0, 0) };
    let count = unsafe { ptr::read_volatile(manager.add(0x468).cast::<u32>()) };
    let key = block & !0x7f;
    let mut result = 0;
    for index in 0..count {
        let slot = unsafe { manager.add(0x46c + index as usize * 0x3c) };
        if unsafe { ptr::read_volatile(slot.add(0x19)) } != 0
            && unsafe { ptr::read_volatile(slot.cast::<u32>()) } == key {
            result = index | 0x80000000;
            break;
        }
    }
    unsafe { parse_result_destroy(record) };
    result
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    fn check(slots: &[(u32, u8)], count: usize, block: u32) -> u32 {
        let mut manager = std::vec![0xa5a5a5a5u32; 0x46c / 4 + slots.len() * 15];
        manager[0x468 / 4] = count as u32;
        for (index, &(key, valid)) in slots.iter().enumerate() {
            let start = 0x46c / 4 + index * 15;
            manager[start] = key;
            manager[start + 6] = u32::from_le_bytes([0xa5, valid, 0xa5, 0xa5]);
        }
        let before = manager.clone();
        let expected = slots[..count].iter().position(|&(key, valid)| {
            valid != 0 && key == block & !0x7f
        }).map_or(0, |index| index as u32 | 0x80000000);
        let actual = unsafe { cache_slot_find(manager.as_ptr().cast(), block) };
        assert_eq!(actual, expected);
        assert_eq!(manager, before);
        actual
    }

    #[test]
    fn empty_miss_and_count_boundary() {
        assert_eq!(check(&[], 0, 0), 0);
        assert_eq!(check(&[(0x100, 1)], 0, 0x100), 0);
        assert_eq!(check(&[(0x100, 0), (0x180, 1)], 2, 0x100), 0);
        assert_eq!(check(&[(0x180, 1), (0x100, 1)], 1, 0x100), 0);
    }

    #[test]
    fn first_valid_match_and_all_low_seven_bits() {
        for offset in 0..128 {
            assert_eq!(check(&[(0x100, 0), (0x180, 1), (0x100, 2),
                (0x100, 255)], 4, 0x100 + offset), 0x80000002);
        }
        assert_eq!(check(&[(0, 255), (0, 1)], 2, 0x7f), 0x80000000);
    }

    #[test]
    fn unsigned_keys_and_unaligned_stored_key() {
        for block in [0, 0x7f, 0x80, 0x80000000, 0xffffff80, u32::MAX] {
            let key = block & !0x7f;
            assert_eq!(check(&[(key | 1, 1), (key, 1)], 2, block), 0x80000001);
        }
    }
}
