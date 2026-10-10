//! Conditional unique record-ID collection from a filesystem record.
//!
//! Original `FUN_0806df48` @ 0x0806df48; true extent
//! [0x0806df48, 0x0806dfcc), 132 bytes. Raw A32 decoding verifies two
//! incoming plain BLs (0x0804339c, 0x080e7374), no predicated incoming BLs,
//! and no outgoing plain or predicated BLs. The next function starts with
//! PUSH {r4-r8,lr}. Ghidra's supposed indirect calls are stack-pop returns.
//! Append the +0xb0 ID if it is >=2, the +0xb4 word is zero, and the +0x80
//! halfword is zero or 0x191..=0x195; scan the count-prefixed word list first
//! to suppress duplicates. Concrete record type and tag meanings are unknown.
//! Deliberate deviations: omit the dead always-zero r12 condition and stack
//! frame; retain volatile access order, including the count reload after the
//! append, so aliasing has the original behavior. No allocation or seams.

use core::ptr::{read_volatile, write_volatile};

/// Collect an eligible record ID into a caller-owned count-prefixed list.
///
/// # Safety
/// `record` must be word-aligned and readable through byte +0xb7. `ids` must
/// be word-aligned with its count readable, all counted entries readable,
/// and one additional writable entry plus a writable count on insertion.
/// Rejected records do not require a valid list pointer. No capacity check
/// or null-record guard exists in the original.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn record_id_collect(record: *const u32, ids: *mut u32) {
    let id = read_volatile(record.add(0xb0 / 4));
    if id < 2 {
        return;
    }
    if read_volatile(record.add(0xb4 / 4)) != 0 {
        return;
    }
    let tag = read_volatile(record.add(0x80 / 4).cast::<u16>()) as u32;
    if tag != 0 && tag.wrapping_sub(0x191) > 4 {
        return;
    }
    let count = read_volatile(ids);
    let mut index = 0u32;
    while index < count {
        if read_volatile(ids.add(index as usize + 1)) == id {
            return;
        }
        index += 1;
    }
    write_volatile(ids.add(count as usize + 1), id);
    write_volatile(ids, read_volatile(ids).wrapping_add(1));
}

#[cfg(test)]
mod tests {
    use super::record_id_collect;

    fn record(id: u32, tag: u16, blocker: u32) -> [u32; 46] {
        let mut record = [0u32; 46];
        record[0x80 / 4] = 0xbeef0000 | tag as u32;
        record[0xb0 / 4] = id;
        record[0xb4 / 4] = blocker;
        record
    }

    #[test]
    fn eligibility_boundaries_match_reference() {
        for id in [0, 1, 2, 0x80000000, u32::MAX] {
            for tag in [0, 1, 0x190, 0x191, 0x192, 0x193, 0x194, 0x195, 0x196, u16::MAX] {
                for blocker in [0, 1, u32::MAX] {
                    let record = record(id, tag, blocker);
                    let mut ids = [0, 0xaaaaaaaa, 0xbbbbbbbb];
                    unsafe { record_id_collect(record.as_ptr(), ids.as_mut_ptr()); }
                    let eligible = id >= 2 && blocker == 0 && (tag == 0 || (0x191..=0x195).contains(&tag));
                    let expected = if eligible { [1, id, 0xbbbbbbbb] } else { [0, 0xaaaaaaaa, 0xbbbbbbbb] };
                    assert_eq!(ids, expected, "id={id:x} tag={tag:x} blocker={blocker:x}");
                }
            }
        }
    }

    #[test]
    fn duplicates_at_each_position_and_append_preserve_other_words() {
        for id in [2, 7, u32::MAX, 9] {
            let record = record(id, 0x193, 0);
            let mut ids = [3, 2, 7, u32::MAX, 0xaaaaaaaa, 0xbbbbbbbb];
            unsafe { record_id_collect(record.as_ptr(), ids.as_mut_ptr()); }
            let expected = if id == 9 { [4, 2, 7, u32::MAX, 9, 0xbbbbbbbb] }
                else { [3, 2, 7, u32::MAX, 0xaaaaaaaa, 0xbbbbbbbb] };
            assert_eq!(ids, expected);
            unsafe { record_id_collect(record.as_ptr(), ids.as_mut_ptr()); }
            assert_eq!(ids, expected);
        }
    }

    #[test]
    fn rejected_records_never_access_list() {
        for (id, tag, blocker) in [(0, 0, 0), (1, 0x191, 0), (2, 0, 1), (2, 0x190, 0), (2, 0x196, 0)] {
            let record = record(id, tag, blocker);
            unsafe { record_id_collect(record.as_ptr(), core::ptr::null_mut()); }
        }
    }
}
