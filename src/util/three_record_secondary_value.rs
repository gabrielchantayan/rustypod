//! `three_record_secondary_value` — original: `FUN_08194190` @ `0x08194190`
//! (20 bytes; `0x08194190..0x081941a4`).
//!
//! # Algorithm
//!
//! Reject signed indices of three or greater, then return word `+0x04` from
//! the selected 0x20-byte record. Negative indices are deliberately accepted:
//! ARM's `blge` is a signed comparison, so they select records before the
//! supplied base. A rejected index takes the predicated fatal path through
//! `heap_panic` and never returns.
//!
//! Deliberate deviations: none.
//!
//! Raw `osos.dec` words establish the 20-byte extent ending in `bx lr`; the
//! next real function begins at `0x081941a4`. There is one outbound predicated
//! BL (`blge 0x08030f44`, `heap_panic`) and no outbound plain BL calls. Full
//! image A32 decoding finds three inbound plain unconditional BL call sites
//! and no predicated inbound BL forms.

/// Target-width layout of one record in the three-element table.
#[repr(C)]
pub struct ThreeRecord {
    _prefix: u32,
    secondary_value: u32,
    _rest: [u32; 6],
}

/// Returns the selected record's word at byte offset four.
///
/// `records` must be valid at the signed `index` selected record.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.three_record_secondary_value")]
pub unsafe extern "C" fn three_record_secondary_value(records: *const ThreeRecord, index: i32) -> u32 {
    if index >= 3 {
        crate::heap::veneers::heap_panic();
    }
    (*records.offset(index as isize)).secondary_value
}

#[cfg(test)]
mod tests {
    use super::{three_record_secondary_value, ThreeRecord};

    fn record(secondary_value: u32) -> ThreeRecord {
        ThreeRecord { _prefix: 0, secondary_value, _rest: [0; 6] }
    }

    #[test]
    fn returns_the_secondary_word_for_valid_positive_and_negative_indices() {
        let records = [record(0x1122_3344), record(0xdead_beef), record(0), record(0xffff_ffff)];
        let base = unsafe { records.as_ptr().add(1) };

        for (index, expected) in [(-1, 0x1122_3344), (0, 0xdead_beef), (1, 0), (2, 0xffff_ffff)] {
            assert_eq!(unsafe { three_record_secondary_value(base, index) }, expected);
        }
    }
}
