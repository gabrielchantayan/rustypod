//! Identifier-to-value lookup at retailOS `0x08290498`.
//!
//! True extent: 56 bytes through `0x082904d0` (48 instruction bytes,
//! table literal at +0x30, and `"???\0"` at +0x34). Raw A32 decoding
//! verifies zero outgoing BLs and two incoming plain BLs at `0x0819fd58`
//! and `0x081e9b94`, with zero predicated incoming BLs.
//!
//! Scan 3,920 eight-byte records at `0x083f8728`, comparing each second
//! word with the identifier. Return the first matching first word as a
//! pointer, even when zero; otherwise return the original fallback string.
//! Callers pass the result to the COW string constructor. The captured table
//! words do not establish more specific identifier/value semantics.
//!
//! Deliberate deviations: none on target. Tests supply aligned u32 records
//! to the same scan, retaining four-byte target fields on 64-bit hosts.

const RECORD_COUNT: usize = 0xf50;
const RECORD_TABLE: *const u32 = 0x083f_8728 as *const u32;
const UNKNOWN_VALUE: *const u8 = 0x0829_04cc as *const u8;

#[inline(always)]
unsafe fn find_value(records: *const u32, identifier: u32) -> *const u8 {
    for index in 0..RECORD_COUNT {
        let record = records.add(index * 2);
        if record.add(1).read() == identifier {
            return record.read() as usize as *const u8;
        }
    }
    UNKNOWN_VALUE
}

/// The firmware table must be mapped and readable for all 3,920 records.
/// The returned pointer is not dereferenced or validated by this function.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn identifier_value_lookup(identifier: u32) -> *const u8 {
    find_value(RECORD_TABLE, identifier)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_match_wins_including_null_and_high_bit_values() {
        let mut records = [0u32; RECORD_COUNT * 2];
        records[0] = 0;
        records[1] = u32::MAX;
        records[2] = 0xffff_fffc;
        records[3] = u32::MAX;
        assert_eq!(unsafe { find_value(records.as_ptr(), u32::MAX) }, core::ptr::null());
        records[1] = 1;
        assert_eq!(unsafe { find_value(records.as_ptr(), u32::MAX) } as usize, 0xffff_fffc);
    }

    #[test]
    fn last_record_is_included_but_following_record_is_not() {
        let mut records = [0u32; (RECORD_COUNT + 1) * 2];
        records[(RECORD_COUNT - 1) * 2] = 0x1234_5678;
        records[(RECORD_COUNT - 1) * 2 + 1] = 42;
        records[RECORD_COUNT * 2] = 0x8765_4321;
        records[RECORD_COUNT * 2 + 1] = 43;
        assert_eq!(unsafe { find_value(records.as_ptr(), 42) } as usize, 0x1234_5678);
        assert_eq!(unsafe { find_value(records.as_ptr(), 43) }, UNKNOWN_VALUE);
    }
}
