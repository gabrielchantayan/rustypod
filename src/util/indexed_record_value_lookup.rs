//! `indexed_record_value_lookup` — original: `FUN_080ffcf0` @ `0x080ffcf0`
//! (60 instruction bytes, followed by its four-byte literal at `0x080ffd2c`;
//! the separately linked function starts at `0x080ffd30`).
//!
//! Raw ARM decoding finds six inbound direct calls, all unconditional `bl` at
//! `0x080ffed4`, `0x080fff44`, `0x080fff70`, `0x0811e868`, `0x08171b54`, and
//! `0x0818761c`; there are no predicated call forms. The first search scans
//! 205 20-byte records at `0x083e9d94` for a matching halfword at +0x0a. On a
//! hit it tail-branches into a second search over 32 four-byte records at
//! `0x083e9d14`, matching the first record's +0x10 halfword against the second
//! record's +0x02 halfword and returning its signed halfword at +0x00. Either
//! miss returns `i32::MAX`.
//!
//! The target reads the two immutable retail tables at their verified absolute
//! addresses. Host builds deliberately use private tables with the same packed
//! record layout so tests can exercise both searches without mapping firmware
//! memory; they otherwise perform the identical first-match lookup.

/// Number of records in the outer, 20-byte retail table.
const PRIMARY_RECORD_COUNT: usize = 0xcd;
/// Number of records in the inner, four-byte retail table.
const SECONDARY_RECORD_COUNT: usize = 0x20;
const NOT_FOUND: i32 = i32::MAX;
const PRIMARY_TABLE_ADDRESS: usize = 0x083e_9d94;
const SECONDARY_TABLE_ADDRESS: usize = 0x083e_9d14;

/// A record whose only consumed fields are the two halfwords at +0x0a and
/// +0x10. The byte arrays retain the exact retail record stride and offsets.
#[repr(C)]
#[derive(Clone, Copy)]
struct PrimaryRecord {
    prefix: [u8; 10],
    key: u16,
    middle: [u8; 4],
    secondary_key: u16,
    suffix: [u8; 2],
}

const PRIMARY_RECORD_EMPTY: PrimaryRecord = PrimaryRecord {
    prefix: [0; 10],
    key: 0,
    middle: [0; 4],
    secondary_key: 0,
    suffix: [0; 2],
};

/// A four-byte record searched by the tail shared with `FUN_080ffb2c`.
#[repr(C)]
#[derive(Clone, Copy)]
struct SecondaryRecord {
    value: i16,
    key: u16,
}

const SECONDARY_RECORD_EMPTY: SecondaryRecord = SecondaryRecord { value: 0, key: 0 };

const _: [u8; 20] = [0; core::mem::size_of::<PrimaryRecord>()];
const _: [u8; 4] = [0; core::mem::size_of::<SecondaryRecord>()];
const _: [u8; 10] = [0; core::mem::offset_of!(PrimaryRecord, key)];
const _: [u8; 16] = [0; core::mem::offset_of!(PrimaryRecord, secondary_key)];
const _: [u8; 2] = [0; core::mem::offset_of!(SecondaryRecord, key)];

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn primary_table() -> &'static [PrimaryRecord; PRIMARY_RECORD_COUNT] {
    unsafe { &*(PRIMARY_TABLE_ADDRESS as *const [PrimaryRecord; PRIMARY_RECORD_COUNT]) }
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn secondary_table() -> &'static [SecondaryRecord; SECONDARY_RECORD_COUNT] {
    unsafe { &*(SECONDARY_TABLE_ADDRESS as *const [SecondaryRecord; SECONDARY_RECORD_COUNT]) }
}

#[cfg(not(target_os = "none"))]
static mut HOST_PRIMARY_TABLE: [PrimaryRecord; PRIMARY_RECORD_COUNT] =
    [PRIMARY_RECORD_EMPTY; PRIMARY_RECORD_COUNT];

#[cfg(not(target_os = "none"))]
static mut HOST_SECONDARY_TABLE: [SecondaryRecord; SECONDARY_RECORD_COUNT] =
    [SECONDARY_RECORD_EMPTY; SECONDARY_RECORD_COUNT];

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn primary_table() -> &'static [PrimaryRecord; PRIMARY_RECORD_COUNT] {
    unsafe { &*core::ptr::addr_of!(HOST_PRIMARY_TABLE) }
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn secondary_table() -> &'static [SecondaryRecord; SECONDARY_RECORD_COUNT] {
    unsafe { &*core::ptr::addr_of!(HOST_SECONDARY_TABLE) }
}

#[inline]
fn lookup_record_value(
    key: u32,
    primary: &[PrimaryRecord; PRIMARY_RECORD_COUNT],
    secondary: &[SecondaryRecord; SECONDARY_RECORD_COUNT],
) -> i32 {
    let Some(record) = primary.iter().find(|record| u32::from(record.key) == key) else {
        return NOT_FOUND;
    };

    secondary
        .iter()
        .find(|candidate| candidate.key == record.secondary_key)
        .map_or(NOT_FOUND, |candidate| i32::from(candidate.value))
}

/// Looks up the signed value paired with `key` in retailOS's two static tables.
///
/// # Safety
///
/// On the target, both table addresses must retain their stock layouts. The
/// retail function similarly dereferences them without guards.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.indexed_record_value_lookup")]
#[inline(never)]
pub unsafe extern "C" fn indexed_record_value_lookup(key: u32) -> i32 {
    unsafe { lookup_record_value(key, primary_table(), secondary_table()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe fn reset_tables() {
        unsafe {
            core::ptr::addr_of_mut!(HOST_PRIMARY_TABLE)
                .write([PRIMARY_RECORD_EMPTY; PRIMARY_RECORD_COUNT]);
            core::ptr::addr_of_mut!(HOST_SECONDARY_TABLE)
                .write([SECONDARY_RECORD_EMPTY; SECONDARY_RECORD_COUNT]);
        }
    }

    #[test]
    fn exported_lookup_preserves_both_first_match_searches_and_miss_sentinel() {

        unsafe {
            reset_tables();
            (*core::ptr::addr_of_mut!(HOST_PRIMARY_TABLE))[0].key = 0x1234;
            (*core::ptr::addr_of_mut!(HOST_PRIMARY_TABLE))[0].secondary_key = 0xabcd;
            (*core::ptr::addr_of_mut!(HOST_PRIMARY_TABLE))[1].key = 0x1234;
            (*core::ptr::addr_of_mut!(HOST_PRIMARY_TABLE))[1].secondary_key = 0xbeef;
            (*core::ptr::addr_of_mut!(HOST_SECONDARY_TABLE))[7] = SecondaryRecord {
                value: -321,
                key: 0xabcd,
            };
            (*core::ptr::addr_of_mut!(HOST_SECONDARY_TABLE))[8] = SecondaryRecord {
                value: 77,
                key: 0xbeef,
            };

            assert_eq!(indexed_record_value_lookup(0x1234), -321);
            assert_eq!(indexed_record_value_lookup(0x1_1234), NOT_FOUND);
            assert_eq!(indexed_record_value_lookup(0x7777), NOT_FOUND);

            (*core::ptr::addr_of_mut!(HOST_PRIMARY_TABLE))[2].key = 0x5678;
            (*core::ptr::addr_of_mut!(HOST_PRIMARY_TABLE))[2].secondary_key = 0xfeed;
            assert_eq!(indexed_record_value_lookup(0x5678), NOT_FOUND);

            (*core::ptr::addr_of_mut!(HOST_SECONDARY_TABLE))[31] = SecondaryRecord {
                value: i16::MIN,
                key: 0xfeed,
            };
            assert_eq!(indexed_record_value_lookup(0x5678), i32::from(i16::MIN));
        }
    }
}
