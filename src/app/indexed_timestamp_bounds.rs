//! `indexed_timestamp_bounds_update` — original: `FUN_081c4c5c` @
//! `0x081c4c5c` (**148 bytes**, `0x081c4c5c..0x081c4cec`; the next separately
//! linked function begins at `0x081c4cf0`).
//!
//! Raw ARM establishes six inbound direct `bl` sites: five unconditional at
//! `0x081c2634`, `0x081c5fa8`, `0x081c6328`, `0x081c6df8`, and `0x081c73ec`,
//! plus one `blne` at `0x081c5d90`. The predicated caller supplies this helper
//! only when its enclosing condition is nonzero; this helper itself has no
//! null, index, or divisor guard. Its sole outbound call is the already ported
//! `__aeabi_uldivmod` at `0x0802eefc`.
//!
//! # Algorithm
//!
//! Select the current 24-byte entry from the target-width table at `state+0x38`.
//! Copy its timestamp pair to `state+0xc8`; multiply its first signed 64-bit
//! pair by the signed scale at `+0x9c`, divide the resulting bit pattern by the
//! unsigned divisor at `+0x64`, and store that quotient at `+0xd8`. The
//! timestamp plus quotient becomes the end pair at `+0xd0`. An index at or
//! beyond the signed entry count instead stores the `i64::MAX` pair as both
//! timestamp and end, and zeroes the scaled pair. No deliberate deviations.

use crate::runtime::aeabi_64div::__aeabi_uldivmod;

/// The recovered target-width table header at `state+0x38`.
#[repr(C)]
pub struct IndexedTimestampTable {
    pub entry_count: i32,
    pub entries: u32,
}

const _: [u8; 0x00] = [0; core::mem::offset_of!(IndexedTimestampTable, entry_count)];
const _: [u8; 0x04] = [0; core::mem::offset_of!(IndexedTimestampTable, entries)];
const _: [u8; 0x08] = [0; core::mem::size_of::<IndexedTimestampTable>()];

/// One recovered 24-byte entry. The first and third pairs are interpreted as
/// signed 64-bit values by the arithmetic and addition respectively.
#[repr(C)]
pub struct IndexedTimestampEntry {
    pub scaled_value_low: u32,
    pub scaled_value_high: u32,
    pub timestamp_low: u32,
    pub timestamp_high: u32,
    pub opaque_10: u32,
    pub opaque_14: u32,
}

const _: [u8; 0x00] = [0; core::mem::offset_of!(IndexedTimestampEntry, scaled_value_low)];
const _: [u8; 0x08] = [0; core::mem::offset_of!(IndexedTimestampEntry, timestamp_low)];
const _: [u8; 0x18] = [0; core::mem::size_of::<IndexedTimestampEntry>()];

/// The observed target-width fields of the wider indexed-timestamp state.
#[repr(C)]
pub struct IndexedTimestampBoundsState {
    pub opaque_00_34: [u32; 14],
    pub entries_table: u32,
    pub opaque_3c_60: [u32; 10],
    pub time_divisor: u32,
    pub opaque_68_98: [u32; 13],
    pub time_scale: i32,
    pub opaque_a0_c0: [u32; 9],
    pub current_index: i32,
    pub timestamp_low: u32,
    pub timestamp_high: u32,
    pub end_low: u32,
    pub end_high: u32,
    pub scaled_low: u32,
    pub scaled_high: u32,
}

const _: [u8; 0x38] = [0; core::mem::offset_of!(IndexedTimestampBoundsState, entries_table)];
const _: [u8; 0x64] = [0; core::mem::offset_of!(IndexedTimestampBoundsState, time_divisor)];
const _: [u8; 0x9c] = [0; core::mem::offset_of!(IndexedTimestampBoundsState, time_scale)];
const _: [u8; 0xc4] = [0; core::mem::offset_of!(IndexedTimestampBoundsState, current_index)];
const _: [u8; 0xc8] = [0; core::mem::offset_of!(IndexedTimestampBoundsState, timestamp_low)];
const _: [u8; 0xd0] = [0; core::mem::offset_of!(IndexedTimestampBoundsState, end_low)];
const _: [u8; 0xd8] = [0; core::mem::offset_of!(IndexedTimestampBoundsState, scaled_low)];
const _: [u8; 0xe0] = [0; core::mem::size_of::<IndexedTimestampBoundsState>()];

/// Updates timestamp, scaled offset, and end bounds for the selected entry.
///
/// # Safety
///
/// `state` and its target-width `entries_table` field must be non-null and
/// four-byte aligned. When `current_index < entry_count`, the table's `entries`
/// word must identify a readable 24-byte entry at the target-width wrapped
/// `current_index * 24` offset. `time_divisor` must follow the retail caller
/// contract for `__aeabi_uldivmod`; this function adds no validation.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.indexed_timestamp_bounds_update")]
#[inline(never)]
pub unsafe extern "C" fn indexed_timestamp_bounds_update(state: *mut IndexedTimestampBoundsState) {
    let table = (*state).entries_table as usize as *const IndexedTimestampTable;
    let index = (*state).current_index;

    if index >= (*table).entry_count {
        (*state).timestamp_low = u32::MAX;
        (*state).timestamp_high = i32::MAX as u32;
        (*state).scaled_low = 0;
        (*state).scaled_high = 0;
        (*state).end_low = u32::MAX;
        (*state).end_high = i32::MAX as u32;
        return;
    }

    let entry_address = (*table)
        .entries
        .wrapping_add((index as u32).wrapping_mul(core::mem::size_of::<IndexedTimestampEntry>() as u32));
    let entry = entry_address as usize as *const IndexedTimestampEntry;
    let timestamp = ((*entry).timestamp_high as u64) << 32 | (*entry).timestamp_low as u64;
    let scaled_value = (((*entry).scaled_value_high as u64) << 32 | (*entry).scaled_value_low as u64) as i64;
    let numerator = scaled_value.wrapping_mul((*state).time_scale as i64) as u64;
    let scaled = __aeabi_uldivmod(numerator, (*state).time_divisor as u64);
    let end = timestamp.wrapping_add(scaled);

    (*state).timestamp_low = (*entry).timestamp_low;
    (*state).timestamp_high = (*entry).timestamp_high;
    (*state).scaled_low = scaled as u32;
    (*state).scaled_high = (scaled >> 32) as u32;
    (*state).end_low = end as u32;
    (*state).end_high = (end >> 32) as u32;
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr;
    use std::sync::{LazyLock, Mutex};

    const FIXTURE_LEN: usize = 0x1000;
    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::INDEXED_TIMESTAMP_BOUNDS, FIXTURE_LEN).map(|pointer| pointer as usize)
    });
    static FIXTURE_LOCK: Mutex<()> = Mutex::new(());

    unsafe fn fixture() -> Option<(*mut IndexedTimestampBoundsState, *mut IndexedTimestampTable, *mut IndexedTimestampEntry)> {
        let base = (*FIXTURE)? as *mut u8;
        ptr::write_bytes(base, 0, FIXTURE_LEN);
        Some((
            base.cast::<IndexedTimestampBoundsState>(),
            base.add(0x400).cast::<IndexedTimestampTable>(),
            base.add(0x500).cast::<IndexedTimestampEntry>(),
        ))
    }

    #[test]
    fn selected_entry_updates_all_three_pairs() {
        let _guard = FIXTURE_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some((state, table, entries)) = (unsafe { fixture() }) else {
            assert!(note_missing_u32_fixture("app::indexed_timestamp_bounds"));
            return;
        };

        unsafe {
            entries.add(0).write(IndexedTimestampEntry {
                scaled_value_low: 999,
                scaled_value_high: 0,
                timestamp_low: 1,
                timestamp_high: 0,
                opaque_10: 0,
                opaque_14: 0,
            });
            entries.add(1).write(IndexedTimestampEntry {
                scaled_value_low: 10,
                scaled_value_high: 0,
                timestamp_low: 100,
                timestamp_high: 0,
                opaque_10: 0,
                opaque_14: 0,
            });
            table.write(IndexedTimestampTable {
                entry_count: 2,
                entries: entries as usize as u32,
            });
            state.write(IndexedTimestampBoundsState {
                opaque_00_34: [0; 14],
                entries_table: table as usize as u32,
                opaque_3c_60: [0; 10],
                time_divisor: 2,
                opaque_68_98: [0; 13],
                time_scale: 3,
                opaque_a0_c0: [0; 9],
                current_index: 1,
                timestamp_low: 0,
                timestamp_high: 0,
                end_low: 0,
                end_high: 0,
                scaled_low: 0,
                scaled_high: 0,
            });

            indexed_timestamp_bounds_update(state);
            assert_eq!(((*state).timestamp_low, (*state).timestamp_high), (100, 0));
            assert_eq!(((*state).scaled_low, (*state).scaled_high), (15, 0));
            assert_eq!(((*state).end_low, (*state).end_high), (115, 0));
        }
    }

    #[test]
    fn signed_product_uses_unsigned_division_bit_pattern() {
        let _guard = FIXTURE_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some((state, table, entries)) = (unsafe { fixture() }) else {
            assert!(note_missing_u32_fixture("app::indexed_timestamp_bounds"));
            return;
        };

        unsafe {
            entries.write(IndexedTimestampEntry {
                scaled_value_low: (-10i64) as u64 as u32,
                scaled_value_high: ((-10i64) as u64 >> 32) as u32,
                timestamp_low: 9,
                timestamp_high: 0,
                opaque_10: 0,
                opaque_14: 0,
            });
            table.write(IndexedTimestampTable {
                entry_count: 1,
                entries: entries as usize as u32,
            });
            state.write(IndexedTimestampBoundsState {
                opaque_00_34: [0; 14],
                entries_table: table as usize as u32,
                opaque_3c_60: [0; 10],
                time_divisor: 2,
                opaque_68_98: [0; 13],
                time_scale: 3,
                opaque_a0_c0: [0; 9],
                current_index: 0,
                timestamp_low: 0,
                timestamp_high: 0,
                end_low: 0,
                end_high: 0,
                scaled_low: 0,
                scaled_high: 0,
            });

            indexed_timestamp_bounds_update(state);
            assert_eq!(((*state).scaled_low, (*state).scaled_high), (0xffff_fff1, 0x7fff_ffff));
            assert_eq!(((*state).end_low, (*state).end_high), (0xffff_fffa, 0x7fff_ffff));
        }
    }

    #[test]
    fn exhausted_table_stores_maximum_end_sentinel() {
        let _guard = FIXTURE_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some((state, table, _entries)) = (unsafe { fixture() }) else {
            assert!(note_missing_u32_fixture("app::indexed_timestamp_bounds"));
            return;
        };

        unsafe {
            table.write(IndexedTimestampTable { entry_count: 1, entries: 0 });
            state.write(IndexedTimestampBoundsState {
                opaque_00_34: [0; 14],
                entries_table: table as usize as u32,
                opaque_3c_60: [0; 10],
                time_divisor: 0,
                opaque_68_98: [0; 13],
                time_scale: 0,
                opaque_a0_c0: [0; 9],
                current_index: 1,
                timestamp_low: 1,
                timestamp_high: 2,
                end_low: 3,
                end_high: 4,
                scaled_low: 5,
                scaled_high: 6,
            });

            indexed_timestamp_bounds_update(state);
            assert_eq!(((*state).timestamp_low, (*state).timestamp_high), (u32::MAX, i32::MAX as u32));
            assert_eq!(((*state).scaled_low, (*state).scaled_high), (0, 0));
            assert_eq!(((*state).end_low, (*state).end_high), (u32::MAX, i32::MAX as u32));
        }
    }
}
