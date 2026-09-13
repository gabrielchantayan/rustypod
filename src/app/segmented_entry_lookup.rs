//! `segmented_entry_lookup` — original: `FUN_082ce368` @ `0x082ce368`
//! (88 bytes).
//!
//! Raw `osos.dec` establishes the exact extent `0x082ce368..0x082ce3c0`:
//! the next separately linked function begins with `push {r0-r12,lr}` at
//! `0x082ce3c0`. Decoding every ARM `B`/`BL` immediate finds six direct
//! inbound calls, all unconditional `bl` at `0x082b6080`, `0x082b66d0`,
//! `0x082b67a4`, `0x082b697c`, `0x082e877c`, and `0x083710f8`; there are no
//! predicated forms.
//!
//! # Algorithm
//!
//! The table has up to five eight-byte override slots. Starting at the last
//! populated slot, the routine ignores a slot whose unsigned 16-bit boundary
//! is greater than the signed requested index; it returns that slot's direct
//! entry when equal, and otherwise decrements the index before considering
//! the next slot. If no slot matches, it reads a big-endian 16-bit entry offset
//! from `entry_data + offset_table_start + 2 * adjusted_index` and returns
//! `entry_data + entry_offset`.
//!
//! # Deliberate deviations
//!
//! None. The original has no pointer, count, index, or table-range guards;
//! this port retains those caller-owned preconditions.

/// One eight-byte override in a [`SegmentedEntryTable`].
#[repr(C)]
pub struct SegmentedEntryOverride {
    /// Returned directly when `boundary` equals the adjusted lookup index.
    pub direct_entry: u32,
    /// Inclusive boundary for this override.
    pub boundary: u16,
    pub opaque_06_to_07: [u8; 2],
}

const _: [u8; 0x00] = [0; core::mem::offset_of!(SegmentedEntryOverride, direct_entry)];
const _: [u8; 0x04] = [0; core::mem::offset_of!(SegmentedEntryOverride, boundary)];
const _: [u8; 0x08] = [0; core::mem::size_of::<SegmentedEntryOverride>()];

/// Recovered prefix and five override slots used by `segmented_entry_lookup`.
///
/// `entry_data` is a target-width pointer and therefore stays a `u32` on host
/// tests. The opaque bytes include fields interpreted by neighbouring retailOS
/// code but not by this leaf lookup.
#[repr(C)]
pub struct SegmentedEntryTable {
    pub opaque_00_to_01: [u8; 2],
    pub override_count: u8,
    pub opaque_03_to_0d: [u8; 11],
    pub offset_table_start: u16,
    pub opaque_10_to_17: [u8; 8],
    pub overrides: [SegmentedEntryOverride; 5],
    pub opaque_40_to_43: [u8; 4],
    pub entry_data: u32,
}

const _: [u8; 0x02] = [0; core::mem::offset_of!(SegmentedEntryTable, override_count)];
const _: [u8; 0x0e] = [0; core::mem::offset_of!(SegmentedEntryTable, offset_table_start)];
const _: [u8; 0x18] = [0; core::mem::offset_of!(SegmentedEntryTable, overrides)];
const _: [u8; 0x44] = [0; core::mem::offset_of!(SegmentedEntryTable, entry_data)];
const _: [u8; 0x48] = [0; core::mem::size_of::<SegmentedEntryTable>()];

/// Resolves `index` to a direct override entry or a big-endian offset-table entry.
///
/// Original: `FUN_082ce368` @ `0x082ce368` (88 bytes; six unconditional direct
/// `bl` call sites, binary-scanned). The override count must be at most five;
/// all pointer and table-range validation remains the caller's responsibility,
/// as in retailOS.
///
/// # Safety
///
/// `table` must identify readable, aligned [`SegmentedEntryTable`] storage,
/// `override_count` must not exceed five, and `entry_data` plus every selected
/// offset-table/entry offset must identify readable target storage.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.segmented_entry_lookup")]
#[inline(never)]
pub unsafe extern "C" fn segmented_entry_lookup(
    table: *const SegmentedEntryTable,
    index: i32,
) -> *mut u8 {
    let mut adjusted_index = index;
    let table_ref = unsafe { &*table };

    for override_index in (0..usize::from(table_ref.override_count)).rev() {
        let entry_override = unsafe { table_ref.overrides.get_unchecked(override_index) };
        let boundary = i32::from(entry_override.boundary);
        if boundary > adjusted_index {
            continue;
        }
        if boundary == adjusted_index {
            return entry_override.direct_entry as usize as *mut u8;
        }
        adjusted_index = adjusted_index.wrapping_sub(1);
    }

    let entry_data = table_ref.entry_data as usize as *const u8;
    let table_offset = u32::from(table_ref.offset_table_start)
        .wrapping_add((adjusted_index as u32).wrapping_shl(1)) as usize;
    let entry_offset = (u32::from(unsafe { entry_data.add(table_offset).read() }) << 8)
        | u32::from(unsafe { entry_data.add(table_offset + 1).read() });
    unsafe { entry_data.add(entry_offset as usize) as *mut u8 }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::{LazyLock, Mutex, MutexGuard};

    const FIXTURE_LEN: usize = 0x1000;
    const ENTRY_DATA_OFFSET: usize = 0x200;
    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::SEGMENTED_ENTRY_LOOKUP, FIXTURE_LEN).map(|pointer| pointer as usize)
    });
    static FIXTURE_LOCK: Mutex<()> = Mutex::new(());

    fn fixture() -> Option<(*mut SegmentedEntryTable, *mut u8, MutexGuard<'static, ()>)> {
        let guard = FIXTURE_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let base = (*FIXTURE)? as *mut u8;
        unsafe { core::ptr::write_bytes(base, 0, FIXTURE_LEN) };
        let table = base.cast::<SegmentedEntryTable>();
        let entry_data = unsafe { base.add(ENTRY_DATA_OFFSET) };
        unsafe {
            (*table).entry_data = entry_data as usize as u32;
        }
        Some((table, entry_data, guard))
    }

    #[test]
    fn reads_big_endian_offset_without_overrides() {
        let Some((table, entry_data, _guard)) = fixture() else {
            assert!(note_missing_u32_fixture("app::segmented_entry_lookup"));
            return;
        };
        unsafe {
            (*table).offset_table_start = 0x80;
            entry_data.add(0x80).write(0x01);
            entry_data.add(0x81).write(0x20);
            entry_data.add(0x82).write(0x00);
            entry_data.add(0x83).write(0x34);

            assert_eq!(segmented_entry_lookup(table, 0), entry_data.add(0x120));
            assert_eq!(segmented_entry_lookup(table, 1), entry_data.add(0x34));
        }
    }

    #[test]
    fn walks_overrides_backwards_and_adjusts_nonmatching_indices() {
        let Some((table, entry_data, _guard)) = fixture() else {
            assert!(note_missing_u32_fixture("app::segmented_entry_lookup"));
            return;
        };
        unsafe {
            (*table).override_count = 3;
            (*table).offset_table_start = 0x80;
            (*table).overrides[0].boundary = 1;
            (*table).overrides[0].direct_entry = entry_data.add(0x111) as usize as u32;
            (*table).overrides[1].boundary = 3;
            (*table).overrides[1].direct_entry = entry_data.add(0x133) as usize as u32;
            (*table).overrides[2].boundary = 5;
            (*table).overrides[2].direct_entry = entry_data.add(0x155) as usize as u32;
            entry_data.add(0x84).write(0x01);
            entry_data.add(0x85).write(0x77);

            assert_eq!(segmented_entry_lookup(table, 5), entry_data.add(0x155));
            assert_eq!(segmented_entry_lookup(table, 4), entry_data.add(0x177));
        }
    }
}
