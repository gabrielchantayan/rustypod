//! Timestamp-table cursor seek.
//!
//! `timestamp_index_seek` — original: `FUN_081c55c8` @ `0x081c55c8` (132
//! bytes, exact: `0x081c55c8..0x081c564b`; the independently entered next
//! function begins at `0x081c564c`). A full-image A32 decode finds three
//! inbound direct `bl` sites — plain unconditional calls at `0x081c5dbc`,
//! `0x081c6c34`, and `0x081c6ee8` — and zero predicated `bl` sites.
//!
//! Raw ARM reads the signed timestamp table at state+0x40 and maintains the
//! selected index at +0xa4. A target at or after the final timestamp selects
//! the final entry. Otherwise, a nonzero existing cursor is retained when the
//! target lies in its `(previous, current]` interval; index zero deliberately
//! enters the scan. All other targets scan from zero to select the first
//! timestamp greater than or equal to the target.
//!
//! Deliberate deviation: the partially recovered state and table are expressed
//! as target-word layouts instead of guessed complete C++ classes. The original
//! uses a linear scan, which the Rust port retains.

/// Target-width timestamp-table header at state+0x40.
#[repr(C)]
pub struct TimestampIndexTable {
    pub count: u32,
    pub timestamps: u32,
}

const _: [u8; 0x08] = [0; core::mem::size_of::<TimestampIndexTable>()];

/// Observed fields of the timestamp-index owner.
#[repr(C)]
pub struct TimestampIndexState {
    pub opaque_00_3c: [u32; 16],
    pub table: u32,
    pub opaque_44_a0: [u32; 24],
    pub selected_index: u32,
}

const _: [u8; 0x40] = [0; core::mem::offset_of!(TimestampIndexState, table)];
const _: [u8; 0xa4] = [0; core::mem::offset_of!(TimestampIndexState, selected_index)];
const _: [u8; 0xa8] = [0; core::mem::size_of::<TimestampIndexState>()];

/// Selects the first signed timestamp at or after `target_timestamp`.
///
/// # Safety
///
/// `state` must be non-null and four-byte aligned. Its target-width table and
/// timestamp pointer must be readable, the table count must be nonzero, and
/// `selected_index` must be a valid table index. RetailOS supplies those
/// preconditions; this port adds no guards.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn timestamp_index_seek(
    state: *mut TimestampIndexState,
    target_timestamp: i32,
) {
    let table = (*state).table as usize as *const TimestampIndexTable;
    let timestamps = (*table).timestamps as usize as *const i32;
    let count = (*table).count;
    let last_index = count.wrapping_sub(1);

    if *timestamps.add(last_index as usize) <= target_timestamp {
        (*state).selected_index = last_index;
        return;
    }

    let selected_index = (*state).selected_index;
    if selected_index != 0 {
        let previous_timestamp = *timestamps.add(selected_index as usize - 1);
        if previous_timestamp >= target_timestamp {
            return;
        }
        if *timestamps.add(selected_index as usize) >= target_timestamp {
            return;
        }
    }

    let mut index = 0;
    while index < last_index && *timestamps.add(index as usize) < target_timestamp {
        index += 1;
    }
    (*state).selected_index = index;
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
        try_map_u32_slab(hints::TIMESTAMP_INDEX_SEEK, FIXTURE_LEN).map(|pointer| pointer as usize)
    });
    static FIXTURE_LOCK: Mutex<()> = Mutex::new(());

    fn reference_cursor(timestamps: &[i32], selected_index: usize, target: i32) -> usize {
        if timestamps[timestamps.len() - 1] <= target {
            return timestamps.len() - 1;
        }
        if selected_index != 0 && timestamps[selected_index - 1] >= target {
            return selected_index;
        }
        if timestamps[selected_index] >= target {
            return selected_index;
        }
        timestamps.iter().position(|&timestamp| timestamp >= target).unwrap()
    }

    #[test]
    fn seeks_signed_timestamps_and_retains_current_interval() {
        let _guard = FIXTURE_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some(base) = *FIXTURE else {
            assert!(note_missing_u32_fixture("app::timestamp_index_seek"));
            return;
        };

        let timestamps = [-10, 0, 5, 20];
        unsafe {
            let base = base as *mut u8;
            ptr::write_bytes(base, 0, FIXTURE_LEN);
            let table = base.cast::<TimestampIndexTable>();
            let values = base.add(0x100).cast::<i32>();
            for (index, &timestamp) in timestamps.iter().enumerate() {
                values.add(index).write(timestamp);
            }
            table.write(TimestampIndexTable {
                count: timestamps.len() as u32,
                timestamps: values as usize as u32,
            });

            for (selected_index, target) in [(0, -15), (2, -1), (2, 5), (2, 7), (1, 100)] {
                let mut state = TimestampIndexState {
                    opaque_00_3c: [0; 16],
                    table: table as usize as u32,
                    opaque_44_a0: [0; 24],
                    selected_index,
                };
                timestamp_index_seek(&mut state, target);
                assert_eq!(state.selected_index as usize, reference_cursor(&timestamps, selected_index as usize, target));
            }
        }
    }

    #[test]
    fn ordering_is_signed_not_unsigned() {
        let _guard = FIXTURE_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some(base) = *FIXTURE else {
            assert!(note_missing_u32_fixture("app::timestamp_index_seek"));
            return;
        };

        let timestamps = [-2, 1, 5];
        unsafe {
            let base = base as *mut u8;
            ptr::write_bytes(base, 0, FIXTURE_LEN);
            let table = base.cast::<TimestampIndexTable>();
            let values = base.add(0x100).cast::<i32>();
            for (index, &timestamp) in timestamps.iter().enumerate() {
                values.add(index).write(timestamp);
            }
            table.write(TimestampIndexTable {
                count: timestamps.len() as u32,
                timestamps: values as usize as u32,
            });

            for (selected_index, target) in [(1, -3), (0, -1), (1, i32::MAX)] {
                let mut state = TimestampIndexState {
                    opaque_00_3c: [0; 16],
                    table: table as usize as u32,
                    opaque_44_a0: [0; 24],
                    selected_index,
                };
                timestamp_index_seek(&mut state, target);
                assert_eq!(state.selected_index as usize, reference_cursor(&timestamps, selected_index as usize, target));
            }
        }
    }
}
