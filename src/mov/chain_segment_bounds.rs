//! Loads bounds for a MOV chained-table segment.
//!
//! Port:
//! - [`mov_chain_table_load_segment_bounds`] — original: `FUN_081e43cc` @
//!   **0x081e43cc** (**140 bytes**, 0x081e43cc..0x081e4458; **3 inbound
//!   direct call sites, all unconditional `bl`, zero predicated forms**).
//!
//! # Algorithm
//!
//! Resolves the segment's primary chain index into +0x1268, then resolves a
//! secondary index into +0x126c. The secondary index comes from +0x1264 when
//! the state-relative +0x13b0 flag is clear, otherwise +0x1248. On two
//! successful resolutions, +0x126c becomes its resolved start plus length.
//! Any lookup failure returns 3; a failed second lookup preserves its start.

use crate::mov::chain_value_span::{mov_chain_table_load_span, MovPlaybackManagerChainState};

const MOV_SEGMENT_STRIDE: usize = 0x50;
const MOV_SEGMENT_PRIMARY_INDEX_WORD: usize = 0x1240 / core::mem::size_of::<u32>();
const MOV_SEGMENT_ALTERNATE_SECONDARY_INDEX_WORD: usize = 0x1248 / core::mem::size_of::<u32>();
const MOV_SEGMENT_SECONDARY_INDEX_WORD: usize = 0x1264 / core::mem::size_of::<u32>();
const MOV_SEGMENT_PRIMARY_START_WORD: usize = 0x1268 / core::mem::size_of::<u32>();
const MOV_SEGMENT_SECONDARY_END_WORD: usize = 0x126c / core::mem::size_of::<u32>();
const MOV_SEGMENT_ALTERNATE_FLAG_OFFSET: usize = 0x13b0;

/// mov_chain_table_load_segment_bounds — original: `FUN_081e43cc` @ 0x081e43cc
/// (140 bytes, 0x081e43cc..0x081e4458; **3 inbound direct call sites, all
/// unconditional `bl`, zero predicated forms** — decoded from `osos.dec`).
///
/// Resolves the primary and selected secondary chain-table indices for
/// `segment_index`. On success stores the primary start at +0x1268 and the
/// secondary end (`start + length`, wrapping) at +0x126c. It returns 3 when
/// either resolution fails.
///
/// # Deviations
///
/// None. The flag is modeled state-relative: stock adds the state base to the
/// IRAM-mirror offset 0x13b0. Word-indexed fields preserve 32-bit firmware
/// offsets on 64-bit hosts.
///
/// # Safety
///
/// `state` must be writable through the selected segment's +0x126f and
/// readable through its +0x13b0 flag. It must also satisfy
/// [`mov_chain_table_load_span`]'s requirements.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.mov_chain_table_load_segment_bounds")]
pub unsafe extern "C" fn mov_chain_table_load_segment_bounds(
    state: *mut u8,
    segment_index: i32,
) -> i32 {
    let segment = unsafe { state.add(segment_index as usize * MOV_SEGMENT_STRIDE).cast::<u32>() };
    let primary_index = unsafe { core::ptr::read(segment.add(MOV_SEGMENT_PRIMARY_INDEX_WORD)) } as i32;
    let primary_start = unsafe { segment.add(MOV_SEGMENT_PRIMARY_START_WORD) };
    let mut length = 0u32;
    if unsafe {
        mov_chain_table_load_span(
            state.cast::<MovPlaybackManagerChainState>(),
            primary_index,
            primary_start,
            &mut length,
        )
    } != 0
    {
        return 3;
    }

    let secondary_index_word = if unsafe { core::ptr::read(state.add(MOV_SEGMENT_ALTERNATE_FLAG_OFFSET)) } == 0 {
        MOV_SEGMENT_SECONDARY_INDEX_WORD
    } else {
        MOV_SEGMENT_ALTERNATE_SECONDARY_INDEX_WORD
    };
    let secondary_index = unsafe { core::ptr::read(segment.add(secondary_index_word)) } as i32;
    let secondary_end = unsafe { segment.add(MOV_SEGMENT_SECONDARY_END_WORD) };
    if unsafe {
        mov_chain_table_load_span(
            state.cast::<MovPlaybackManagerChainState>(),
            secondary_index,
            secondary_end,
            &mut length,
        )
    } != 0
    {
        return 3;
    }
    unsafe { core::ptr::write(secondary_end, core::ptr::read(secondary_end).wrapping_add(length)) };
    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::kernel::sync_mutex::Mutex;
    use crate::mov::chain_table::{MovChainEntry, MovChainTable, MovChainTableManager, MOV_CHAIN_TABLE_SLOTS};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::{LazyLock, Mutex as TestMutex};

    const MATCH_VALUE: u32 = 0xa5a5_5a5a;
    const RECORD_WORDS: usize = 0x20000;
    const PRIMARY_RECORD: usize = 0;
    const STANDARD_RECORD: usize = 1;
    const ALTERNATE_RECORD: usize = 2;
    const START_WORD: usize = 0x7fff4 / 4;
    const LENGTH_WORD: usize = 0x7fff0 / 4;
    static RECORDS: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::MOV_CHAIN_TABLE_LOAD_SEGMENT_BOUNDS, RECORD_WORDS * 3 * 4).map(|p| p as usize)
    });
    static TEST_LOCK: TestMutex<()> = TestMutex::new(());

    #[repr(C, align(8))]
    struct StateFixture([u8; MOV_SEGMENT_ALTERNATE_FLAG_OFFSET + 8]);

    fn fresh_manager(records: *mut u32) -> MovChainTableManager {
        let mut manager = MovChainTableManager {
            table: MovChainTable { entries: [const { MovChainEntry { field_00: 0, field_04: 0, tag: 0, pad_09: [0; 3], next: 0, field_10: 0 } }; MOV_CHAIN_TABLE_SLOTS] },
            mutex: Mutex { sem_cell: core::ptr::null_mut(), unused: 0 },
            lock_service: core::ptr::null_mut(),
        };
        for (index, record) in [PRIMARY_RECORD, STANDARD_RECORD, ALTERNATE_RECORD].into_iter().enumerate() {
            manager.table.entries[index].field_00 = unsafe { records.add(record * RECORD_WORDS) } as usize as u32;
            manager.table.entries[index].tag = 3;
            manager.table.entries[index].field_10 = MATCH_VALUE;
        }
        manager
    }

    unsafe fn write_word(state: *mut u8, word: usize, value: u32) {
        unsafe { core::ptr::write(state.cast::<u32>().add(word), value) };
    }

    fn fresh_state(manager: *mut MovChainTableManager) -> StateFixture {
        let mut state = StateFixture([0; MOV_SEGMENT_ALTERNATE_FLAG_OFFSET + 8]);
        unsafe {
            core::ptr::write(state.0.as_mut_ptr().add(0x1060).cast::<*mut MovChainTableManager>(), manager);
            write_word(state.0.as_mut_ptr(), 0x1394 / 4, MATCH_VALUE);
        }
        state
    }

    #[test]
    fn stores_primary_start_and_selected_secondary_end() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some(records) = *RECORDS else { assert!(note_missing_u32_fixture("mov/chain_segment_bounds")); return; };
        let records = records as *mut u32;
        let mut manager = fresh_manager(records);
        let mut state = fresh_state(&mut manager);
        unsafe {
            for (record, start, length) in [(PRIMARY_RECORD, 0x1000, 9), (STANDARD_RECORD, 0x2000, 17), (ALTERNATE_RECORD, 0x3000, 33)] {
                core::ptr::write(records.add(record * RECORD_WORDS + START_WORD), start);
                core::ptr::write(records.add(record * RECORD_WORDS + LENGTH_WORD), length);
            }
            write_word(state.0.as_mut_ptr(), MOV_SEGMENT_PRIMARY_INDEX_WORD, 0);
            write_word(state.0.as_mut_ptr(), MOV_SEGMENT_SECONDARY_INDEX_WORD, 1);
            write_word(state.0.as_mut_ptr(), MOV_SEGMENT_ALTERNATE_SECONDARY_INDEX_WORD, 2);
            assert_eq!(mov_chain_table_load_segment_bounds(state.0.as_mut_ptr(), 0), 0);
            assert_eq!(core::ptr::read(state.0.as_ptr().cast::<u32>().add(MOV_SEGMENT_PRIMARY_START_WORD)), 0x1000);
            assert_eq!(core::ptr::read(state.0.as_ptr().cast::<u32>().add(MOV_SEGMENT_SECONDARY_END_WORD)), 0x2011);
            core::ptr::write(state.0.as_mut_ptr().add(MOV_SEGMENT_ALTERNATE_FLAG_OFFSET), 1);
            assert_eq!(mov_chain_table_load_segment_bounds(state.0.as_mut_ptr(), 0), 0);
            assert_eq!(core::ptr::read(state.0.as_ptr().cast::<u32>().add(MOV_SEGMENT_SECONDARY_END_WORD)), 0x3021);
        }
    }

    #[test]
    fn lookup_failure_returns_three_before_secondary_store() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some(records) = *RECORDS else { assert!(note_missing_u32_fixture("mov/chain_segment_bounds")); return; };
        let mut manager = fresh_manager(records as *mut u32);
        let mut state = fresh_state(&mut manager);
        unsafe {
            write_word(state.0.as_mut_ptr(), MOV_SEGMENT_PRIMARY_INDEX_WORD, 0);
            write_word(state.0.as_mut_ptr(), MOV_SEGMENT_SECONDARY_INDEX_WORD, 7);
            write_word(state.0.as_mut_ptr(), MOV_SEGMENT_SECONDARY_END_WORD, 0xdead_beef);
            assert_eq!(mov_chain_table_load_segment_bounds(state.0.as_mut_ptr(), 0), 3);
            assert_eq!(core::ptr::read(state.0.as_ptr().cast::<u32>().add(MOV_SEGMENT_SECONDARY_END_WORD)), 0xdead_beef);
        }
    }
}
