//! Loads a MOV chained-table value's playback span.
//!
//! Port:
//! - [`mov_chain_table_load_span`] — original: `FUN_081e32a8` @
//!   **0x081e32a8** (**80 bytes**, 0x081e32a8..0x081e32f8; **7 direct call
//!   sites, all unconditional `bl`, zero predicated forms**), verified from
//!   `osos.dec` by decoding every ARM B/BL word: 0x081e4020, 0x081e4088,
//!   0x081e43f8, 0x081e4430, 0x081e4eb0, 0x081e4ecc, and 0x081e4f6c.
//!
//! # Algorithm
//!
//! The function reads the chained-table manager from the MOV playback state
//! at +0x1060 and calls
//! [`crate::mov::chain_table::mov_chain_table_lookup_tagged_value`] with the
//! caller's signed chain index and state word +0x1394. On success, the
//! returned (non-null) value pointer identifies a 0x80000-byte record. The
//! word at +0x7fff4 becomes `*start`; the word at +0x7fff0 becomes `*length`.
//! Any lookup failure returns 3 and leaves both output words untouched.
//!
//! `MOV_PLAYBACK_MANAGER_MATCH_VALUE_WORD` deliberately models the second
//! state field as a word index rather than a host-width pointer-containing
//! `repr(C)` tail: the firmware object's fields are four bytes apart, whereas
//! a host pointer is eight bytes. No NULL guards or alignment repairs are
//! added; stock faults on invalid pointers.

use crate::mov::chain_table::{
    mov_chain_table_lookup_tagged_value, MovChainTableManager, MOV_CHAIN_TABLE_OK,
};

/// Word index of the match value at playback-state byte offset +0x1394.
const MOV_PLAYBACK_MANAGER_MATCH_VALUE_WORD: usize = 0x1394 / core::mem::size_of::<u32>();
/// Word indexes of the span fields in a chain-table value record.
const MOV_CHAIN_VALUE_LENGTH_WORD: usize = 0x7fff0 / core::mem::size_of::<u32>();
const MOV_CHAIN_VALUE_START_WORD: usize = 0x7fff4 / core::mem::size_of::<u32>();

/// The prefix of the MOV playback state needed to locate its chained-table
/// manager. Its native pointer field remains at +0x1060 on both the 32-bit
/// target and the host; later 32-bit fields are accessed by word index.
#[repr(C)]
pub struct MovPlaybackManagerChainState {
    reserved_0000_105f: [u32; 0x1060 / core::mem::size_of::<u32>()],
    pub chain_table_manager: *mut MovChainTableManager,
}

const _: () = assert!(core::mem::offset_of!(MovPlaybackManagerChainState, chain_table_manager) == 0x1060);

/// mov_chain_table_load_span — original: `FUN_081e32a8` @ 0x081e32a8
/// (80 bytes, 0x081e32a8..0x081e32f8; **7 direct call sites, all
/// unconditional `bl`, zero predicated forms** — counted by decoding every
/// ARM B/BL word in `osos.dec`).
///
/// Resolves `chain_index` with the playback state's match value, then stores
/// the resolved record's +0x7fff4 start word and +0x7fff0 length word. Returns
/// 0 on success; returns 3 when the chained-table lookup rejects the index,
/// tag, match value, or null record pointer. Lookup failure leaves `start` and
/// `length` untouched.
///
/// # Deviations
///
/// None. Output stores retain stock's order (`start` before `length`) and use
/// aligned word loads, matching the two `ldr` instructions after the lookup.
///
/// # Safety
///
/// `state` must point to the MOV playback state through +0x1397; `start` and
/// `length` must be writable when lookup succeeds. A successful lookup must
/// return a word-aligned pointer to a readable record through +0x7fff7. None
/// of these pointers are NULL-checked, matching stock.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.mov_chain_table_load_span")]
pub unsafe extern "C" fn mov_chain_table_load_span(
    state: *mut MovPlaybackManagerChainState,
    chain_index: i32,
    start: *mut u32,
    length: *mut u32,
) -> i32 {
    let manager = unsafe { core::ptr::read(core::ptr::addr_of!((*state).chain_table_manager)) };
    let match_value = unsafe {
        core::ptr::read(state.cast::<u32>().add(MOV_PLAYBACK_MANAGER_MATCH_VALUE_WORD))
    };
    let mut value = 0u32;
    if unsafe { mov_chain_table_lookup_tagged_value(manager, &mut value, chain_index, match_value) }
        != MOV_CHAIN_TABLE_OK
    {
        return 3;
    }

    let value = value as usize as *const u32;
    let resolved_start = unsafe { core::ptr::read(value.add(MOV_CHAIN_VALUE_START_WORD)) };
    let resolved_length = unsafe { core::ptr::read(value.add(MOV_CHAIN_VALUE_LENGTH_WORD)) };
    unsafe { core::ptr::write(start, resolved_start) };
    unsafe { core::ptr::write(length, resolved_length) };
    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::kernel::sync_mutex::Mutex;
    use crate::mov::chain_table::{MovChainEntry, MovChainTable, MOV_CHAIN_TABLE_SLOTS};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::{LazyLock, Mutex as TestMutex};

    const POISON: u32 = 0xdead_beef;
    const VALUE_BYTES: usize = (MOV_CHAIN_VALUE_START_WORD + 1) * core::mem::size_of::<u32>();
    static VALUE_RECORD: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::MOV_CHAIN_TABLE_LOAD_SPAN, VALUE_BYTES).map(|p| p as usize)
    });
    static TEST_LOCK: TestMutex<()> = TestMutex::new(());

    #[repr(C)]
    struct StateFixture {
        state: MovPlaybackManagerChainState,
        /// Extends the object beyond the +0x1394 match-value word on hosts.
        trailing_words: [u32; 0x330 / core::mem::size_of::<u32>()],
    }

    fn fresh_manager() -> MovChainTableManager {
        MovChainTableManager {
            table: MovChainTable {
                entries: [const {
                    MovChainEntry {
                        field_00: 0,
                        field_04: 0,
                        tag: 0,
                        pad_09: [0; 3],
                        next: 0,
                        field_10: 0,
                    }
                }; MOV_CHAIN_TABLE_SLOTS],
            },
            mutex: Mutex { sem_cell: core::ptr::null_mut(), unused: 0 },
            lock_service: core::ptr::null_mut(),
        }
    }

    fn fresh_state(manager: *mut MovChainTableManager, match_value: u32) -> StateFixture {
        let mut fixture = StateFixture {
            state: MovPlaybackManagerChainState {
                reserved_0000_105f: [0; 0x1060 / core::mem::size_of::<u32>()],
                chain_table_manager: manager,
            },
            trailing_words: [0; 0x330 / core::mem::size_of::<u32>()],
        };
        unsafe {
            core::ptr::write(
                core::ptr::addr_of_mut!(fixture.state).cast::<u32>().add(MOV_PLAYBACK_MANAGER_MATCH_VALUE_WORD),
                match_value,
            );
        }
        fixture
    }

    fn value_record() -> Option<*mut u32> {
        (*VALUE_RECORD).map(|address| address as *mut u32)
    }

    /// A matching entry resolves a low-address record and preserves the stock
    /// output order: +0x7fff4 is start, followed by +0x7fff0 as length.
    #[test]
    fn loads_span_words_from_matching_value_record() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some(record) = value_record() else {
            assert!(note_missing_u32_fixture("mov/chain_value_span"));
            return;
        };
        unsafe { core::ptr::write_bytes(record.cast::<u8>(), 0, VALUE_BYTES) };
        let mut manager = fresh_manager();
        let match_value = 0xa5a5_5a5a;
        manager.table.entries[17].field_00 = record as usize as u32;
        manager.table.entries[17].tag = 3;
        manager.table.entries[17].field_10 = match_value;
        unsafe {
            core::ptr::write(record.add(MOV_CHAIN_VALUE_START_WORD), 0x1020_3040);
            core::ptr::write(record.add(MOV_CHAIN_VALUE_LENGTH_WORD), 0x0001_0203);
        }
        let mut state = fresh_state(&mut manager, match_value);
        let mut start = POISON;
        let mut length = POISON;

        let rc = unsafe { mov_chain_table_load_span(&mut state.state, 17, &mut start, &mut length) };

        assert_eq!(rc, 0);
        assert_eq!((start, length), (0x1020_3040, 0x0001_0203));

        // Raw pointers permit the stock-observable aliasing case. The final
        // word must be length, proving the two stores remain start then length.
        let mut aliased_output = POISON;
        let output = core::ptr::addr_of_mut!(aliased_output);
        let rc = unsafe { mov_chain_table_load_span(&mut state.state, 17, output, output) };
        assert_eq!(rc, 0);
        assert_eq!(aliased_output, 0x0001_0203);
    }

    /// Lookup failure returns 3 before either resolved-record load or output
    /// store, so both sentinels survive tag, match, index, and null-value
    /// rejection paths.
    #[test]
    fn lookup_failures_leave_outputs_untouched() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let mut manager = fresh_manager();
        let match_value = 0x55;
        manager.table.entries[3].field_00 = 0x1234_5678;
        manager.table.entries[3].tag = 2;
        manager.table.entries[3].field_10 = match_value;
        let mut state = fresh_state(&mut manager, match_value);

        for index in [3, -1, 128] {
            let mut start = POISON;
            let mut length = POISON;
            let rc = unsafe { mov_chain_table_load_span(&mut state.state, index, &mut start, &mut length) };
            assert_eq!(rc, 3, "index {index}");
            assert_eq!((start, length), (POISON, POISON), "index {index}");
        }
    }
}
