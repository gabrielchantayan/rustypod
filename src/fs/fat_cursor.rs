//! FAT directory cursor synchronization.
//!
//! `fat_cursor_synchronize` is retailOS `FUN_082b2014` at load address
//! **0x082b2014**, 140 bytes (`0x082b2014..0x082b20a0`; the separately entered
//! next function starts at `0x082b20a0`). Decoding every ARM B/BL-immediate
//! word in `osos.dec` finds eight direct inbound calls, all unconditional
//! plain `bl` at `0x082b19b4`, `0x082b1c64`, `0x082b1ccc`, `0x082e5ebc`,
//! `0x082e620c`, `0x082e62d0`, `0x082e65b8`, and `0x082e6650`; no predicated
//! branch or aligned data word targets this entry.
//!
//! # Algorithm
//!
//! A zero current cluster is initialized from the cursor state's FAT directory
//! entry, then translated to its cache-block index. When the advance flag is
//! set and the current cluster is nonzero, it instead reads the next FAT
//! cluster. A successful advance updates the cache-block index, clears both
//! the advance flag and current cluster; a zero next-cluster result preserves
//! the cursor unchanged. The raw body has no NULL guards.
//!
//! # Deliberate deviations
//!
//! None. Ghidra's unused second parameter and apparent 64-bit return from
//! `FUN_082e01cc` are artifacts: the decoded ARM consumes only `r0`, returns
//! only `r0`, and initializes its `r1` scratch register to zero.

use super::fat_cluster_to_block::fat_cluster_to_block_index;
use super::fat_dirent::{fat_dirent_start_cluster, FatDirEntry, FatVolume};
use super::fat_next_cluster::fat_next_cluster;

/// Target-width cursor state at `FatCursor.state`.
///
/// The two words are firmware pointers, stored as `u32` so their offsets stay
/// valid on both the 32-bit target and 64-bit test host.
#[repr(C)]
pub struct FatCursorState {
    volume: u32,
    entry: u32,
}

/// FAT directory cursor fields inspected by the retail synchronizer.
#[repr(C)]
pub struct FatCursor {
    state: u32,
    _unknown_04: [u32; 2],
    current_cluster: u32,
    current_block: u32,
    _unknown_14: [u32; 2],
    advance: u32,
}

const _: () = assert!(core::mem::offset_of!(FatCursorState, volume) == 0x00);
const _: () = assert!(core::mem::offset_of!(FatCursorState, entry) == 0x04);
const _: () = assert!(core::mem::offset_of!(FatCursor, state) == 0x00);
const _: () = assert!(core::mem::offset_of!(FatCursor, current_cluster) == 0x0c);
const _: () = assert!(core::mem::offset_of!(FatCursor, current_block) == 0x10);
const _: () = assert!(core::mem::offset_of!(FatCursor, advance) == 0x1c);

#[inline(always)]
unsafe fn cursor_state(cursor: *const FatCursor) -> *const FatCursorState {
    unsafe { (*cursor).state as usize as *const FatCursorState }
}

#[inline(always)]
unsafe fn state_volume(state: *const FatCursorState) -> *mut FatVolume {
    unsafe { (*state).volume as usize as *mut FatVolume }
}

#[inline(always)]
unsafe fn state_entry(state: *const FatCursorState) -> *const FatDirEntry {
    unsafe { (*state).entry as usize as *const FatDirEntry }
}

/// Initializes or advances a FAT directory cursor.
///
/// Original: `FUN_082b2014` at load address `0x082b2014`, 140 bytes, eight
/// verified plain-`bl` callers. The second Ghidra parameter is not read by
/// the ARM body.
///
/// # Safety
///
/// `cursor`, its target-width state pointer, and that state's volume and
/// directory-entry pointers must be valid whenever the selected path reads
/// them. The nested FAT helpers retain their own unchecked contracts.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.fat_cursor_synchronize")]
#[inline(never)]
pub unsafe extern "C" fn fat_cursor_synchronize(cursor: *mut FatCursor) {
    let mut cluster = unsafe { (*cursor).current_cluster };

    if cluster == 0 {
        let state = unsafe { cursor_state(cursor) };
        let volume = unsafe { state_volume(state) };
        cluster = unsafe { fat_dirent_start_cluster(volume, state_entry(state)) };
        unsafe { (*cursor).current_cluster = cluster; }

        if cluster == 0 {
            unsafe { (*cursor).current_block = 0; }
        } else {
            unsafe { (*cursor).current_block = fat_cluster_to_block_index(volume, cluster); }
        }
    }

    if unsafe { (*cursor).advance } != 0 && cluster != 0 {
        let state = unsafe { cursor_state(cursor) };
        let volume = unsafe { state_volume(state) };
        let next_cluster = unsafe { fat_next_cluster(volume, cluster) };
        if next_cluster != 0 {
            unsafe {
                (*cursor).current_cluster = next_cluster;
                let next_block = fat_cluster_to_block_index(volume, next_cluster);
                core::ptr::addr_of_mut!((*cursor).current_block).write_volatile(next_block);
                (*cursor).advance = 0;
                (*cursor).current_cluster = 0;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::fs::cache_position_value::{
        replace_read_cache_position_value, CACHE_POSITION_VALUE_TEST_LOCK,
    };
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr;
    use std::sync::{LazyLock, Mutex};

    const SLAB_LEN: usize = 0x1000;
    const STATE_AT: usize = 0x100;
    const VOLUME_AT: usize = 0x200;
    const ENTRY_AT: usize = 0x500;
    const FIRST_DATA_BLOCK_WORD: usize = 29;
    const CLUSTER_BLOCK_SHIFT_HALFWORD: usize = 231;
    const CACHE_BLOCK_LIMIT_WORD: usize = 118;

    static FIXTURE_BASE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::FAT_CURSOR_SYNCHRONIZE, SLAB_LEN).map(|pointer| pointer as usize)
    });
    static FIXTURE_LOCK: Mutex<()> = Mutex::new(());

    unsafe extern "C" fn read_next_cluster(
        _cache: *mut u8, _position: u32, value: *mut u32,
    ) -> u32 {
        unsafe { value.write(9); }
        1
    }

    unsafe extern "C" fn fail_to_read_next_cluster(
        _cache: *mut u8, _position: u32, _value: *mut u32,
    ) -> u32 {
        0
    }

    unsafe fn fixture(start_cluster: u16) -> Option<*mut FatCursor> {
        let base = *FIXTURE_BASE.as_ref()? as *mut u8;
        unsafe {
            ptr::write_bytes(base, 0, SLAB_LEN);
            let cursor = base.cast::<FatCursor>();
            let state = base.add(STATE_AT);
            let volume = base.add(VOLUME_AT);
            let entry = base.add(ENTRY_AT);
            (*cursor).state = state as usize as u32;
            (state as *mut u32).write(volume as usize as u32);
            (state.add(4) as *mut u32).write(entry as usize as u32);
            (volume as *mut u32).add(FIRST_DATA_BLOCK_WORD).write(10);
            (volume as *mut u16).add(CLUSTER_BLOCK_SHIFT_HALFWORD).write(2);
            (volume as *mut u32).add(CACHE_BLOCK_LIMIT_WORD).write(100);
            (entry.add(0x1a) as *mut u16).write(start_cluster);
            Some(cursor)
        }
    }

    #[test]
    fn initializes_empty_cursor_from_its_directory_entry() {
        let _fixture_guard = FIXTURE_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some(cursor) = (unsafe { fixture(3) }) else {
            assert!(note_missing_u32_fixture("fs/fat_cursor"));
            return;
        };

        unsafe { fat_cursor_synchronize(cursor); }

        assert_eq!(unsafe { (*cursor).current_cluster }, 3);
        assert_eq!(unsafe { (*cursor).current_block }, 14);
    }

    #[test]
    fn leaves_cached_cursor_unchanged_without_an_advance_request() {
        let _fixture_guard = FIXTURE_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some(cursor) = (unsafe { fixture(3) }) else {
            assert!(note_missing_u32_fixture("fs/fat_cursor"));
            return;
        };
        unsafe {
            (*cursor).current_cluster = 7;
            (*cursor).current_block = 0xfeed_beef;
            (*cursor).state = 0;
        }

        unsafe { fat_cursor_synchronize(cursor); }

        assert_eq!(unsafe { (*cursor).current_cluster }, 7);
        assert_eq!(unsafe { (*cursor).current_block }, 0xfeed_beef);
    }

    #[test]
    fn advances_then_marks_the_cursor_for_reinitialization() {
        let _fixture_guard = FIXTURE_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let _cache_guard = CACHE_POSITION_VALUE_TEST_LOCK.lock();
        let Some(cursor) = (unsafe { fixture(3) }) else {
            assert!(note_missing_u32_fixture("fs/fat_cursor"));
            return;
        };
        unsafe {
            (*cursor).current_cluster = 5;
            (*cursor).current_block = 22;
            (*cursor).advance = 1;
            let previous = replace_read_cache_position_value(read_next_cluster);
            fat_cursor_synchronize(cursor);
            replace_read_cache_position_value(previous);
        }

        assert_eq!(unsafe { (*cursor).current_cluster }, 0);
        assert_eq!(unsafe { (*cursor).current_block }, 38);
        assert_eq!(unsafe { (*cursor).advance }, 0);
    }

    #[test]
    fn preserves_advance_request_when_next_cluster_is_unavailable() {
        let _fixture_guard = FIXTURE_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let _cache_guard = CACHE_POSITION_VALUE_TEST_LOCK.lock();
        let Some(cursor) = (unsafe { fixture(3) }) else {
            assert!(note_missing_u32_fixture("fs/fat_cursor"));
            return;
        };
        unsafe {
            (*cursor).current_cluster = 5;
            (*cursor).current_block = 22;
            (*cursor).advance = 1;
            let previous = replace_read_cache_position_value(fail_to_read_next_cluster);
            fat_cursor_synchronize(cursor);
            replace_read_cache_position_value(previous);
        }

        assert_eq!(unsafe { (*cursor).current_cluster }, 5);
        assert_eq!(unsafe { (*cursor).current_block }, 22);
        assert_eq!(unsafe { (*cursor).advance }, 1);
    }
}
