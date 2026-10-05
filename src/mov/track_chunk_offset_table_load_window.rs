//! Track chunk-offset window loader — FUN_081c4ff4 at 0x081c4ff4.
//!
//! True extent: 124 bytes, 0x081c4ff4..0x081c5070 (exclusive), followed
//! by a separate push prologue. Raw A32 decoding verifies two inbound plain
//! BLs at 0x081c6718 and 0x081c6828, zero predicated inbound BLs, and one
//! outbound plain BL to u32_window_reader (0x081c3960), zero predicated BLs.
//!
//! Reject a missing current track with status 3. Load at most 0x4000 chunk
//! offsets from the track's +0x48/+0x4c base plus the wrapping 32-bit index*4
//! and 16-byte atom header. Bounds use signed ARM comparisons. On success,
//! reload the current track/table and record the window index; failures map
//! to status 3. Deliberate deviation: call the established Rust reader rather
//! than the retail address. The host reader pointer is native-width, with
//! padding adjusted to retain the track slot at +0x1b8; track/table pointers
//! remain target-width words. No additional validation or error paths.

use super::chunk_offset_table_load_window::MovChunkOffsetTable;
use super::u32_window_reader::{u32_window_reader, U32WindowReadOwner};

#[repr(C)]
pub struct MovTrackChunkOffsetParser {
    pub owner: U32WindowReadOwner,
    pub unresolved_to_track: [u32; (0x1b8 - core::mem::size_of::<U32WindowReadOwner>()) / 4],
    pub current_track: u32,
}

#[repr(C)]
pub struct MovChunkOffsetTrack {
    pub unresolved_00_to_0c: [u32; 4],
    pub chunk_offsets: u32,
    pub unresolved_14_to_44: [u32; 13],
    pub payload_base_lo: u32,
    pub payload_base_hi: u32,
}

/// # Safety
/// Parser and non-null track/table words must name live aligned objects.
/// The reader must accept the computed window, including retail wrapping
/// counts for out-of-range indices. It may replace the track/table on success.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn mov_track_chunk_offset_table_load_window(
    parser: *mut MovTrackChunkOffsetParser,
    index: u32,
) -> u32 {
    let track = unsafe { (*parser).current_track as usize as *mut MovChunkOffsetTrack };
    if track.is_null() {
        return 3;
    }
    let table = unsafe { (*track).chunk_offsets as usize as *mut MovChunkOffsetTable };
    let count = unsafe { (*table).entry_count };
    let window_count = if (count as i32) > (index.wrapping_add(0x4000) as i32) {
        0x4000
    } else {
        count.wrapping_sub(index)
    };
    let (lo, carry) = unsafe { (*track).payload_base_lo.overflowing_add(index.wrapping_shl(2)) };
    let hi = unsafe { (*track).payload_base_hi.wrapping_add(carry as u32) };
    let (lo, carry) = lo.overflowing_add(16);
    let result = unsafe {
        u32_window_reader(
            core::ptr::addr_of_mut!((*parser).owner),
            (*table).entries as usize as *mut u32,
            lo,
            hi.wrapping_add(carry as u32),
            window_count,
        )
    };
    if result != 0 {
        return 3;
    }
    let track = unsafe { (*parser).current_track as usize as *mut MovChunkOffsetTrack };
    let table = unsafe { (*track).chunk_offsets as usize as *mut MovChunkOffsetTable };
    unsafe { (*table).window_index = index };
    0
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use super::super::u32_window_reader::{U32WindowReader, U32WindowReaderVtable};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    static LOCK: Mutex<()> = Mutex::new(());
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::MOV_TRACK_CHUNK_OFFSET_WINDOW, 0x20000).map(|p| p as usize)
    });

    #[repr(C)]
    struct Reader {
        base: U32WindowReader,
        offset: u64,
        bytes: u32,
        fail: bool,
        replacement: u32,
        parser: *mut MovTrackChunkOffsetParser,
    }

    unsafe extern "C" fn prepare(reader: *mut U32WindowReader, _: *mut u32, lo: u32, hi: u32, _: u32) -> u32 {
        let reader = unsafe { &mut *reader.cast::<Reader>() };
        reader.offset = ((hi as u64) << 32) | lo as u64;
        if reader.replacement != 0 {
            unsafe { (*reader.parser).current_track = reader.replacement };
        }
        reader.fail as u32
    }

    unsafe extern "C" fn read(reader: *mut U32WindowReader, output: *mut u32, bytes: u32, mode: u32, _: u32) -> u32 {
        assert_eq!(mode, 2);
        unsafe { (*reader.cast::<Reader>()).bytes = bytes };
        for i in 0..bytes / 4 {
            unsafe { output.add(i as usize).write((i + 7).swap_bytes()) };
        }
        0
    }

    #[test]
    fn real_reader_windows_carries_failures_and_reloaded_track() {
        let _lock = LOCK.lock();
        let Some(slab) = *SLAB else {
            assert!(note_missing_u32_fixture("mov/track_chunk_offset_table_load_window"));
            return;
        };
        let track = slab as *mut MovChunkOffsetTrack;
        let table = (slab + 0x100) as *mut MovChunkOffsetTable;
        let replacement = (slab + 0x200) as *mut MovChunkOffsetTrack;
        let replacement_table = (slab + 0x300) as *mut MovChunkOffsetTable;
        let output = (slab + 0x1000) as *mut u32;
        let vtable = U32WindowReaderVtable { unresolved_00_to_0f: [0; 4], read_slot_10: read, prepare_slot_14: prepare };
        let mut reader = Reader { base: U32WindowReader { vtable: &vtable }, offset: 0, bytes: 0, fail: false, replacement: 0, parser: core::ptr::null_mut() };
        let mut parser = MovTrackChunkOffsetParser {
            owner: U32WindowReadOwner { unresolved_00_to_07: [0; 2], reader: &mut reader.base },
            unresolved_to_track: [0; (0x1b8 - core::mem::size_of::<U32WindowReadOwner>()) / 4],
            current_track: 0,
        };
        reader.parser = &mut parser;
        assert_eq!(unsafe { mov_track_chunk_offset_table_load_window(&mut parser, 0) }, 3);
        assert_eq!(reader.bytes, 0);
        unsafe {
            track.write(MovChunkOffsetTrack { unresolved_00_to_0c: [0; 4], chunk_offsets: table as u32, unresolved_14_to_44: [0; 13], payload_base_lo: 0xffff_fff8, payload_base_hi: 7 });
            replacement.write(MovChunkOffsetTrack { chunk_offsets: replacement_table as u32, ..core::ptr::read(track) });
            replacement_table.write(MovChunkOffsetTable { entry_count: 0, window_index: 99, entries: output as u32 });
        }
        for (count, index, expected_count) in [(0, 0, 0), (9, 7, 2), (0x5000, 1, 0x4000), (0x8000_0000, 0, 0x8000_0000), (0, 0xffff_ffff, 1)] {
            parser.current_track = track as u32;
            unsafe { table.write(MovChunkOffsetTable { entry_count: count, window_index: 99, entries: output as u32 }) };
            reader.bytes = 0;
            reader.fail = expected_count > 0x4000;
            let result = unsafe { mov_track_chunk_offset_table_load_window(&mut parser, index) };
            assert_eq!(result, if reader.fail { 3 } else { 0 });
            let expected_offset = (7u64 << 32) | 0xffff_fff8;
            assert_eq!(reader.offset, expected_offset.wrapping_add(index.wrapping_shl(2) as u64).wrapping_add(16));
            assert_eq!(unsafe { (*table).window_index }, if reader.fail { 99 } else { index });
            if !reader.fail {
                assert_eq!(reader.bytes, expected_count * 4);
                for i in 0..expected_count {
                    assert_eq!(unsafe { *output.add(i as usize) }, i + 7);
                }
            }
        }
        parser.current_track = track as u32;
        unsafe { (*table).entry_count = 1; (*table).window_index = 99 };
        reader.fail = false;
        reader.replacement = replacement as u32;
        assert_eq!(unsafe { mov_track_chunk_offset_table_load_window(&mut parser, 0) }, 0);
        assert_eq!(unsafe { (*table).window_index }, 99);
        assert_eq!(unsafe { (*replacement_table).window_index }, 0);
    }
}
