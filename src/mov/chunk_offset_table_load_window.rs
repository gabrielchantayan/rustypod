//! Loads a window of MOV `stco` chunk offsets — `FUN_081c5224` @ 0x081c5224.
//!
//! Raw `osos.dec` establishes the exact 100-byte extent
//! 0x081c5224..0x081c5287; 0x081c5288 begins the next function with its own
//! push prologue. Whole-image A32 decoding finds four incoming plain `bl`
//! calls and no predicated `bl` calls. The body makes one plain `bl`, to the
//! unported 0x081c3960 helper, and no predicated calls.
//!
//! Algorithm: cap the requested `stco` entries at 0x4000 and at the remaining
//! table count. Ask the common big-endian-u32 window reader to fill the table
//! storage from atom payload byte offset `16 + index * 4`, using the parser's
//! 64-bit payload base at +0xe0. On success, advance the table index; map any
//! helper failure to retailOS status 3.
//!
//! Deliberate deviation: `FUN_081c3960` has no stronger established semantic
//! identity than its verified window-read behavior, so target builds call its
//! fixed address while host tests use a volatile ABI seam. Target pointer
//! fields remain u32 words on hosts to preserve their original offsets.

#[cfg(not(target_os = "none"))]
use core::ptr::addr_of;

const RETAIL_READ_U32_WINDOW: usize = 0x081c_3960;

/// `stco` table fields consumed by this loader.
#[repr(C)]
pub struct MovChunkOffsetTable {
    /// +0x00: total entry count.
    pub entry_count: u32,
    /// +0x04: first entry in the loaded window.
    pub window_index: u32,
    /// +0x08: destination u32-entry storage.
    pub entries: u32,
}

/// Target-width parser view used by the `stco` loader.
#[repr(C)]
pub struct MovChunkOffsetParser {
    pub unresolved_00_to_1c: [u32; 8],
    /// +0x20: `MovChunkOffsetTable` as a target u32 pointer.
    pub chunk_offsets: u32,
    pub unresolved_24_to_dc: [u32; 47],
    /// +0xe0: little-endian low/high words of the atom payload base.
    pub payload_base_lo: u32,
    pub payload_base_hi: u32,
}

/// ABI of the unported u32-window reader at 0x081c3960.
pub type MovReadU32Window = unsafe extern "C" fn(
    *mut MovChunkOffsetParser,
    u32,
    u32,
    u32,
    u32,
) -> u32;

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct MovChunkOffsetLoaderOps {
    pub read_u32_window: MovReadU32Window,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_read_u32_window(
    _parser: *mut MovChunkOffsetParser,
    _entries: u32,
    _offset_lo: u32,
    _offset_hi: u32,
    _entry_count: u32,
) -> u32 {
    panic!("install MOV chunk-offset loader host operations before calling this wrapper")
}

#[cfg(not(target_os = "none"))]
pub static mut MOV_CHUNK_OFFSET_LOADER_OPS: MovChunkOffsetLoaderOps = MovChunkOffsetLoaderOps {
    read_u32_window: missing_read_u32_window,
};

#[inline(always)]
unsafe fn read_u32_window(
    parser: *mut MovChunkOffsetParser,
    entries: u32,
    offset_lo: u32,
    offset_hi: u32,
    entry_count: u32,
) -> u32 {
    #[cfg(target_os = "none")]
    {
        let helper: MovReadU32Window = unsafe { core::mem::transmute(RETAIL_READ_U32_WINDOW) };
        return unsafe { helper(parser, entries, offset_lo, offset_hi, entry_count) };
    }
    #[cfg(not(target_os = "none"))]
    {
        let helper = unsafe { core::ptr::read_volatile(addr_of!(MOV_CHUNK_OFFSET_LOADER_OPS.read_u32_window)) };
        unsafe { helper(parser, entries, offset_lo, offset_hi, entry_count) }
    }
}

/// Loads up to 0x4000 big-endian chunk offsets from the parser's `stco` atom.
///
/// # Safety
///
/// `parser`, its +0x20 table word, and the table's +0x08 storage word must
/// name readable/writable target-layout objects accepted by the window reader.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn mov_chunk_offset_table_load_window(
    parser: *mut MovChunkOffsetParser,
    index: u32,
) -> u32 {
    let table = unsafe { (*parser).chunk_offsets as usize as *mut MovChunkOffsetTable };
    let entry_count = unsafe { (*table).entry_count };
    let window_count = if entry_count > index.wrapping_add(0x4000) {
        0x4000
    } else {
        entry_count.wrapping_sub(index)
    };
    let byte_offset = index.wrapping_shl(2);
    let (payload_lo, carry) = unsafe { (*parser).payload_base_lo.overflowing_add(byte_offset) };
    let payload_hi = unsafe { (*parser).payload_base_hi.wrapping_add(carry as u32) };
    if unsafe {
        read_u32_window(
            parser,
            (*table).entries,
            payload_lo.wrapping_add(16),
            payload_hi.wrapping_add((payload_lo > u32::MAX - 16) as u32),
            window_count,
        )
    } != 0 {
        3
    } else {
        unsafe { (*table).window_index = index };
        0
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr::addr_of_mut;
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    static LOCK: Mutex<()> = Mutex::new(());
    static TABLE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::MOV_CHUNK_OFFSET_TABLE_LOAD_WINDOW, 0x1000).map(|pointer| pointer as usize)
    });
    static mut CALL: Option<(u32, u32, u32, u32)> = None;
    static mut RESULT: u32 = 0;

    unsafe extern "C" fn record_read(
        _parser: *mut MovChunkOffsetParser,
        entries: u32,
        offset_lo: u32,
        offset_hi: u32,
        entry_count: u32,
    ) -> u32 {
        unsafe { CALL = Some((entries, offset_lo, offset_hi, entry_count)); RESULT }
    }

    #[test]
    fn caps_window_and_carries_payload_offset() {
        let _guard = LOCK.lock();
        let Some(table) = *TABLE else {
            assert!(note_missing_u32_fixture("mov/chunk_offset_table_load_window"));
            return;
        };
        let table = table as *mut MovChunkOffsetTable;
        unsafe { table.write(MovChunkOffsetTable { entry_count: 0x5001, window_index: 0, entries: 0x1234_5678 }) };
        unsafe { MOV_CHUNK_OFFSET_LOADER_OPS.read_u32_window = record_read; CALL = None; RESULT = 0 };
        let mut parser = MovChunkOffsetParser { unresolved_00_to_1c: [0; 8], chunk_offsets: table as u32, unresolved_24_to_dc: [0; 47], payload_base_lo: 0xffff_fff8, payload_base_hi: 7 };
        assert_eq!(unsafe { mov_chunk_offset_table_load_window(addr_of_mut!(parser), 0) }, 0);
        assert_eq!(unsafe { CALL }, Some((0x1234_5678, 8, 8, 0x4000)));
        assert_eq!(unsafe { (*table).window_index }, 0);
    }

    #[test]
    fn uses_remaining_entries_and_preserves_index_on_failure() {
        let _guard = LOCK.lock();
        let Some(table) = *TABLE else {
            assert!(note_missing_u32_fixture("mov/chunk_offset_table_load_window"));
            return;
        };
        let table = table as *mut MovChunkOffsetTable;
        unsafe { table.write(MovChunkOffsetTable { entry_count: 9, window_index: 2, entries: 0x11 }) };
        unsafe { MOV_CHUNK_OFFSET_LOADER_OPS.read_u32_window = record_read; CALL = None; RESULT = 1 };
        let mut parser = MovChunkOffsetParser { unresolved_00_to_1c: [0; 8], chunk_offsets: table as u32, unresolved_24_to_dc: [0; 47], payload_base_lo: 0x1000, payload_base_hi: 2 };
        assert_eq!(unsafe { mov_chunk_offset_table_load_window(addr_of_mut!(parser), 7) }, 3);
        assert_eq!(unsafe { CALL }, Some((0x11, 0x102c, 2, 2)));
        assert_eq!(unsafe { (*table).window_index }, 2);
    }
}
