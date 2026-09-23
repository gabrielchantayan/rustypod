//! Loads a window of MOV `stsz` per-sample sizes — `FUN_081c538c` @ 0x081c538c.
//!
//! Raw `osos.dec` establishes the exact 120-byte extent
//! 0x081c538c..0x081c5403; 0x081c5404 begins the next function with its own
//! push prologue. Whole-image A32 decoding finds three inbound plain `bl`
//! calls and no predicated `bl` calls. The body makes one plain `bl`, to the
//! ported `u32_window_reader` at 0x081c3960, and no predicated calls.
//!
//! Algorithm: fixed-size `stsz` tables need no per-sample window. Otherwise,
//! cap a requested window at 0x8000 entries and the remaining sample count,
//! read big-endian sizes from atom payload byte offset `20 + index * 4`, then
//! record the loaded window index. Any reader failure maps to retailOS status
//! 3.
//!
//! Deliberate deviation: the target calls the already ported reader directly;
//! host tests install an ABI-equivalent seam because target-width parser fields
//! cannot hold native pointers.

#[cfg(not(target_os = "none"))]
use core::ptr::addr_of;

#[cfg(target_os = "none")]
use super::u32_window_reader::{u32_window_reader, U32WindowReadOwner};

/// `stsz` table fields consumed by this loader.
#[repr(C)]
pub struct MovSampleSizeTable {
    /// +0x00: fixed sample size; zero selects per-sample entries.
    pub fixed_sample_size: u32,
    /// +0x04: total sample count.
    pub sample_count: u32,
    /// +0x08: first sample in the loaded window.
    pub window_index: u32,
    /// +0x0c: destination u32-entry storage.
    pub entries: u32,
}

/// Target-width parser view used by the `stsz` loader.
#[repr(C)]
pub struct MovSampleSizeParser {
    pub unresolved_00_to_17: [u32; 6],
    /// +0x18: `MovSampleSizeTable` as a target u32 pointer.
    pub sample_sizes: u32,
    pub unresolved_1c_to_ec: [u32; 53],
    /// +0xf0: little-endian low/high words of the atom payload base.
    pub payload_base_lo: u32,
    pub payload_base_hi: u32,
}

/// ABI of the shared big-endian u32 window reader.
pub type MovSampleSizeReadWindow = unsafe extern "C" fn(*mut MovSampleSizeParser, u32, u32, u32, u32) -> u32;

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct MovSampleSizeTableLoaderOps {
    pub read_u32_window: MovSampleSizeReadWindow,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_read_u32_window(
    _parser: *mut MovSampleSizeParser,
    _entries: u32,
    _offset_lo: u32,
    _offset_hi: u32,
    _sample_count: u32,
) -> u32 {
    panic!("install MOV sample-size loader host operations before calling this wrapper")
}

#[cfg(not(target_os = "none"))]
pub static mut MOV_SAMPLE_SIZE_TABLE_LOADER_OPS: MovSampleSizeTableLoaderOps = MovSampleSizeTableLoaderOps {
    read_u32_window: missing_read_u32_window,
};

#[inline(always)]
unsafe fn read_u32_window(
    parser: *mut MovSampleSizeParser,
    entries: u32,
    offset_lo: u32,
    offset_hi: u32,
    sample_count: u32,
) -> u32 {
    #[cfg(target_os = "none")]
    {
        unsafe { u32_window_reader(parser.cast::<U32WindowReadOwner>(), entries as usize as *mut u32, offset_lo, offset_hi, sample_count) }
    }
    #[cfg(not(target_os = "none"))]
    {
        let helper = unsafe { core::ptr::read_volatile(addr_of!(MOV_SAMPLE_SIZE_TABLE_LOADER_OPS.read_u32_window)) };
        unsafe { helper(parser, entries, offset_lo, offset_hi, sample_count) }
    }
}

/// Loads up to 0x8000 per-sample sizes from an `stsz` atom payload.
///
/// # Safety
///
/// `parser`, its +0x18 table word, and the table's +0x0c storage word must
/// name readable/writable target-layout objects accepted by the window reader.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn mov_sample_size_table_load_window(
    parser: *mut MovSampleSizeParser,
    index: u32,
) -> u32 {
    let table = unsafe { (*parser).sample_sizes as usize as *mut MovSampleSizeTable };
    if unsafe { (*table).fixed_sample_size } != 0 {
        return 0;
    }
    let sample_count = unsafe { (*table).sample_count };
    let window_count = if sample_count > index.wrapping_add(0x8000) {
        0x8000
    } else {
        sample_count.wrapping_sub(index)
    };
    let byte_offset = index.wrapping_shl(2);
    let (payload_lo, carry) = unsafe { (*parser).payload_base_lo.overflowing_add(byte_offset) };
    let payload_hi = unsafe { (*parser).payload_base_hi.wrapping_add(carry as u32) };
    if unsafe {
        read_u32_window(
            parser,
            (*table).entries,
            payload_lo.wrapping_add(20),
            payload_hi.wrapping_add((payload_lo > u32::MAX - 20) as u32),
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
        try_map_u32_slab(hints::MOV_SAMPLE_SIZE_TABLE_LOAD_WINDOW, 0x1000).map(|pointer| pointer as usize)
    });
    static mut CALL: Option<(u32, u32, u32, u32)> = None;
    static mut RESULT: u32 = 0;

    unsafe extern "C" fn record_read(
        _parser: *mut MovSampleSizeParser,
        entries: u32,
        offset_lo: u32,
        offset_hi: u32,
        sample_count: u32,
    ) -> u32 {
        unsafe { CALL = Some((entries, offset_lo, offset_hi, sample_count)); RESULT }
    }

    #[test]
    fn fixed_size_skips_reader() {
        let _guard = LOCK.lock();
        let Some(table) = *TABLE else {
            assert!(note_missing_u32_fixture("mov/sample_size_table_load_window"));
            return;
        };
        let table = table as *mut MovSampleSizeTable;
        unsafe { table.write(MovSampleSizeTable { fixed_sample_size: 4, sample_count: 9, window_index: 2, entries: 0x11 }) };
        unsafe { MOV_SAMPLE_SIZE_TABLE_LOADER_OPS.read_u32_window = record_read; CALL = None };
        let mut parser = MovSampleSizeParser { unresolved_00_to_17: [0; 6], sample_sizes: table as u32, unresolved_1c_to_ec: [0; 53], payload_base_lo: 0, payload_base_hi: 0 };
        assert_eq!(unsafe { mov_sample_size_table_load_window(addr_of_mut!(parser), 7) }, 0);
        assert_eq!(unsafe { CALL }, None);
        assert_eq!(unsafe { (*table).window_index }, 2);
    }

    #[test]
    fn caps_window_and_carries_payload_offset() {
        let _guard = LOCK.lock();
        let Some(table) = *TABLE else {
            assert!(note_missing_u32_fixture("mov/sample_size_table_load_window"));
            return;
        };
        let table = table as *mut MovSampleSizeTable;
        unsafe { table.write(MovSampleSizeTable { fixed_sample_size: 0, sample_count: 0x8001, window_index: 0, entries: 0x1234_5678 }) };
        unsafe { MOV_SAMPLE_SIZE_TABLE_LOADER_OPS.read_u32_window = record_read; CALL = None; RESULT = 0 };
        let mut parser = MovSampleSizeParser { unresolved_00_to_17: [0; 6], sample_sizes: table as u32, unresolved_1c_to_ec: [0; 53], payload_base_lo: 0xffff_fff8, payload_base_hi: 7 };
        assert_eq!(unsafe { mov_sample_size_table_load_window(addr_of_mut!(parser), 0) }, 0);
        assert_eq!(unsafe { CALL }, Some((0x1234_5678, 12, 8, 0x8000)));
        assert_eq!(unsafe { (*table).window_index }, 0);
    }

    #[test]
    fn uses_remaining_samples_and_preserves_index_on_failure() {
        let _guard = LOCK.lock();
        let Some(table) = *TABLE else {
            assert!(note_missing_u32_fixture("mov/sample_size_table_load_window"));
            return;
        };
        let table = table as *mut MovSampleSizeTable;
        unsafe { table.write(MovSampleSizeTable { fixed_sample_size: 0, sample_count: 9, window_index: 2, entries: 0x11 }) };
        unsafe { MOV_SAMPLE_SIZE_TABLE_LOADER_OPS.read_u32_window = record_read; CALL = None; RESULT = 1 };
        let mut parser = MovSampleSizeParser { unresolved_00_to_17: [0; 6], sample_sizes: table as u32, unresolved_1c_to_ec: [0; 53], payload_base_lo: 0x1000, payload_base_hi: 2 };
        assert_eq!(unsafe { mov_sample_size_table_load_window(addr_of_mut!(parser), 7) }, 3);
        assert_eq!(unsafe { CALL }, Some((0x11, 0x1030, 2, 2)));
        assert_eq!(unsafe { (*table).window_index }, 2);
    }
}
