//! Reverse-packed MOV chain record word lookup.
//!
//! Original: FUN_081e48b8 @ 0x081e48b8, 168 bytes through 0x081e4960
//! (164 instruction bytes plus the +0x7fff8 literal). Raw A32 decoding finds
//! two inbound plain BLs (0x081e3c34, 0x081e3d60), zero predicated BLs,
//! and one outbound plain BL to mov_chain_table_lookup_tagged_value.
//! Resolve the tagged chain value using playback state +0x1060/+0x1394;
//! reject lookup failure, a signed record index >= the signed +0x7fff8 count,
//! or a layout other than 0/1. Layouts select 12/16-byte reverse-packed
//! records; return their word at record +0x7fff8 - stride*(index+1).
//! Negative indices and overflowing products retain ARM wrapping semantics.
//! No deliberate behavioral deviations; reuse the native-pointer state prefix
//! used by chain_value_span so host fixtures preserve its +0x1060 field.

use super::chain_table::{mov_chain_table_lookup_tagged_value, MOV_CHAIN_TABLE_OK};
use super::chain_value_span::MovPlaybackManagerChainState;

/// # Safety
/// State must contain a readable manager pointer at +0x1060 and word at
/// +0x1394. A successful lookup must return a target-width pointer with a
/// readable count at +0x7fff8 and readable selected word (including admitted
/// negative indices). `out` must be writable on success; failures do not store.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn mov_chain_table_load_record_word(
    state: *mut MovPlaybackManagerChainState, chain_index: i32,
    layout: u32, record_index: i32, out: *mut u32,
) -> i32 {
    let manager = unsafe { core::ptr::addr_of!((*state).chain_table_manager).read() };
    let match_value = unsafe { state.cast::<u32>().add(0x1394 / 4).read() };
    let mut record = 0;
    if unsafe { mov_chain_table_lookup_tagged_value(manager, &mut record, chain_index, match_value) }
        != MOV_CHAIN_TABLE_OK
    {
        return 3;
    }
    let count = unsafe { (record.wrapping_add(0x7fff8) as usize as *const i32).read() };
    if record_index >= count {
        return 3;
    }
    let stride = match layout {
        0 => 12i32,
        1 => 16i32,
        _ => return 3,
    };
    // The stock signed divide-by-four then multiply-by-four does not alter
    // these products: both supported strides are multiples of four.
    let offset = (0x7fff8u32).wrapping_sub(stride as u32)
        .wrapping_sub(record_index.wrapping_mul(stride) as u32);
    let word = unsafe { (record.wrapping_add(offset) as usize as *const u32).read() };
    unsafe { out.write(word) };
    0
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::kernel::sync_mutex::Mutex;
    use crate::mov::chain_table::{MovChainEntry, MovChainTable, MovChainTableManager, MOV_CHAIN_TABLE_SLOTS};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    #[test]
    fn reverse_records_signed_bounds_and_lookup_failures() {
        let Some(record) = try_map_u32_slab(hints::MOV_CHAIN_TABLE_LOAD_RECORD_WORD, 0x81000) else {
            assert!(note_missing_u32_fixture("mov/chain_record_word"));
            return;
        };
        let mut manager = MovChainTableManager {
            table: MovChainTable { entries: [const { MovChainEntry {
                field_00: 0, field_04: 0, tag: 0, pad_09: [0; 3], next: 0, field_10: 0,
            } }; MOV_CHAIN_TABLE_SLOTS] },
            mutex: Mutex { sem_cell: core::ptr::null_mut(), unused: 0 },
            lock_service: core::ptr::null_mut(),
        };
        manager.table.entries[7].field_00 = record as usize as u32;
        manager.table.entries[7].tag = 3;
        manager.table.entries[7].field_10 = 0x12345678;
        // Aligned backing with enough room for the real state and manager fields.
        let mut state_words = [0usize; 0x1400 / core::mem::size_of::<usize>()];
        let state = state_words.as_mut_ptr().cast::<MovPlaybackManagerChainState>();
        unsafe {
            core::ptr::addr_of_mut!((*state).chain_table_manager).write(&mut manager);
            state.cast::<u32>().add(0x1394 / 4).write(0x12345678);
        }
        let base = record.cast::<u8>();
        let mut out;
        for layout in [0, 1] {
            let stride = if layout == 0 { 12 } else { 16 };
            unsafe { base.add(0x7fff8).cast::<i32>().write(3) };
            for index in [0i32, 1, 2, -1, -2, i32::MIN] {
                let offset = 0x7fff8u32.wrapping_sub(stride)
                    .wrapping_sub((index as u32).wrapping_mul(stride));
                let expected = if index == -1 { 3 } else { 0xaabb0000 | (index as u32 & 0xffff) };
                unsafe { base.add(offset as usize).cast::<u32>().write(expected) };
                out = 0xdeadbeef;
                assert_eq!(unsafe { mov_chain_table_load_record_word(state, 7, layout, index, &mut out) }, 0);
                assert_eq!(out, expected);
            }
            for index in [3, 4, i32::MAX] {
                out = 0xdeadbeef;
                assert_eq!(unsafe { mov_chain_table_load_record_word(state, 7, layout, index, &mut out) }, 3);
                assert_eq!(out, 0xdeadbeef);
            }
        }
        for (count, index, layout, chain) in [(0, 0, 0, 7), (-2, -2, 1, 7), (3, 0, 2, 7),
            (3, 0, u32::MAX, 7), (3, 0, 0, -1), (3, 0, 0, 128), (3, 0, 0, 8)] {
            unsafe { base.add(0x7fff8).cast::<i32>().write(count) };
            out = 0xdeadbeef;
            assert_eq!(unsafe { mov_chain_table_load_record_word(state, chain, layout, index, &mut out) }, 3);
            assert_eq!(out, 0xdeadbeef);
        }
        manager.table.entries[7].tag = 2;
        assert_eq!(unsafe { mov_chain_table_load_record_word(state, 7, 0, 0, core::ptr::null_mut()) }, 3);
        manager.table.entries[7].tag = 3;
        manager.table.entries[7].field_10 = 99;
        assert_eq!(unsafe { mov_chain_table_load_record_word(state, 7, 0, 0, core::ptr::null_mut()) }, 3);
    }
}
