//! `opaque_record_source_entry_lookup` — original: `FUN_0827b434` @ `0x0827b434`
//! (68 bytes, `0x0827b434..0x0827b478`; the next real function starts at
//! `0x0827b478`).
//!
//! Raw ARM contains one plain unconditional `bl`, to the verified entry-count
//! accessor at `0x081c1cdc`. Whole-image immediate-branch decoding finds three
//! direct inbound plain unconditional `bl` calls (`0x081a1980`, `0x081a19d8`,
//! and `0x081a1a20`) and no predicated inbound `bl` calls.
//!
//! # Algorithm
//!
//! Get the signed entry count through the source's provider word at `+0x04`.
//! Treat the requested index and count as unsigned, reject an out-of-range index
//! or a null entry-table word at `+0x08`, and copy the selected 16-byte entry.
//!
//! # Deliberate deviations
//!
//! The unported `FUN_081c1cdc` is reached through the already verified
//! `opaque_record_source_entry_count` port, which implements its three loads;

use crate::app::opaque_record_source_entry_count::opaque_record_source_entry_count;

const PROVIDER_OFFSET: usize = 0x04;
const ENTRY_TABLE_OFFSET: usize = 0x08;
const ENTRY_BYTES: usize = 0x10;

/// The recovered prefix used to look up fixed-size opaque entries.
///
/// Pointer fields remain target-width `u32` values on host builds.
#[repr(C)]
pub struct OpaqueRecordSourceEntryTable {
    pub opaque_00: u32,
    pub provider: u32,
    pub entries: u32,
}

const _: [u8; 0x04] = [0; core::mem::offset_of!(OpaqueRecordSourceEntryTable, provider)];
const _: [u8; 0x08] = [0; core::mem::offset_of!(OpaqueRecordSourceEntryTable, entries)];

/// Copies entry `index` from `source` into `output`, returning zero on success.
///
/// Original: `FUN_0827b434` @ `0x0827b434` (68 bytes; one plain body `bl`,
/// three direct inbound plain `bl` calls, and no predicated inbound `bl` calls).
/// The index comparison is unsigned and neither pointer receives a null guard.
///
/// # Safety
///
/// `source` must identify readable, aligned [`OpaqueRecordSourceEntryTable`]
/// storage. Its provider must meet `opaque_record_source_entry_count`'s safety
/// requirements. When the index is in range, `entries` must be zero or identify
/// `index * 16 + 16` readable bytes; `output` must identify 16 writable bytes.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.opaque_record_source_entry_lookup")]
#[inline(never)]
pub unsafe extern "C" fn opaque_record_source_entry_lookup(
    source: *const OpaqueRecordSourceEntryTable,
    index: usize,
    output: *mut u8,
) -> i32 {
    if (opaque_record_source_entry_count(source.cast()) as u32) <= index as u32 {
        return -1;
    }

    let entries = unsafe { source.add(0).cast::<u8>().add(ENTRY_TABLE_OFFSET).cast::<u32>().read() };
    if entries == 0 {
        return -1;
    }

    let entry = (entries as usize as *const u8)
        .add((index as u32).wrapping_mul(ENTRY_BYTES as u32) as usize)
        .cast::<u32>();
    let word_0 = entry.read();
    let word_1 = entry.add(1).read();
    let word_2 = entry.add(2).read();
    let word_3 = entry.add(3).read();
    let output = output.cast::<u32>();
    output.write(word_0);
    output.add(1).write(word_1);
    output.add(2).write(word_2);
    output.add(3).write(word_3);
    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::{LazyLock, Mutex, MutexGuard};

    const FIXTURE_LEN: usize = 0x1000;
    const PROVIDER_OFFSET_IN_FIXTURE: usize = 0x100;
    const COUNT_STATE_OFFSET_IN_FIXTURE: usize = 0x200;
    const ENTRIES_OFFSET_IN_FIXTURE: usize = 0x300;
    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::OPAQUE_RECORD_SOURCE_ENTRY_LOOKUP, FIXTURE_LEN).map(|pointer| pointer as usize)
    });
    static FIXTURE_LOCK: Mutex<()> = Mutex::new(());

    fn fixture() -> Option<(*mut u8, *mut u8, *mut u8, *mut u8, MutexGuard<'static, ()>)> {
        let guard = FIXTURE_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let base = (*FIXTURE)? as *mut u8;
        unsafe { core::ptr::write_bytes(base, 0, FIXTURE_LEN) };
        Some((
            base,
            unsafe { base.add(PROVIDER_OFFSET_IN_FIXTURE) },
            unsafe { base.add(COUNT_STATE_OFFSET_IN_FIXTURE) },
            unsafe { base.add(ENTRIES_OFFSET_IN_FIXTURE) },
            guard,
        ))
    }

    fn source(provider: *mut u8, entries: *mut u8) -> OpaqueRecordSourceEntryTable {
        OpaqueRecordSourceEntryTable {
            opaque_00: 0xdecafbad,
            provider: provider as usize as u32,
            entries: entries as usize as u32,
        }
    }

    #[test]
    fn rejects_unsigned_out_of_range_index_without_touching_output() {
        let Some((base, provider, count_state, entries, _guard)) = fixture() else {
            assert!(note_missing_u32_fixture("app::opaque_record_source_entry_lookup"));
            return;
        };
        unsafe {
            provider.add(0x1c).cast::<u32>().write(count_state as usize as u32);
            count_state.add(4).cast::<i32>().write(1);
            entries.cast::<u32>().write(0x1122_3344);
        }
        let source = source(provider, entries);
        let mut output = [0xa5_u8; ENTRY_BYTES];

        assert_eq!(unsafe { opaque_record_source_entry_lookup(&source, usize::MAX, output.as_mut_ptr()) }, -1);
        assert_eq!(output, [0xa5; ENTRY_BYTES]);
        let _ = base;
    }

    #[test]
    fn rejects_null_entry_table_without_touching_output() {
        let Some((_base, provider, count_state, _entries, _guard)) = fixture() else {
            assert!(note_missing_u32_fixture("app::opaque_record_source_entry_lookup"));
            return;
        };
        unsafe {
            provider.add(0x1c).cast::<u32>().write(count_state as usize as u32);
            count_state.add(4).cast::<i32>().write(1);
        }
        let source = source(provider, core::ptr::null_mut());
        let mut output = [0x5a_u8; ENTRY_BYTES];

        assert_eq!(unsafe { opaque_record_source_entry_lookup(&source, 0, output.as_mut_ptr()) }, -1);
        assert_eq!(output, [0x5a; ENTRY_BYTES]);
    }

    #[test]
    fn copies_selected_sixteen_byte_entry() {
        let Some((_base, provider, count_state, entries, _guard)) = fixture() else {
            assert!(note_missing_u32_fixture("app::opaque_record_source_entry_lookup"));
            return;
        };
        let first = [0x11_u8; ENTRY_BYTES];
        let second = [0x22_u8; ENTRY_BYTES];
        unsafe {
            provider.add(0x1c).cast::<u32>().write(count_state as usize as u32);
            count_state.add(4).cast::<i32>().write(2);
            core::ptr::copy_nonoverlapping(first.as_ptr(), entries, ENTRY_BYTES);
            core::ptr::copy_nonoverlapping(second.as_ptr(), entries.add(ENTRY_BYTES), ENTRY_BYTES);
        }
        let source = source(provider, entries);
        let mut output = [0_u8; ENTRY_BYTES];

        assert_eq!(unsafe { opaque_record_source_entry_lookup(&source, 1, output.as_mut_ptr()) }, 0);
        assert_eq!(output, second);
    }
}
