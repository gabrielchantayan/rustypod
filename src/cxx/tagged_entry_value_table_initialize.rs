//! Tagged entry value-table initialization — retailOS `FUN_082c568c` at load
//! address `0x082c568c` (88 bytes; `0x082c568c..0x082c56e4`). The next real
//! function begins at `0x082c56e4`.
//!
//! Raw `osos.dec` decoding finds two direct callers (`0x0838efec` and
//! `0x0838f068`), both plain unconditional `bl`; there are no predicated
//! `bl` callers. The function itself is a leaf and contains no `bl` calls.
//! It initializes a one-based value table once by scanning 20-byte entries:
//! entries tagged `0x1a` contribute their +0x10 word to table slot
//! (`entry[+4] - 1`).
//!
//! Deliberate deviation: none. The raw 32-bit pointer fields are retained as
//! `u32` words so their ARM layout remains correct on 64-bit test hosts.

const ENTRY_WORDS: usize = 5;
const ENTRY_TAG: u32 = 0x1a;
const ENTRY_TAG_OFFSET: usize = 0;
const ENTRY_TABLE_INDEX_OFFSET: usize = 1;
const ENTRY_VALUE_OFFSET: usize = 4;
const ENTRY_COUNT_OFFSET: usize = 3;
const ENTRIES_OFFSET: usize = 5;
const VALUE_TABLE_OFFSET: usize = 15;
const INITIALIZED_OFFSET: usize = 16;

/// Builds the one-based value table from tagged 20-byte entries, once.
///
/// `context` is the retail 32-bit layout. Its +0x0c count, +0x14 entry-base,
/// +0x3c value-table, and +0x40 initialized fields are accessed at their
/// original ARM offsets.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn tagged_entry_value_table_initialize(context: *mut u32) {
    if context.add(INITIALIZED_OFFSET).read() != 0 { return; }

    let entries = context.add(ENTRIES_OFFSET).read() as usize as *const u32;
    let entry_count = context.add(ENTRY_COUNT_OFFSET).read() as usize;
    let value_table = context.add(VALUE_TABLE_OFFSET).read() as usize as *mut u32;

    for entry_index in 0..entry_count {
        let entry = entries.add(entry_index * ENTRY_WORDS);
        if entry.add(ENTRY_TAG_OFFSET).read() == ENTRY_TAG {
            let table_index = entry.add(ENTRY_TABLE_INDEX_OFFSET).read() as usize;
            value_table.add(table_index - 1).write(entry.add(ENTRY_VALUE_OFFSET).read());
        }
    }

    context.add(INITIALIZED_OFFSET).write(1);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::LazyLock;

    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::TAGGED_ENTRY_VALUE_TABLE_INITIALIZE, 0x1000).map(|pointer| pointer as usize)
    });

    #[test]
    fn populates_one_based_slots_only_for_tag_1a_entries() {
        let Some(base) = *FIXTURE else { assert!(note_missing_u32_fixture("cxx/tagged_entry_value_table_initialize")); return; };
        let context = base as *mut u32;
        let entries = unsafe { (base + 0x100) as *mut u32 };
        let values = unsafe { (base + 0x200) as *mut u32 };
        unsafe {
            (base as *mut u8).write_bytes(0, 0x1000);
            context.add(ENTRY_COUNT_OFFSET).write(3);
            context.add(ENTRIES_OFFSET).write(entries as u32);
            context.add(VALUE_TABLE_OFFSET).write(values as u32);
            entries.add(ENTRY_WORDS).write(ENTRY_TAG);
            entries.add(ENTRY_WORDS + ENTRY_TABLE_INDEX_OFFSET).write(1);
            entries.add(ENTRY_WORDS + ENTRY_VALUE_OFFSET).write(0x1111_2222);
            entries.add(2 * ENTRY_WORDS).write(ENTRY_TAG);
            entries.add(2 * ENTRY_WORDS + ENTRY_TABLE_INDEX_OFFSET).write(3);
            entries.add(2 * ENTRY_WORDS + ENTRY_VALUE_OFFSET).write(0x3333_4444);
            values.write(0xaaaa_aaaa);
            values.add(1).write(0xbbbb_bbbb);
            values.add(2).write(0xcccc_cccc);

            tagged_entry_value_table_initialize(context);

            assert_eq!(values.read(), 0x1111_2222);
            assert_eq!(values.add(1).read(), 0xbbbb_bbbb);
            assert_eq!(values.add(2).read(), 0x3333_4444);
            assert_eq!(context.add(INITIALIZED_OFFSET).read(), 1);
        }
    }

    #[test]
    fn initialized_context_does_not_dereference_entry_or_value_pointers() {
        let Some(base) = *FIXTURE else { assert!(note_missing_u32_fixture("cxx/tagged_entry_value_table_initialize")); return; };
        let context = base as *mut u32;
        unsafe {
            (base as *mut u8).write_bytes(0, 0x1000);
            context.add(INITIALIZED_OFFSET).write(1);
            context.add(ENTRIES_OFFSET).write(u32::MAX);
            context.add(VALUE_TABLE_OFFSET).write(u32::MAX);
            tagged_entry_value_table_initialize(context);
            assert_eq!(context.add(INITIALIZED_OFFSET).read(), 1);
        }
    }
}
