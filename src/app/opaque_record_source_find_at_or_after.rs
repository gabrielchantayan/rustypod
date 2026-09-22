//! `opaque_record_source_find_at_or_after` — original: `FUN_0828443c` @
//! **0x0828443c** (**120 bytes**, `0x0828443c..0x082844b0`; the next separately
//! linked function starts at `0x082844b4`).
//!
//! Raw ARM first rejects a null provider, then calls the already ported
//! [`opaque_record_source_item_count`]. For each 80-byte record in the table at
//! `source + 0x04`, it returns the first index whose inclusive endpoint word at
//! `+0x14` is at least `position` and whose word at `+0x04` is nonzero. It
//! otherwise returns `-1`.
//!
//! Complete B/BL-immediate decoding finds three direct inbound calls, all plain
//! unconditional `bl` at `0x081a1b7c`, `0x081a1c00`, and `0x081a1f88`; there
//! are no predicated `bl` calls. Its body has one plain `bl`, to
//! `opaque_record_source_item_count`, and no predicated `bl` calls.
//!
//! Deliberate deviation: none. The Rust loop expresses the ARM signed
//! count-bound and preserves its no-table-null-check contract once the count is
//! positive.

use crate::app::opaque_record_source_item_count::{
    opaque_record_source_item_count, OpaqueRecordSource,
};

const RECORD_BYTES: usize = 0x50;
const RECORD_AVAILABLE_WORD_OFFSET: usize = 0x04;
const RECORD_END_POSITION_OFFSET: usize = 0x14;

/// Finds the first available record whose inclusive endpoint reaches `position`.
///
/// Original: `FUN_0828443c` @ `0x0828443c` (120 bytes; three inbound plain
/// unconditional `bl` calls, no predicated calls, binary-scanned).
///
/// # Safety
///
/// `source` must identify readable, aligned [`OpaqueRecordSource`] storage. If
/// its provider is nonzero and its item count is positive, its target-width
/// word at `+0x04` must identify aligned readable records through the selected
/// count, each 80 bytes long. This preserves retailOS's lack of a table-null
/// check in that path.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.opaque_record_source_find_at_or_after")]
#[inline(never)]
pub unsafe extern "C" fn opaque_record_source_find_at_or_after(
    source: *const OpaqueRecordSource,
    position: u32,
) -> i32 {
    if (*source).provider == 0 {
        return -1;
    }

    let count = opaque_record_source_item_count(source);
    if count < 0 {
        return -1;
    }

    let record_table = (*source).opaque_04_to_14[0] as usize as *const u8;
    for index in 0..count {
        let record = record_table.add(index as usize * RECORD_BYTES);
        if record.add(RECORD_END_POSITION_OFFSET).cast::<u32>().read() >= position
            && record.add(RECORD_AVAILABLE_WORD_OFFSET).cast::<u32>().read() != 0
        {
            return index;
        }
    }

    -1
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::app::opaque_record_source_item_count::{
        test_support, RecordSourceItemCountOps, DEFAULT_RECORD_SOURCE_ITEM_COUNT_OPS,
        RECORD_SOURCE_ITEM_COUNT_OPS,
    };
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr::addr_of_mut;
    use std::sync::{LazyLock, MutexGuard};

    const TABLE_BYTES: usize = RECORD_BYTES * 4;
    static RECORD_TABLE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::OPAQUE_RECORD_SOURCE_FIND_AT_OR_AFTER, TABLE_BYTES)
            .map(|pointer| pointer as usize)
    });
    static mut ITEM_COUNT: i32 = 0;

    unsafe extern "C" fn item_count(_provider: *mut u8, _selector: i32) -> i32 {
        ITEM_COUNT
    }

    fn install_item_count(count: i32) -> MutexGuard<'static, ()> {
        let guard = test_support::RECORD_SOURCE_ITEM_COUNT_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        unsafe {
            addr_of_mut!(ITEM_COUNT).write(count);
            addr_of_mut!(RECORD_SOURCE_ITEM_COUNT_OPS).write(RecordSourceItemCountOps { item_count });
        }
        guard
    }

    fn restore_default(guard: MutexGuard<'static, ()>) {
        unsafe {
            addr_of_mut!(RECORD_SOURCE_ITEM_COUNT_OPS).write(DEFAULT_RECORD_SOURCE_ITEM_COUNT_OPS);
        }
        drop(guard);
    }

    fn source(record_table: u32) -> OpaqueRecordSource {
        OpaqueRecordSource {
            provider: 1,
            opaque_04_to_14: [record_table, 0, 0, 0, 0],
            opaque_18: 0,
            opaque_19: 0,
            selector: 0,
        }
    }

    #[test]
    fn null_provider_returns_negative_one_without_count_dispatch() {
        let source = OpaqueRecordSource {
            provider: 0,
            opaque_04_to_14: [0; 5],
            opaque_18: 0,
            opaque_19: 0,
            selector: 0,
        };

        assert_eq!(unsafe { opaque_record_source_find_at_or_after(&source, 0) }, -1);
    }

    #[test]
    fn finds_first_available_record_at_or_after_position() {
        let guard = install_item_count(4);
        let Some(table) = *RECORD_TABLE else {
            restore_default(guard);
            assert!(note_missing_u32_fixture("app::opaque_record_source_find_at_or_after"));
            return;
        };
        unsafe {
            core::ptr::write_bytes(table as *mut u8, 0, TABLE_BYTES);
            let table = table as *mut u8;
            table.add(RECORD_END_POSITION_OFFSET).cast::<u32>().write(9);
            table.add(RECORD_BYTES + RECORD_AVAILABLE_WORD_OFFSET).cast::<u32>().write(1);
            table.add(RECORD_BYTES + RECORD_END_POSITION_OFFSET).cast::<u32>().write(9);
            table.add(2 * RECORD_BYTES + RECORD_AVAILABLE_WORD_OFFSET).cast::<u32>().write(1);
            table.add(2 * RECORD_BYTES + RECORD_END_POSITION_OFFSET).cast::<u32>().write(10);

            assert_eq!(opaque_record_source_find_at_or_after(&source(table as usize as u32), 10), 2);
            assert_eq!(opaque_record_source_find_at_or_after(&source(table as usize as u32), 11), -1);
        }
        restore_default(guard);
    }

    #[test]
    fn rejects_negative_count_and_absent_qualifying_record() {
        let guard = install_item_count(-1);
        let source = source(0);
        assert_eq!(unsafe { opaque_record_source_find_at_or_after(&source, 0) }, -1);
        restore_default(guard);
    }
}
