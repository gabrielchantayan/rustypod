//! `opaque_record_source_copy_item` — original: `FUN_08284390` @ `0x08284390`
//! (**100 bytes**, `0x08284390..0x082843f0`; the next separately linked function
//! starts at `0x082843f4`).
//!
//! Raw ARM calls `FUN_081c1ee0` through the already ported
//! [`opaque_record_source_item_count`], then accepts only an index strictly below
//! that unsigned result and a non-null entry-table word at `source + 0x04`. It
//! copies the selected 80-byte record to the caller buffer through the IRAM
//! memcpy veneer and succeeds only if copied record word 1 is non-null.
//!
//! Decoding every ARM B/BL immediate in `osos.dec` finds **six direct plain
//! unconditional `bl` call sites**, at `0x081a1b98`, `0x081a1bf4`,
//! `0x081a1cfc`, `0x081a1d88`, `0x081a1e08`, and `0x081a1ff4`. There are no
//! predicated calls or direct tail branches.
//!
//! Deliberate deviation: the provider's item-count helper remains unported.
//! Target builds reach its fixed retailOS address through a shared direct-call
//! helper; host tests install that module's volatile dispatch seam.

use crate::app::opaque_record_source_item_count::{
    record_source_item_count_unchecked, OpaqueRecordSource,
};
use crate::libc::iram_veneers::iram_memcpy_veneer;

const RECORD_BYTES: usize = 0x50;
const REQUIRED_RECORD_WORD_OFFSET: usize = 0x04;

/// Copies a valid indexed record from `source` into `output`.
///
/// Original: `FUN_08284390` @ `0x08284390` (100 bytes; six plain unconditional
/// direct `bl` call sites and no predicated calls, binary-scanned). It has no
/// source or output-pointer guard. The item count result is compared as an
/// unsigned 32-bit value, preserving every bit of the helper's result on ARM.
///
/// # Safety
///
/// `source` must identify readable, aligned [`OpaqueRecordSource`] storage.
/// Its target-width word at `+0x04`, when nonzero, must identify at least
/// `index * 0x50 + 0x50` readable bytes. `output` must identify aligned,
/// writable 80-byte storage. Neither pointer receives additional validation.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.opaque_record_source_copy_item")]
#[inline(never)]
pub unsafe extern "C" fn opaque_record_source_copy_item(
    source: *const OpaqueRecordSource,
    index: usize,
    output: *mut u8,
) -> i32 {
    let provider = (*source).provider;
    let selector = (*source).selector as i32;
    if (record_source_item_count_unchecked(provider, selector) as u32) <= index as u32 {
        return -1;
    }

    let records = (*source).opaque_04_to_14[0];
    if records == 0 {
        return -1;
    }

    let record_offset = (index as u32).wrapping_mul(RECORD_BYTES as u32) as usize;
    iram_memcpy_veneer(
        output,
        (records as usize as *const u8).add(record_offset),
        RECORD_BYTES,
    );

    if output.add(REQUIRED_RECORD_WORD_OFFSET).cast::<u32>().read() != 0 {
        0
    } else {
        -1
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::app::opaque_record_source_item_count::{
        test_support::RECORD_SOURCE_ITEM_COUNT_TEST_LOCK, RecordSourceItemCountOps,
        DEFAULT_RECORD_SOURCE_ITEM_COUNT_OPS, RECORD_SOURCE_ITEM_COUNT_OPS,
    };
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr::{addr_of_mut, copy_nonoverlapping};
    use std::sync::{LazyLock, MutexGuard};

    const FIXTURE_LEN: usize = 0x1000;
    static RECORDS_FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::OPAQUE_RECORD_SOURCE_COPY_ITEM, FIXTURE_LEN)
            .map(|pointer| pointer as usize)
    });
    static mut ITEM_COUNT_RESULT: i32 = 0;

    unsafe extern "C" fn record_item_count(_provider: *mut u8, _selector: i32) -> i32 {
        ITEM_COUNT_RESULT
    }

    fn install_item_count(result: i32) -> MutexGuard<'static, ()> {
        let guard = RECORD_SOURCE_ITEM_COUNT_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        unsafe {
            addr_of_mut!(ITEM_COUNT_RESULT).write(result);
            addr_of_mut!(RECORD_SOURCE_ITEM_COUNT_OPS).write(RecordSourceItemCountOps {
                item_count: record_item_count,
            });
        }
        guard
    }

    fn restore_default(guard: MutexGuard<'static, ()>) {
        unsafe {
            addr_of_mut!(RECORD_SOURCE_ITEM_COUNT_OPS).write(DEFAULT_RECORD_SOURCE_ITEM_COUNT_OPS);
        }
        drop(guard);
    }

    fn source(records: u32) -> OpaqueRecordSource {
        OpaqueRecordSource {
            provider: 1,
            opaque_04_to_14: [records, 0, 0, 0, 0],
            opaque_18: 0,
            opaque_19: 0,
            selector: -1,
        }
    }

    #[test]
    fn count_bound_rejects_before_reading_records_or_output() {
        let guard = install_item_count(2);
        let source = source(1);

        assert_eq!(
            unsafe { opaque_record_source_copy_item(&source, 2, core::ptr::dangling_mut()) },
            -1
        );
        restore_default(guard);
    }

    #[test]
    fn null_record_table_leaves_output_unchanged() {
        let guard = install_item_count(1);
        let source = source(0);
        let mut output = [0xa5_u8; RECORD_BYTES];

        assert_eq!(unsafe { opaque_record_source_copy_item(&source, 0, output.as_mut_ptr()) }, -1);
        assert_eq!(output, [0xa5; RECORD_BYTES]);
        restore_default(guard);
    }

    #[test]
    fn copies_full_record_and_requires_its_second_word() {
        let guard = install_item_count(2);
        let Some(records) = *RECORDS_FIXTURE else {
            restore_default(guard);
            assert!(note_missing_u32_fixture("app::opaque_record_source_copy_item"));
            return;
        };
        let records = records as *mut u8;
        let mut first = [0_u8; RECORD_BYTES];
        let mut second = [0_u8; RECORD_BYTES];
        for (offset, byte) in second.iter_mut().enumerate() {
            *byte = offset as u8 ^ 0x5a;
        }
        second[4..8].copy_from_slice(&0x1122_3344_u32.to_le_bytes());
        unsafe {
            copy_nonoverlapping(first.as_ptr(), records, RECORD_BYTES);
            copy_nonoverlapping(second.as_ptr(), records.add(RECORD_BYTES), RECORD_BYTES);
        }
        let source = source(records as usize as u32);
        let mut output = [0xcc_u8; RECORD_BYTES];

        assert_eq!(unsafe { opaque_record_source_copy_item(&source, 1, output.as_mut_ptr()) }, 0);
        assert_eq!(output, second);

        assert_eq!(unsafe { opaque_record_source_copy_item(&source, 0, output.as_mut_ptr()) }, -1);
        assert_eq!(output, first);
        restore_default(guard);
    }
}
