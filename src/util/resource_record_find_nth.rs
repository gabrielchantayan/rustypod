//! Resource-record occurrence lookup @ 0x0805af24.
//!
//! The retail wrapper rejects a NULL table slot and occurrence zero. Otherwise it
//! asks the stock record-table walker for that occurrence of `record_tag`, returns
//! the matched record's byte offset from `*table_slot`, and optionally converts
//! the big-endian word at record `+0x08` into a host u32 written as little-endian
//! bytes. The unported walker is reached by a literal veneer on ARM and a test
//! seam on hosts.

use core::ptr;

use crate::util::le_read::read_u32_le;
use crate::util::u32_le_store_last_byte::store_u32_le_last_byte;

/// ABI of the stock record-table walker at `0x0809a844`.
type RetailRecordFindNth = unsafe extern "C" fn(
    table_slot: *mut *mut u8,
    directory_offset: u32,
    record_tag: u32,
    occurrence: u32,
    secondary_tag: u32,
    entry_index_out: *mut u32,
    matched_rank_out: *mut u16,
) -> *mut u8;

#[cfg(target_arch = "arm")]
extern "C" {
    fn retail_record_find_nth(
        table_slot: *mut *mut u8,
        directory_offset: u32,
        record_tag: u32,
        occurrence: u32,
        secondary_tag: u32,
        entry_index_out: *mut u32,
        matched_rank_out: *mut u16,
    ) -> *mut u8;
}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_retail_record_find_nth(
    _table_slot: *mut *mut u8,
    _directory_offset: u32,
    _record_tag: u32,
    _occurrence: u32,
    _secondary_tag: u32,
    _entry_index_out: *mut u32,
    _matched_rank_out: *mut u16,
) -> *mut u8 {
    ptr::null_mut()
}

#[cfg(not(target_arch = "arm"))]
static mut RETAIL_RECORD_FIND_NTH: RetailRecordFindNth = missing_retail_record_find_nth;

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
unsafe fn retail_record_find_nth(
    table_slot: *mut *mut u8,
    directory_offset: u32,
    record_tag: u32,
    occurrence: u32,
    secondary_tag: u32,
    entry_index_out: *mut u32,
    matched_rank_out: *mut u16,
) -> *mut u8 {
    ptr::read_volatile(ptr::addr_of!(RETAIL_RECORD_FIND_NTH))(
        table_slot,
        directory_offset,
        record_tag,
        occurrence,
        secondary_tag,
        entry_index_out,
        matched_rank_out,
    )
}

// This body moves into the payload, so its stock PC-relative `bl` can no longer
// reach the retail walker. The veneer preserves the seven-argument AAPCS call.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl retail_record_find_nth
    .type retail_record_find_nth, %function
retail_record_find_nth:
    ldr     pc, [pc, #-4]
    .word   0x0809a844
    .size retail_record_find_nth, . - retail_record_find_nth
"#
);

/// resource_record_find_nth — original: `FUN_0805af24` @ `0x0805af24`
/// (180 bytes; seven verified inbound unconditional `bl` call sites, no
/// predicated `bl` forms).
///
/// Finds occurrence `occurrence` of `record_tag` through the stock table walker.
/// A NULL `table_slot` or zero occurrence returns zero without dispatching. A
/// successful lookup returns `record - *table_slot` as a signed byte offset. If
/// `out_record_value` is non-NULL, it receives the record's `+0x08` big-endian
/// word as a little-endian stored u32. The stock body makes six direct calls:
/// the walker, four unaligned little-endian reads, and the word store.
///
/// Deliberate deviations: the four identical byte loads are represented by one
/// `read_u32_le` plus `swap_bytes`; records are ordinary mapped data, so this
/// preserves their value while avoiding three redundant non-volatile reads.
///
/// # Safety
/// When `table_slot` and `occurrence` are nonzero, `table_slot` must point to a
/// readable table-base pointer. The stock walker defines all record traversal;
/// a successful result must belong to that table. A non-NULL `out_record_value`
/// must be writable for four bytes.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(
    target_os = "none",
    link_section = ".text.resource_record_find_nth"
)]
#[inline(never)]
pub unsafe extern "C" fn resource_record_find_nth(
    table_slot: *mut *mut u8,
    directory_offset: u32,
    record_tag: u32,
    occurrence: u32,
    out_record_value: *mut u8,
) -> i32 {
    if table_slot.is_null() || occurrence == 0 {
        return 0;
    }

    let record = retail_record_find_nth(
        table_slot,
        directory_offset,
        record_tag,
        occurrence,
        0,
        ptr::null_mut(),
        1usize as *mut u16,
    );
    if record.is_null() {
        return 0;
    }

    let offset = (record as usize as u32).wrapping_sub(table_slot.read() as usize as u32) as i32;
    if !out_record_value.is_null() {
        let record_value = read_u32_le(record.add(8)).swap_bytes();
        store_u32_le_last_byte(out_record_value, record_value);
    }
    offset
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut FIND_CALLS: u32 = 0;
    static mut FOUND_RECORD: *mut u8 = ptr::null_mut();
    static mut SEEN_ARGS: (usize, u32, u32, u32, u32, usize, usize) = (0, 0, 0, 0, 0, 0, 0);

    unsafe extern "C" fn recording_retail_record_find_nth(
        table_slot: *mut *mut u8,
        directory_offset: u32,
        record_tag: u32,
        occurrence: u32,
        secondary_tag: u32,
        entry_index_out: *mut u32,
        matched_rank_out: *mut u16,
    ) -> *mut u8 {
        FIND_CALLS += 1;
        SEEN_ARGS = (
            table_slot as usize,
            directory_offset,
            record_tag,
            occurrence,
            secondary_tag,
            entry_index_out as usize,
            matched_rank_out as usize,
        );
        FOUND_RECORD
    }

    struct RestoreSeam(RetailRecordFindNth);

    impl Drop for RestoreSeam {
        fn drop(&mut self) {
            unsafe { ptr::addr_of_mut!(RETAIL_RECORD_FIND_NTH).write(self.0) };
        }
    }

    unsafe fn install_recording_seam(record: *mut u8) -> RestoreSeam {
        let previous = ptr::read_volatile(ptr::addr_of!(RETAIL_RECORD_FIND_NTH));
        ptr::addr_of_mut!(RETAIL_RECORD_FIND_NTH).write(recording_retail_record_find_nth);
        FIND_CALLS = 0;
        FOUND_RECORD = record;
        SEEN_ARGS = (0, 0, 0, 0, 0, 0, 0);
        RestoreSeam(previous)
    }

    #[test]
    fn null_table_or_zero_occurrence_skips_the_walker() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _restore = unsafe { install_recording_seam(ptr::null_mut()) };
        let mut table_base = ptr::null_mut();

        assert_eq!(unsafe { resource_record_find_nth(ptr::null_mut(), 1, 2, 1, ptr::null_mut()) }, 0);
        assert_eq!(unsafe { resource_record_find_nth(&mut table_base, 1, 2, 0, ptr::null_mut()) }, 0);
        assert_eq!(unsafe { FIND_CALLS }, 0);
    }

    #[test]
    fn found_record_returns_offset_converts_word_and_forwards_fixed_arguments() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut table = [0u8; 96];
        let record = unsafe { table.as_mut_ptr().add(0x40) };
        unsafe { record.add(8).copy_from_nonoverlapping([0x12, 0x34, 0x56, 0x78].as_ptr(), 4) };
        let mut table_base = table.as_mut_ptr();
        let _restore = unsafe { install_recording_seam(record) };
        let mut out = [0xa5u8; 4];

        let offset = unsafe {
            resource_record_find_nth(&mut table_base, 0x20, 0x5245_5343, 3, out.as_mut_ptr())
        };

        assert_eq!(offset, 0x40);
        assert_eq!(out, [0x78, 0x56, 0x34, 0x12]);
        assert_eq!(unsafe { FIND_CALLS }, 1);
        assert_eq!(unsafe { SEEN_ARGS }, (
            &mut table_base as *mut *mut u8 as usize,
            0x20,
            0x5245_5343,
            3,
            0,
            0,
            1,
        ));
    }

    #[test]
    fn missing_record_leaves_optional_output_untouched() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut table_base = ptr::null_mut();
        let _restore = unsafe { install_recording_seam(ptr::null_mut()) };
        let mut out = [0xa5u8; 4];

        assert_eq!(unsafe { resource_record_find_nth(&mut table_base, 4, 5, 6, out.as_mut_ptr()) }, 0);
        assert_eq!(out, [0xa5; 4]);
        assert_eq!(unsafe { FIND_CALLS }, 1);
    }
}
