//! Fixed-table four-word record registration.
//!
//! Original: `FUN_0806430c` @ `0x0806430c`: 96 bytes to the next real
//! function at 0x0806436c (92 code bytes plus literal 0x08ad1458).
//! Verified calls: zero outgoing plain/predicated BL; two incoming plain BL,
//! zero incoming predicated BL. Reject a zero key with -50, scan 50 sixteen-
//! byte records for the first zero key, store all four input words, optionally
//! report its index, and return zero. The second zero-key check's -108 path
//! is unreachable: exhaustion instead stores at address zero with index 50.
//! No target behavioral deviations. ARM stores use assembly to preserve that
//! address-zero behavior without Rust null-pointer UB. Host exhaustion panics
//! rather than writing address zero; the host table is explicitly supplied.

use core::ptr::{read_volatile, write_volatile};

#[cfg(not(target_os = "none"))]
pub static mut WORD_RECORD_TABLE: *mut u32 = core::ptr::null_mut();

#[inline(always)]
unsafe fn vacant_record(table: *mut u32) -> (*mut u32, u32) {
    for index in 0..50 {
        let record = table.add(index * 4);
        if read_volatile(record) == 0 { return (record, index as u32); }
    }
    (core::ptr::null_mut(), 50)
}

#[inline(always)]
unsafe fn register_in_table(table: *mut u32, key: u32, value: u32, extra: u32,
    flags: u32, index_out: *mut u32) -> i32 {
    if key == 0 { return -50; }
    let (record, index) = vacant_record(table);
    #[cfg(target_os = "none")]
    core::arch::asm!(
        "stmia {record}, {{r0, r1, r2, r3}}",
        record = in(reg) record,
        in("r0") key, in("r1") value, in("r2") extra, in("r3") flags,
        options(nostack, preserves_flags),
    );
    #[cfg(not(target_os = "none"))]
    {
        assert!(!record.is_null(), "retail full-table path writes address zero");
        write_volatile(record, key);
        write_volatile(record.add(1), value);
        write_volatile(record.add(2), extra);
        write_volatile(record.add(3), flags);
    }
    if !index_out.is_null() { write_volatile(index_out, index); }
    0
}

/// Register a nonzero key and three opaque words in the firmware table.
///
/// # Safety
/// The table contains 50 readable/writable aligned four-word records and is
/// externally serialized. A nonnull output must be writable, including when
/// it aliases the table. Host callers must install `WORD_RECORD_TABLE` first.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn word_record_register(key: u32, value: u32, extra: u32,
    flags: u32, index_out: *mut u32) -> i32 {
    #[cfg(target_os = "none")]
    let table = 0x08ad_1458 as *mut u32;
    #[cfg(not(target_os = "none"))]
    let table = read_volatile(core::ptr::addr_of!(WORD_RECORD_TABLE));
    register_in_table(table, key, value, extra, flags, index_out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_key_does_not_access_table_or_output() {
        assert_eq!(unsafe { register_in_table(core::ptr::null_mut(), 0, 1, 2, 3,
            core::ptr::null_mut()) }, -50);
    }

    #[test]
    fn first_free_record_and_last_record_preserve_neighbors() {
        for free in 0..50 {
            let mut table = [[0xdead_beefu32, 9, 8, 7]; 50];
            table[free][0] = 0;
            if free < 49 { table[free + 1][0] = 0; }
            let mut expected = table;
            expected[free] = [u32::MAX, 0, 0x8000_0000, 0x1234_5678];
            let mut index = u32::MAX;
            assert_eq!(unsafe { register_in_table(table.as_mut_ptr().cast(), u32::MAX,
                0, 0x8000_0000, 0x1234_5678, &mut index) }, 0);
            assert_eq!(index, free as u32);
            assert_eq!(table, expected);
        }
    }

    #[test]
    fn optional_output_and_alias_are_written_after_record() {
        let mut table = [[0u32; 4]; 50];
        let base = table.as_mut_ptr().cast::<u32>();
        assert_eq!(unsafe { register_in_table(base, 1, 2, 3, 4, core::ptr::null_mut()) }, 0);
        assert_eq!(unsafe { register_in_table(base, 5, 6, 7, 8, base.add(5)) }, 0);
        assert_eq!(table[0], [1, 2, 3, 4]);
        assert_eq!(table[1], [5, 1, 7, 8]);
    }

    #[test]
    fn exhaustion_selects_address_zero_and_index_fifty() {
        let mut table = [[1u32; 4]; 51];
        table[50][0] = 0;
        let (record, index) = unsafe { vacant_record(table.as_mut_ptr().cast()) };
        assert!(record.is_null());
        assert_eq!(index, 50);
        assert_eq!(table[50], [0, 1, 1, 1]);
    }
}
