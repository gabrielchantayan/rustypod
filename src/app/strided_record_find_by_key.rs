//! `strided_record_find_by_key` — original: `FUN_081df4a8` @ `0x081df4a8`
//! (40 bytes, `0x081df4a8..0x081df4d0`; the next independently linked
//! function begins at `0x081df4d0`). Raw ARM decoding verifies three plain
//! `bl` call sites and no predicated `bl` call sites.
//!
//! The container holds a begin pointer at +0x08 and its end sentinel at
//! +0x0c. It linearly scans 12-byte opaque records, comparing each record's
//! word at +0x08 with `key`, and returns either the matching record or end.
//! Ghidra incorrectly reports a void return and three unused parameters;
//! the raw ARM body returns the candidate pointer in r0 and reads only r0/r1.
//! No deliberate behavioral deviations.

#[inline(always)]
unsafe fn target_pointer(field: *const u8) -> *mut u8 {
    field.cast::<u32>().read() as usize as *mut u8
}

/// # Safety
///
/// `records` must be a target-layout container with readable u32 begin and
/// end pointers at +0x08 and +0x0c. Every 12-byte record in `[begin, end)`
/// must be readable through its word at +0x08.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn strided_record_find_by_key(records: *const u8, key: u32) -> *mut u8 {
    let end = target_pointer(records.add(0x0c));
    let mut candidate = target_pointer(records.add(0x08));

    while candidate != end {
        if candidate.add(0x08).cast::<u32>().read() == key {
            break;
        }
        candidate = candidate.add(12);
    }

    candidate
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::{LazyLock, Mutex};

    static LOCK: Mutex<()> = Mutex::new(());
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::STRIDED_RECORD_FIND_BY_KEY, 0x1000).map(|pointer| pointer as usize)
    });

    unsafe fn base() -> *mut u8 { SLAB.expect("fixture mapping was checked") as *mut u8 }

    unsafe fn write_target_pointer(field: *mut u8, value: *const u8) {
        field.cast::<u32>().write(value as usize as u32);
    }

    unsafe fn records_with_keys(keys: &[u32]) -> *mut u8 {
        let records = base();
        let begin = base().add(0x100);
        let end = begin.add(keys.len() * 12);
        records.write_bytes(0, 0x1000);
        write_target_pointer(records.add(0x08), begin);
        write_target_pointer(records.add(0x0c), end);
        for (index, key) in keys.iter().enumerate() {
            begin.add(index * 12 + 8).cast::<u32>().write(*key);
        }
        records
    }

    #[test]
    fn empty_range_returns_its_end_without_record_access() {
        let _guard = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        if SLAB.is_none() { assert!(note_missing_u32_fixture("app/strided_record_find_by_key")); return; }
        unsafe {
            let records = records_with_keys(&[]);
            assert_eq!(strided_record_find_by_key(records, 7), base().add(0x100));
        }
    }

    #[test]
    fn returns_matching_record_after_a_nonmatching_prefix() {
        let _guard = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        if SLAB.is_none() { assert!(note_missing_u32_fixture("app/strided_record_find_by_key")); return; }
        unsafe {
            let records = records_with_keys(&[4, 9, 15]);
            assert_eq!(strided_record_find_by_key(records, 9), base().add(0x10c));
        }
    }

    #[test]
    fn absent_key_returns_end_sentinel() {
        let _guard = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        if SLAB.is_none() { assert!(note_missing_u32_fixture("app/strided_record_find_by_key")); return; }
        unsafe {
            let records = records_with_keys(&[4, 9, 15]);
            assert_eq!(strided_record_find_by_key(records, 10), base().add(0x124));
        }
    }
}
