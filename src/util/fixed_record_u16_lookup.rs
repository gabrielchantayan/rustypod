//! Fixed-record halfword lookup — `FUN_080ffaac` @ `0x080ffaac`.
//!
//! Load address: `0x080ffaac`; true size: 56 bytes (`0x38`), ending in
//! `bx lr` at `0x080ffae0` before the literal-pool word at `0x080ffae4` and
//! the next function at `0x080ffae8`. Decoding the raw ARM words verifies no
//! direct calls in the body; independently scanning `osos.dec` finds four
//! inbound direct `bl` calls, all unconditional.
//!
//! The routine scans 205 fixed 20-byte records at `0x083e9d94`, returning the
//! little-endian halfword at `+0x0a` from the first record whose first word
//! equals `key`; it returns zero on a miss. The raw image has executable
//! bytes at that address, so the record table is runtime-overlaid state rather
//! than an offline-initializable Rust array. Deliberate deviation: host tests
//! supply a writable fixture through a private pointer seam; target builds read
//! the retail address directly, matching the original's absolute table reference.

const RECORD_TABLE_ADDRESS: usize = 0x083e_9d94;
const RECORD_COUNT: usize = 205;
const RECORD_WORD_STRIDE: usize = 5;

#[cfg(not(target_os = "none"))]
static mut HOST_RECORD_TABLE: *const u32 = core::ptr::null();

#[inline(always)]
unsafe fn record_table() -> *const u32 {
    #[cfg(target_os = "none")]
    {
        RECORD_TABLE_ADDRESS as *const u32
    }
    #[cfg(not(target_os = "none"))]
    {
        unsafe { core::ptr::addr_of!(HOST_RECORD_TABLE).read_volatile() }
    }
}

/// fixed_record_u16_lookup — original: `FUN_080ffaac` @ `0x080ffaac` (56 bytes).
///
/// Returns the `+0x0a` halfword from the first 20-byte record whose leading
/// word equals `key`, or zero if the 205-record table has no match.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn fixed_record_u16_lookup(key: u32) -> u16 {
    let table = unsafe { record_table() };
    for record_index in 0..RECORD_COUNT {
        let record = unsafe { table.add(record_index * RECORD_WORD_STRIDE) };
        if unsafe { record.read_volatile() } == key {
            return (unsafe { record.add(2).read_volatile() } >> 16) as u16;
        }
    }
    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab, FIXED_RECORD_U16_LOOKUP_TEST_LOCK};
    use core::ptr;

    const TABLE_PAGE: usize = 0x083e_9000;
    const TABLE_OFFSET: usize = RECORD_TABLE_ADDRESS - TABLE_PAGE;
    const TABLE_BYTES: usize = RECORD_COUNT * RECORD_WORD_STRIDE * core::mem::size_of::<u32>();

    fn table() -> Option<*mut u32> {
        let mapped = try_map_u32_slab(hints::FIXED_RECORD_U16_LOOKUP, TABLE_OFFSET + TABLE_BYTES)?;
        Some(unsafe { mapped.add(TABLE_OFFSET) as *mut u32 })
    }

    fn clear(table: *mut u32) {
        unsafe { ptr::write_bytes(table, 0, RECORD_COUNT * RECORD_WORD_STRIDE) };
    }

    struct Reset;

    impl Drop for Reset {
        fn drop(&mut self) {
            unsafe { ptr::addr_of_mut!(HOST_RECORD_TABLE).write(ptr::null()) };
        }
    }

    #[test]
    fn returns_first_matching_record_halfword() {
        let _guard = FIXED_RECORD_U16_LOOKUP_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(table) = table() else {
            assert!(note_missing_u32_fixture("fixed_record_u16_lookup"));
            return;
        };
        let _reset = Reset;
        unsafe { ptr::addr_of_mut!(HOST_RECORD_TABLE).write(table) };
        clear(table);
        unsafe {
            table.add(3 * RECORD_WORD_STRIDE).write(0x1234_5678);
            table.add(3 * RECORD_WORD_STRIDE + 2).write(0xbeef_0000);
            table.add(17 * RECORD_WORD_STRIDE).write(0x1234_5678);
            table.add(17 * RECORD_WORD_STRIDE + 2).write(0xcafe_0000);
            assert_eq!(fixed_record_u16_lookup(0x1234_5678), 0xbeef);
        }
    }

    #[test]
    fn examines_final_record_and_returns_zero_on_miss() {
        let _guard = FIXED_RECORD_U16_LOOKUP_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(table) = table() else {
            assert!(note_missing_u32_fixture("fixed_record_u16_lookup"));
            return;
        };
        let _reset = Reset;
        unsafe { ptr::addr_of_mut!(HOST_RECORD_TABLE).write(table) };
        clear(table);
        unsafe {
            table.add((RECORD_COUNT - 1) * RECORD_WORD_STRIDE).write(0xfeed_face);
            table.add((RECORD_COUNT - 1) * RECORD_WORD_STRIDE + 2).write(0x0bad_0000);
            assert_eq!(fixed_record_u16_lookup(0xfeed_face), 0x0bad);
            assert_eq!(fixed_record_u16_lookup(0xdead_beef), 0);
        }
    }
}
