//! `current_record_status` — original: `FUN_0829e1d8` @ `0x0829e1d8`.
//! True extent: 36 bytes, `0x0829e1d8..0x0829e1fc`; the next function
//! independently loads a constant and returns at `0x0829e1fc`.
//! Whole-image raw ARM decoding verifies two plain incoming BL sites
//! (`0x081af5d8`, `0x081af630`), zero predicated incoming BL sites, and
//! zero outgoing BL calls of either kind.
//!
//! Return zero for the cursor's `-1` index; otherwise return the unsigned
//! status byte at `records + index * 20 + 8`. The caller `FUN_081af564`
//! compares this byte with 1 before accessing the selected record's handle.
//! Other status meanings are unproven. Address arithmetic wraps at 32 bits;
//! no bounds or NULL checks are added. No deliberate behavioral deviations.

use crate::app::current_record_handle::CurrentRecordCursor;

/// Returns the selected record's status byte, or zero for the absent sentinel.
///
/// # Safety
/// `cursor` must be readable and aligned. Unless its index is `-1`, the
/// target-width wrapping address `records + index * 20 + 8` must be readable.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn current_record_status(cursor: *const CurrentRecordCursor) -> u32 {
    let index = (*cursor).current_index;
    if index == -1 {
        return 0;
    }
    let record = (*cursor).records.wrapping_add((index as u32).wrapping_mul(20));
    (record.wrapping_add(8) as usize as *const u8).read() as u32
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::{LazyLock, Mutex};

    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::CURRENT_RECORD_STATUS, 0x1000).map(|p| p as usize)
    });
    static LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn absent_index_does_not_dereference_records() {
        for records in [0, u32::MAX] {
            let cursor = CurrentRecordCursor { opaque_00: 0, records, current_index: -1 };
            assert_eq!(unsafe { current_record_status(&cursor) }, 0);
        }
    }

    #[test]
    fn byte_width_stride_and_wrapping_indices_match_reference() {
        let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let Some(base) = *FIXTURE else {
            assert!(note_missing_u32_fixture("app::current_record_status"));
            return;
        };
        let bytes = base as *mut u8;
        unsafe {
            core::ptr::write_bytes(bytes, 0xa5, 0x1000);
            // Exercise every unsigned byte and distinguish neighboring bytes,
            // record stride, negative non-sentinel indices, and overflow.
            for value in 0..=255u32 {
                bytes.add(48).write(value as u8);
                for index in [0i32, 2, -2, i32::MAX, i32::MIN] {
                    let records = (base as u32).wrapping_add(40)
                        .wrapping_sub((index as u32).wrapping_mul(20));
                    let cursor = CurrentRecordCursor { opaque_00: 0xffff_ffff, records, current_index: index };
                    let expected_address = records.wrapping_add((index as u32)
                        .wrapping_add((index as u32).wrapping_shl(2)).wrapping_shl(2)).wrapping_add(8);
                    assert_eq!(current_record_status(&cursor), (expected_address as usize as *const u8).read() as u32);
                    assert_eq!(current_record_status(&cursor), value);
                }
            }
            bytes.add(8).write(0x31);
            bytes.add(28).write(0xe2);
            let mut cursor = CurrentRecordCursor { opaque_00: 0, records: base as u32, current_index: 0 };
            assert_eq!(current_record_status(&cursor), 0x31);
            cursor.current_index = 1;
            assert_eq!(current_record_status(&cursor), 0xe2);
        }
    }
}
