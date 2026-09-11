//! `object_masked_word_refresh` — original: `FUN_082c43d0` @ `0x082c43d0`
//! (32 bytes; 10 verified direct `bl` call sites, all unconditional).
//!
//! Raw ARM extent is exactly 32 bytes (`0x082c43d0..0x082c43f0`): the next
//! separately linked function begins with `subs r2, r0, #0` at `0x082c43f0`.
//! The ten calls are all plain `bl` instructions (`0x0838f9c8` through
//! `0x0838fb60`); none is predicated. Decoding every ARM B/BL word in
//! `osos.dec` verified this count.
//!
//! # Algorithm
//!
//! A non-NULL object is a target-width word layout. The function reads word
//! zero as its SQLite connection pointer and word 29 (`+0x74`) as a result
//! code, passes both to the direct [`crate::sqlite::api_exit::sqlite_api_exit`]
//! port, then overwrites word 29 with its result. NULL returns without reading
//! or calling.
//!
//! Deliberate deviation: host objects retain the firmware's `u32` word layout
//! rather than using pointer-width Rust fields, so word 29 stays `+0x74` on
//! both 32-bit target and 64-bit host.

use crate::sqlite::api_exit::sqlite_api_exit;
use core::ptr;

const OBJECT_MASKED_WORD: usize = 29;

/// Refreshes word 29 (`+0x74`) of `object` through its SQLite connection in
/// word zero.
///
/// # Safety
///
/// If non-NULL, `object` must reference at least 30 writable target-width
/// words. Its first word must hold a SQLite connection pointer valid for
/// [`sqlite_api_exit`].
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn object_masked_word_refresh(object: *mut u32) {
    if object.is_null() {
        return;
    }

    let db = unsafe { ptr::read(object) as usize as *mut u8 };
    let result_code = unsafe { ptr::read(object.add(OBJECT_MASKED_WORD)) };
    let refreshed = unsafe { sqlite_api_exit(db, result_code as i32) as u32 };
    unsafe { ptr::write(object.add(OBJECT_MASKED_WORD), refreshed) };
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::{object_masked_word_refresh, OBJECT_MASKED_WORD};
    use crate::sqlite::api_exit::DB_ERR_MASK_OFFSET;
    use crate::sqlite::error::{DB_ERR_CODE_OFFSET, DB_P_ERR_OFFSET};
    use crate::sqlite::mem::MALLOC_FAILED_OFFSET;
    use crate::sqlite::value_new::{MEM_NULL, SQLITE_NULL};
    use crate::sqlite::vdbe::Mem;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr;
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    static FIXTURE_LOCK: Mutex<()> = Mutex::new(());
    static MAPPED_OBJECT: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::OBJECT_MASKED_WORD_REFRESH, 0x200).map(|slab| slab as usize)
    });

    fn mapped_object() -> Option<*mut u32> {
        Some((*MAPPED_OBJECT)? as *mut u32)
    }

    unsafe fn error_code_slot(db: *mut u8) -> *mut i32 {
        db.add(DB_ERR_CODE_OFFSET).cast()
    }

    unsafe fn error_value_slot(db: *mut u8) -> *mut *mut u8 {
        db.add(DB_P_ERR_OFFSET).cast()
    }

    fn null_mem(db: *mut u8) -> Mem {
        Mem {
            u: 0,
            r: 0.0,
            db,
            z: ptr::null_mut(),
            n: 0,
            flags: 0,
            value_type: 0,
            enc: 0,
            x_del: ptr::null_mut(),
            z_malloc: ptr::null_mut(),
        }
    }

    #[test]
    fn null_object_returns_without_reading_its_words() {
        let _lock = FIXTURE_LOCK.lock();

        unsafe { object_masked_word_refresh(ptr::null_mut()) };
    }

    #[test]
    fn forwards_the_raw_connection_and_masks_word_29() {
        let _lock = FIXTURE_LOCK.lock();
        let Some(object) = mapped_object() else {
            assert!(note_missing_u32_fixture("util::object_masked_word_refresh"));
            return;
        };
        let db = unsafe { object.cast::<u8>().add(0x100) };
        unsafe {
            ptr::write_bytes(object.cast::<u8>(), 0, 0x200);
            ptr::write(object, db as usize as u32);
            ptr::write(object.add(OBJECT_MASKED_WORD), 0x1357_9bdf);
            (db.add(DB_ERR_MASK_OFFSET) as *mut i32).write(0x00ff_00ff);
            db.add(MALLOC_FAILED_OFFSET).write(0);

            object_masked_word_refresh(object);
        }

        assert_eq!(
            unsafe { ptr::read(object.add(OBJECT_MASKED_WORD)) },
            0x0057_00df
        );
    }

    #[test]
    fn allocation_failure_replaces_word_29_with_masked_nomem() {
        let _lock = FIXTURE_LOCK.lock();
        let Some(object) = mapped_object() else {
            assert!(note_missing_u32_fixture("util::object_masked_word_refresh"));
            return;
        };
        let db = unsafe { object.cast::<u8>().add(0x100) };
        let mut error_value = null_mem(db);
        unsafe {
            ptr::write_bytes(object.cast::<u8>(), 0, 0x200);
            ptr::write(object, db as usize as u32);
            ptr::write(object.add(OBJECT_MASKED_WORD), u32::MAX);
            (db.add(DB_ERR_MASK_OFFSET) as *mut i32).write(3);
            db.add(MALLOC_FAILED_OFFSET).write(1);
            error_code_slot(db).write(-123);
            error_value_slot(db).write((&mut error_value as *mut Mem).cast());

            object_masked_word_refresh(object);
        }

        assert_eq!(unsafe { ptr::read(object.add(OBJECT_MASKED_WORD)) }, 3);
        assert_eq!(unsafe { db.add(MALLOC_FAILED_OFFSET).read() }, 0);
        assert_eq!(unsafe { error_code_slot(db).read() }, 7);
        assert_eq!(error_value.flags, MEM_NULL);
        assert_eq!(error_value.value_type, SQLITE_NULL);
    }
}
