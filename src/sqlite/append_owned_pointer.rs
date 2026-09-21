//! SQLite owned-pointer-array append helper.
//!
//! `append_owned_pointer` — original: `FUN_082b2c94` @ **0x082b2c94**
//! (124 bytes, `0x082b2c94..0x082b2d10`; 3 outbound plain `bl` instructions,
//! no predicated `bl`). Raw ARM reads the target object's signed count at
//! +0x44 and its target-width array pointer at +0x48, grows the array through
//! `db_realloc`, then appends the owned pointer and a trailing NULL sentinel.
//! If growth fails, it releases every existing entry, the new entry, and the
//! old array through `tracked_free`, then clears the count and array pointer.
//! Deliberate deviation: target pointer words are read and written explicitly
//! rather than represented as host pointer fields, preserving the 32-bit
//! firmware layout on 64-bit host tests.

use crate::heap::tracked::tracked_free;
use crate::sqlite::mem::db_realloc;

type Reallocate = unsafe extern "C" fn(*mut u8, *mut u8, i32) -> *mut u8;
type Free = unsafe extern "C" fn(*mut u8);

const COUNT_OFFSET: usize = 0x44;
const ITEMS_OFFSET: usize = 0x48;

/// Appends `item` to the target-width owned pointer array in `owner`.
///
/// # Safety
///
/// `owner` must reference the retail object's +0x4c-byte prefix. Its count
/// and array pointer must describe a live allocation accepted by `db_realloc`
/// and `tracked_free`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn append_owned_pointer(db: *mut u8, owner: *mut u8, item: *mut u8) {
    unsafe { append_owned_pointer_with(db, owner, item, db_realloc, tracked_free) }
}

unsafe fn append_owned_pointer_with(
    db: *mut u8,
    owner: *mut u8,
    item: *mut u8,
    reallocate: Reallocate,
    free: Free,
) {
    unsafe {
        let count = owner.add(COUNT_OFFSET).cast::<i32>().read();
        owner.add(COUNT_OFFSET).cast::<i32>().write(count.wrapping_add(1));
        let items = owner.add(ITEMS_OFFSET).cast::<u32>().read() as usize as *mut u8;
        let grown = reallocate(db, items, count.wrapping_add(2).wrapping_mul(4));
        if grown.is_null() {
            let mut index = 0;
            while index < count {
                free(items.add(index as usize * 4).cast::<u32>().read() as usize as *mut u8);
                index = index.wrapping_add(1);
            }
            free(item);
            free(items);
            owner.add(COUNT_OFFSET).cast::<i32>().write(0);
        } else {
            grown.add(count as usize * 4).cast::<u32>().write(item as usize as u32);
            grown.add(count as usize * 4 + 4).cast::<u32>().write(0);
        }
        owner.add(ITEMS_OFFSET).cast::<u32>().write(grown as usize as u32);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::Mutex;

    const FIXTURE_LEN: usize = 0x1000;
    const OWNER: usize = 0;
    const OLD_ITEMS: usize = 0x100;
    const GROWN_ITEMS: usize = 0x200;
    const ITEM_A: usize = 0x300;
    const ITEM_B: usize = 0x304;
    const NEW_ITEM: usize = 0x308;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut REALLOC_RESULT: *mut u8 = core::ptr::null_mut();
    static mut REALLOC_BYTES: i32 = 0;
    static mut FREED: [*mut u8; 4] = [core::ptr::null_mut(); 4];
    static mut FREE_COUNT: usize = 0;

    unsafe extern "C" fn record_realloc(_db: *mut u8, _items: *mut u8, bytes: i32) -> *mut u8 {
        unsafe { REALLOC_BYTES = bytes; REALLOC_RESULT }
    }

    unsafe extern "C" fn record_free(pointer: *mut u8) {
        unsafe {
            FREED[FREE_COUNT] = pointer;
            FREE_COUNT += 1;
        }
    }

    unsafe fn fixture(hint: usize) -> Option<*mut u8> {
        let base = try_map_u32_slab(hint, FIXTURE_LEN)?;
        base.write_bytes(0, FIXTURE_LEN);
        Some(base)
    }

    #[test]
    fn appends_item_and_null_sentinel_after_growth() {
        let _guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some(base) = (unsafe { fixture(hints::SQLITE_APPEND_OWNED_POINTER_GROW) }) else {
            assert!(note_missing_u32_fixture("sqlite/append_owned_pointer"));
            return;
        };
        unsafe {
            let owner = base.add(OWNER);
            let old_items = base.add(OLD_ITEMS);
            let grown = base.add(GROWN_ITEMS);
            owner.add(COUNT_OFFSET).cast::<i32>().write(1);
            owner.add(ITEMS_OFFSET).cast::<u32>().write(old_items as usize as u32);
            old_items.cast::<u32>().write(base.add(ITEM_A) as usize as u32);
            REALLOC_RESULT = grown;
            REALLOC_BYTES = 0;
            append_owned_pointer_with(core::ptr::null_mut(), owner, base.add(NEW_ITEM), record_realloc, record_free);
            assert_eq!(REALLOC_BYTES, 12);
            assert_eq!(owner.add(COUNT_OFFSET).cast::<i32>().read(), 2);
            assert_eq!(owner.add(ITEMS_OFFSET).cast::<u32>().read(), grown as usize as u32);
            assert_eq!(grown.add(4).cast::<u32>().read(), base.add(NEW_ITEM) as usize as u32);
            assert_eq!(grown.add(8).cast::<u32>().read(), 0);
        }
    }

    #[test]
    fn failed_growth_releases_existing_and_new_items_then_clears_owner() {
        let _guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some(base) = (unsafe { fixture(hints::SQLITE_APPEND_OWNED_POINTER_FAILURE) }) else {
            assert!(note_missing_u32_fixture("sqlite/append_owned_pointer"));
            return;
        };
        unsafe {
            let owner = base.add(OWNER);
            let old_items = base.add(OLD_ITEMS);
            owner.add(COUNT_OFFSET).cast::<i32>().write(2);
            owner.add(ITEMS_OFFSET).cast::<u32>().write(old_items as usize as u32);
            old_items.cast::<u32>().write(base.add(ITEM_A) as usize as u32);
            old_items.add(4).cast::<u32>().write(base.add(ITEM_B) as usize as u32);
            REALLOC_RESULT = core::ptr::null_mut();
            FREE_COUNT = 0;
            append_owned_pointer_with(core::ptr::null_mut(), owner, base.add(NEW_ITEM), record_realloc, record_free);
            assert_eq!(REALLOC_BYTES, 16);
            assert_eq!(FREE_COUNT, 4);
            let freed = core::ptr::read_volatile(core::ptr::addr_of!(FREED));
            assert_eq!(freed, [base.add(ITEM_A), base.add(ITEM_B), base.add(NEW_ITEM), old_items]);
            assert_eq!(owner.add(COUNT_OFFSET).cast::<i32>().read(), 0);
            assert_eq!(owner.add(ITEMS_OFFSET).cast::<u32>().read(), 0);
        }
    }
}
