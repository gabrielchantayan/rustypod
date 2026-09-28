//! Set the B-tree shared cache's page-size-fixed flag — retailOS
//! `FUN_08372c70` at `0x08372c70`.
//!
//! Raw ARM establishes the exact 72-byte extent: `push {r4,r5,r6,r7,r8,lr}`
//! begins at `0x08372c70`, `pop {r4,r5,r6,r7,r8,pc}` ends at `0x08372cb4`, and
//! the next distinct function begins at `0x08372cb8`. The body has two
//! unconditional plain `bl` instructions (`btree_enter` @ `0x0837118c` and
//! `btree_leave` @ `0x08371da4`) and no predicated `bl`; two plain direct
//! callers target this entry.
//!
//! It normalizes `fixed` to zero or one, enters the B-tree, then compares the
//! requested value with `BtShared.pageSizeFixed` (+0x16). A read-only shared
//! cache (+0x15) accepts an unchanged value and otherwise returns
//! `SQLITE_READONLY` (8); a writable cache stores the requested value. It
//! leaves the B-tree on every path. Deliberate deviations: none.

use super::btree_lock::{btree_enter, btree_leave};

const SHARED_CACHE_OFFSET: usize = 0x04;
const READ_ONLY_OFFSET: usize = 0x15;
const PAGE_SIZE_FIXED_OFFSET: usize = 0x16;
const SQLITE_READONLY: u32 = 8;

/// Set `BtShared.pageSizeFixed` after rejecting a change to a read-only cache.
///
/// # Safety
/// `btree` must name a live retail-layout Btree with a target-width `u32`
/// `BtShared` pointer at +0x04. The referenced shared cache must be readable
/// through +0x16 and writable at +0x16 when its read-only byte is zero.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn btree_set_page_size_fixed(btree: *mut u8, fixed: i32) -> u32 {
    let fixed = (fixed != 0) as u8;
    let shared = btree.add(SHARED_CACHE_OFFSET).cast::<u32>().read() as usize as *mut u8;

    btree_enter(btree);
    let result = if shared.add(READ_ONLY_OFFSET).read() != 0
        && shared.add(PAGE_SIZE_FIXED_OFFSET).read() != fixed
    {
        SQLITE_READONLY
    } else {
        shared.add(PAGE_SIZE_FIXED_OFFSET).write(fixed);
        0
    };
    btree_leave(btree);
    result
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::{LazyLock, Mutex};

    const FIXTURE_LEN: usize = 0x1000;
    const SHARED_OFFSET: usize = 0x100;
    const SHARABLE_OFFSET: usize = 0x09;
    const LOCKED_OFFSET: usize = 0x0a;
    const WANT_TO_LOCK_OFFSET: usize = 0x0c;

    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::SQLITE_BTREE_SET_PAGE_SIZE_FIXED, FIXTURE_LEN).map(|p| p as usize)
    });
    static FIXTURE_LOCK: Mutex<()> = Mutex::new(());

    unsafe fn fixture_btree() -> Option<(*mut u8, *mut u8)> {
        let base = (*FIXTURE)? as *mut u8;
        base.write_bytes(0, FIXTURE_LEN);
        let btree = base;
        let shared = base.add(SHARED_OFFSET);
        btree.add(SHARED_CACHE_OFFSET).cast::<u32>().write(shared as u32);
        Some((btree, shared))
    }

    #[test]
    fn writable_cache_normalizes_every_nonzero_input_and_balances_lock() {
        let _guard = FIXTURE_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some((btree, shared)) = (unsafe { fixture_btree() }) else {
            assert!(note_missing_u32_fixture("sqlite/btree_set_page_size_fixed"));
            return;
        };

        for fixed in [0, 1, -1, i32::MIN, i32::MAX] {
            unsafe {
                btree.add(SHARABLE_OFFSET).write(1);
                btree.add(LOCKED_OFFSET).write(1);
                btree.add(WANT_TO_LOCK_OFFSET).cast::<i32>().write(0);
                shared.add(READ_ONLY_OFFSET).write(0);
                shared.add(PAGE_SIZE_FIXED_OFFSET).write(0xaa);
                assert_eq!(btree_set_page_size_fixed(btree, fixed), 0);
                assert_eq!(shared.add(PAGE_SIZE_FIXED_OFFSET).read(), (fixed != 0) as u8);
                assert_eq!(btree.add(WANT_TO_LOCK_OFFSET).cast::<i32>().read(), 0);
                assert_eq!(btree.add(LOCKED_OFFSET).read(), 0);
            }
        }
    }

    #[test]
    fn readonly_cache_allows_only_the_existing_normalized_value() {
        let _guard = FIXTURE_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some((btree, shared)) = (unsafe { fixture_btree() }) else {
            assert!(note_missing_u32_fixture("sqlite/btree_set_page_size_fixed"));
            return;
        };

        unsafe {
            btree.add(SHARABLE_OFFSET).write(0);
            btree.add(LOCKED_OFFSET).write(7);
            btree.add(WANT_TO_LOCK_OFFSET).cast::<i32>().write(3);
            shared.add(READ_ONLY_OFFSET).write(1);
            shared.add(PAGE_SIZE_FIXED_OFFSET).write(1);
            assert_eq!(btree_set_page_size_fixed(btree, -1), 0);
            assert_eq!(shared.add(PAGE_SIZE_FIXED_OFFSET).read(), 1);
            assert_eq!(btree_set_page_size_fixed(btree, 0), SQLITE_READONLY);
            assert_eq!(shared.add(PAGE_SIZE_FIXED_OFFSET).read(), 1);
            assert_eq!(btree.add(WANT_TO_LOCK_OFFSET).cast::<i32>().read(), 3);
            assert_eq!(btree.add(LOCKED_OFFSET).read(), 7);
        }
    }
}
