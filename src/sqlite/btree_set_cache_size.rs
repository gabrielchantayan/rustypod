//! SQLite B-tree page-cache sizing — retailOS `FUN_08372cb8` at
//! `0x08372cb8`.
//!
//! Raw ARM establishes a 48-byte extent: `push {r4,lr}` begins at
//! `0x08372cb8`, `pop {r4,pc}` ends at `0x08372ce4`, and the next distinct
//! function begins with `push {r4,r5,r6,r7,lr}` at `0x08372ce8`. The body has
//! two unconditional plain `bl` instructions (`btree_enter` @ `0x0837118c`
//! and `btree_leave` @ `0x08371da4`) and no predicated `bl`; three plain
//! `bl` instructions elsewhere call this entry. It enters the B-tree,
//! stores `max(n_cache, 10)` in `BtShared.pageSizeFixed`'s cache-size word
//! at `pBt + 0x4c`, leaves the B-tree, and returns zero.
//!
//! Deliberate deviation: the target's 32-bit `Btree.pBt` pointer remains a
//! `u32` word on host builds, preventing host pointer width from changing
//! its offset. The retail target and its field offsets are unchanged.

use super::btree_lock::{btree_enter, btree_leave};

const SHARED_CACHE_OFFSET: usize = 0x04;
const CACHE_SIZE_OFFSET: usize = 0x4c;
const MIN_CACHE_SIZE: i32 = 10;

/// `sqlite3BtreeSetCacheSize` — original: `FUN_08372cb8` @ `0x08372cb8`
/// (48 bytes; 3 plain direct callers, 2 plain internal `bl`, no predicated
/// `bl`, binary-verified).
///
/// Enters `btree`, clamps `n_cache` to at least 10, writes it to the shared
/// B-tree cache-size field, leaves, and returns `SQLITE_OK` (zero).
///
/// # Safety
/// `btree` must name a live retail-layout Btree whose aligned `u32` word at
/// +0x04 is a live BtShared address with writable storage through +0x4f.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn btree_set_cache_size(btree: *mut u8, n_cache: i32) -> u32 {
    btree_enter(btree);
    let shared = btree.add(SHARED_CACHE_OFFSET).cast::<u32>().read() as usize as *mut u8;
    shared.add(CACHE_SIZE_OFFSET).cast::<i32>().write(n_cache.max(MIN_CACHE_SIZE));
    btree_leave(btree);
    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::{LazyLock, Mutex};

    const FIXTURE_LEN: usize = 0x1000;
    const BTREE_OFFSET: usize = 0;
    const SHARED_OFFSET: usize = 0x100;
    const SHARABLE_OFFSET: usize = 0x09;
    const LOCKED_OFFSET: usize = 0x0a;
    const WANT_TO_LOCK_OFFSET: usize = 0x0c;

    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::SQLITE_BTREE_SET_CACHE_SIZE, FIXTURE_LEN).map(|p| p as usize)
    });
    static FIXTURE_LOCK: Mutex<()> = Mutex::new(());

    unsafe fn fixture_btree() -> Option<*mut u8> {
        let base = (*FIXTURE)? as *mut u8;
        base.write_bytes(0, FIXTURE_LEN);
        let btree = base.add(BTREE_OFFSET);
        btree.add(SHARED_CACHE_OFFSET).cast::<u32>().write(base.add(SHARED_OFFSET) as u32);
        Some(btree)
    }

    #[test]
    fn clamps_small_and_negative_sizes_and_balances_shared_lock() {
        let _guard = FIXTURE_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some(btree) = (unsafe { fixture_btree() }) else {
            assert!(note_missing_u32_fixture("sqlite/btree_set_cache_size"));
            return;
        };

        for n_cache in [i32::MIN, -1, 0, 9, 10, 11, 2000] {
            unsafe {
                btree.add(SHARABLE_OFFSET).write(1);
                btree.add(LOCKED_OFFSET).write(1);
                btree.add(WANT_TO_LOCK_OFFSET).cast::<i32>().write(0);
                assert_eq!(btree_set_cache_size(btree, n_cache), 0);
                assert_eq!(
                    (btree.add(SHARED_CACHE_OFFSET).cast::<u32>().read() as usize as *const u8)
                        .add(CACHE_SIZE_OFFSET)
                        .cast::<i32>()
                        .read(),
                    n_cache.max(MIN_CACHE_SIZE)
                );
                assert_eq!(btree.add(WANT_TO_LOCK_OFFSET).cast::<i32>().read(), 0);
                assert_eq!(btree.add(LOCKED_OFFSET).read(), 0);
            }
        }
    }

    #[test]
    fn non_shared_btree_leaves_lock_bytes_unchanged() {
        let _guard = FIXTURE_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some(btree) = (unsafe { fixture_btree() }) else {
            assert!(note_missing_u32_fixture("sqlite/btree_set_cache_size"));
            return;
        };

        unsafe {
            btree.add(SHARABLE_OFFSET).write(0);
            btree.add(LOCKED_OFFSET).write(7);
            btree.add(WANT_TO_LOCK_OFFSET).cast::<i32>().write(3);
            btree_set_cache_size(btree, 42);
            assert_eq!(btree.add(WANT_TO_LOCK_OFFSET).cast::<i32>().read(), 3);
            assert_eq!(btree.add(LOCKED_OFFSET).read(), 7);
        }
    }
}
