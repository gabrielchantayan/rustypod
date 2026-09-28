//! Read the B-tree auto-vacuum mode — retailOS `FUN_08371330` at
//! `0x08371330`.
//!
//! Raw ARM establishes the exact 64-byte extent: `mov r3,r0; push {lr}` begins
//! at `0x08371330`, `pop {pc}` ends at `0x0837136c`, and the next distinct
//! function begins at `0x08371370`. The body has two unconditional plain `bl`
//! instructions (`btree_enter` @ `0x0837118c` and `btree_leave` @ `0x08371da4`)
//! and no predicated `bl`; one plain and one predicated direct caller target
//! this entry.
//!
//! This is SQLite's `sqlite3BtreeGetAutoVacuum`: it enters the B-tree, returns
//! zero when BtShared.autoVacuum (+0x16) is clear, one when it is set and
//! BtShared.incrVacuum (+0x17) is clear, and two when both are set, then leaves.
//! Deliberate deviation: the target-width `Btree.pBt` pointer remains a `u32`
//! word on host builds so host pointer width cannot alter the retail +0x04 layout.

use super::btree_lock::{btree_enter, btree_leave};

const SHARED_CACHE_OFFSET: usize = 0x04;
const AUTO_VACUUM_OFFSET: usize = 0x16;
const INCREMENTAL_VACUUM_OFFSET: usize = 0x17;

/// Return the configured auto-vacuum mode: disabled (0), full (1), or incremental (2).
///
/// # Safety
/// `btree` must name a live retail-layout Btree with a target-width `u32`
/// BtShared pointer at +0x04. The referenced shared cache must be readable
/// through +0x17.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn btree_get_auto_vacuum(btree: *mut u8) -> u32 {
    btree_enter(btree);
    let shared = btree.add(SHARED_CACHE_OFFSET).cast::<u32>().read() as usize as *const u8;
    let mode = if shared.add(AUTO_VACUUM_OFFSET).read() == 0 {
        0
    } else if shared.add(INCREMENTAL_VACUUM_OFFSET).read() == 0 {
        1
    } else {
        2
    };
    btree_leave(btree);
    mode
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
        try_map_u32_slab(hints::SQLITE_BTREE_GET_AUTO_VACUUM, FIXTURE_LEN).map(|p| p as usize)
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
    fn reports_all_auto_vacuum_modes_and_balances_shared_lock() {
        let _guard = FIXTURE_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some((btree, shared)) = (unsafe { fixture_btree() }) else {
            assert!(note_missing_u32_fixture("sqlite/btree_get_auto_vacuum"));
            return;
        };

        for (auto_vacuum, incremental_vacuum, expected) in
            [(0, 0, 0), (0, 1, 0), (1, 0, 1), (1, 1, 2)]
        {
            unsafe {
                btree.add(SHARABLE_OFFSET).write(1);
                btree.add(LOCKED_OFFSET).write(1);
                btree.add(WANT_TO_LOCK_OFFSET).cast::<i32>().write(0);
                shared.add(AUTO_VACUUM_OFFSET).write(auto_vacuum);
                shared.add(INCREMENTAL_VACUUM_OFFSET).write(incremental_vacuum);

                assert_eq!(btree_get_auto_vacuum(btree), expected);
                assert_eq!(btree.add(WANT_TO_LOCK_OFFSET).cast::<i32>().read(), 0);
                assert_eq!(btree.add(LOCKED_OFFSET).read(), 0);
            }
        }
    }

    #[test]
    fn non_shared_btree_preserves_lock_state() {
        let _guard = FIXTURE_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some((btree, shared)) = (unsafe { fixture_btree() }) else {
            assert!(note_missing_u32_fixture("sqlite/btree_get_auto_vacuum"));
            return;
        };

        unsafe {
            btree.add(SHARABLE_OFFSET).write(0);
            btree.add(LOCKED_OFFSET).write(7);
            btree.add(WANT_TO_LOCK_OFFSET).cast::<i32>().write(3);
            shared.add(AUTO_VACUUM_OFFSET).write(1);
            shared.add(INCREMENTAL_VACUUM_OFFSET).write(1);

            assert_eq!(btree_get_auto_vacuum(btree), 2);
            assert_eq!(btree.add(WANT_TO_LOCK_OFFSET).cast::<i32>().read(), 3);
            assert_eq!(btree.add(LOCKED_OFFSET).read(), 7);
        }
    }
}
