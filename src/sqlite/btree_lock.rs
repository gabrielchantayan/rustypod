//! The B-tree shared-cache lock counter — SQLite's `sqlite3BtreeEnter`,
//! `sqlite3BtreeLeave`, `sqlite3BtreeEnterAll`, and `sqlite3BtreeLeaveAll`,
//! called around every b-tree operation the engine performs.
//!
//! - `btree_enter` — original: `FUN_0837118c` @ 0x0837118c (28 bytes;
//!   36 `bl` call sites, binary-scanned).
//! - `btree_enter_all` — original: `FUN_083711a8` @ 0x083711a8 (196 bytes;
//!   3 plain `bl` + 1 predicated `blle`, binary-scanned).
//! - `btree_leave` — original: `FUN_08371da4` @ 0x08371da4 (36 bytes;
//!   41 `bl` + 1 tail `b`).
//! - `btree_leave_all` — original: `FUN_08371dc8` @ 0x08371dc8 (80 bytes;
//!   5 `bl` call sites, binary-scanned).
//!
//! `Btree` layout, pinned by the two functions agreeing on all three
//! fields (and matching SQLite's own struct order `db, pBt, inTrans,
//! sharable, locked, wantToLock`):
//!
//! ```text
//! +0x08 in_trans    (u8)
//! +0x09 sharable    (u8)   non-shared handles skip the whole protocol
//! +0x0a locked      (u8)   this handle currently holds the mutex
//! +0x0c want_to_lock (i32) recursion depth of enter/leave
//! +0x10 next        (Btree*) shared-cache sibling list (enter_all only)
//! +0x14 prev        (Btree*) back-link; only list heads take the lock
//! ```
//!
//! In this build `SQLITE_THREADSAFE` is off, so the mutex acquisition and
//! release the two functions bracket has been compiled away: what is left
//! is the recursion counter plus the `locked` flag, cleared when the
//! outermost `leave` returns. That is the whole body — there is no call
//! out of either function.
//!
//! Deviation: the original's `enter` leaves `p->locked` in r0 on the
//! `sharable` path and the untouched `p` pointer on the other, i.e. its
//! return value is inconsistent between paths. SQLite declares
//! `sqlite3BtreeEnter` as `void`, and no call site consumes r0 (all 36
//! are plain `bl` with the result dead), so it is ported as `void`.

/// Byte offset of `Btree.sharable` (original: `ldrb r1, [r0, #9]`).
const SHARABLE_OFFSET: usize = 0x09;
/// Byte offset of `Btree.locked` (original: `ldrb/strb [r0, #10]`).
const LOCKED_OFFSET: usize = 0x0a;
/// Byte offset of `Btree.wantToLock` (original: `ldr/str [r0, #12]`).
const WANT_TO_LOCK_OFFSET: usize = 0x0c;

/// The nesting counter. A byte offset is used for the `u8` flags and a
/// word offset for the counter; all three are fixed-width fields, not
/// pointers, so the offsets are host-independent.
#[inline(always)]
unsafe fn want_to_lock(btree: *mut u8) -> *mut i32 {
    btree.add(WANT_TO_LOCK_OFFSET) as *mut i32
}

/// btree_enter — original: `FUN_0837118c` @ 0x0837118c (28 bytes;
/// 36 `bl` call sites).
///
/// `sqlite3BtreeEnter`: take a (recursive) reference to the b-tree's
/// shared cache. Non-shared handles return immediately; otherwise the
/// nesting counter goes up.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn btree_enter(btree: *mut u8) {
    if btree.add(SHARABLE_OFFSET).read() == 0 {
        return;
    }
    let depth = want_to_lock(btree);
    depth.write(depth.read().wrapping_add(1));
}

/// btree_leave — original: `FUN_08371da4` @ 0x08371da4 (36 bytes;
/// 41 `bl` + 1 tail `b`).
///
/// `sqlite3BtreeLeave`: drop one reference. The `locked` flag is cleared
/// only when the counter reaches exactly zero — an over-released handle
/// keeps counting down into negatives without clearing it, which is the
/// original's behavior (it relies on an `assert( p->wantToLock>0 )` that
/// is compiled out here).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn btree_leave(btree: *mut u8) {
    if btree.add(SHARABLE_OFFSET).read() == 0 {
        return;
    }
    let depth = want_to_lock(btree);
    let remaining = depth.read().wrapping_sub(1);
    depth.write(remaining);
    if remaining == 0 {
        btree.add(LOCKED_OFFSET).write(0);
    }
}

/// sqlite3 `nDb` field, the signed number of `Db` records.
const DB_COUNT_OFFSET: usize = 0x04;
/// sqlite3 `aDb` field, a target-width pointer to 24-byte `Db` records.
const DATABASES_OFFSET: usize = 0x08;
/// Size of one SQLite `Db` record on the ARM target.
const DATABASE_RECORD_SIZE: usize = 0x18;
/// `Db.pBt`, a target-width pointer to its B-tree handle.
const DATABASE_BTREE_OFFSET: usize = 0x04;

/// Read an aligned target-width pointer.
///
/// `sqlite3.aDb` and `Db.pBt` are both 32-bit words in retailOS. Keeping
/// their target width avoids host-pointer widening changing the recovered
/// offsets.
#[inline(always)]
unsafe fn target_pointer(at: *const u8) -> *mut u8 {
    at.cast::<u32>().read() as usize as *mut u8
}

/// btree_leave_all — original: `FUN_08371dc8` @ 0x08371dc8 (80 bytes;
/// 5 unconditional plain `bl` call sites, binary-scanned).
///
/// `sqlite3BtreeLeaveAll`: scan the signed `sqlite3.nDb` count and, for
/// each non-null `Db.pBt`, release one shared-cache nesting reference when
/// its `Btree.sharable` flag is set. The retail body inlines
/// `sqlite3BtreeLeave`, so this port does likewise rather than adding a
/// call edge. A zero or negative count performs no iteration. As in the
/// original, the `locked` byte is cleared only when decrementing reaches
/// exactly zero.
///
/// Deliberate host-only adaptation: `aDb` and `pBt` remain target-width
/// `u32` words. Host tests map their fixture below 4 GiB before encoding
/// those pointers; device behavior and every target offset are unchanged.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn btree_leave_all(database: *mut u8) {
    let mut index = 0i32;
    while index < database.add(DB_COUNT_OFFSET).cast::<i32>().read() {
        let record = target_pointer(database.add(DATABASES_OFFSET))
            .add(index as usize * DATABASE_RECORD_SIZE);
        let btree = target_pointer(record.add(DATABASE_BTREE_OFFSET));
        if !btree.is_null() && btree.add(SHARABLE_OFFSET).read() != 0 {
            let depth = want_to_lock(btree);
            let remaining = depth.read().wrapping_sub(1);
            depth.write(remaining);
            if remaining == 0 {
                btree.add(LOCKED_OFFSET).write(0);
            }
        }
        index = index.wrapping_add(1);
    }
}

/// `Btree.pNext`, the target-width link to the next handle sharing one
/// `BtShared` (original: `ldr/str [rN, #0x10]`).
const SHARED_NEXT_OFFSET: usize = 0x10;
/// `Btree.pPrev`, the target-width back-link (original: `ldr [r1, #0x14]`).
const SHARED_PREV_OFFSET: usize = 0x14;

/// btree_enter_all — original: `FUN_083711a8` @ 0x083711a8 (196 bytes;
/// 3 unconditional plain `bl` call sites at 0x082b54c4, 0x0837d328,
/// 0x0838f1c8 and 1 predicated `blle` at 0x083820ac, binary-scanned).
///
/// `sqlite3BtreeEnterAll`: scan the signed `sqlite3.nDb` count and, for
/// each non-null, sharable `Db.pBt`, take one shared-cache nesting
/// reference. The retail body inlines the shared-cache half of
/// `sqlite3BtreeEnter`, so this port does likewise rather than adding a
/// call edge:
///
/// - `wantToLock` always goes up, even when the handle is already locked.
/// - An already-`locked` handle stops there.
/// - Otherwise the handle is first walked back along `pPrev` to the
///   head of its `BtShared` sibling list, then forward along `pNext`
///   to the first unlocked sibling (or the list tail). Every successor
///   of that sibling has `locked` cleared where set, and finally
///   `locked` is incremented on that sibling and every successor.
///   Dead in the all-unlocked common case — the head's `locked` was
///   just proven 0, so the forward walk never advances — but kept for
///   structural parity.
///
/// Deliberate host-only adaptation: `aDb`, `pBt`, and the sibling links
/// remain target-width `u32` words. Host tests map their fixture below
/// 4 GiB before encoding those pointers; device behavior and every
/// target offset are unchanged.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn btree_enter_all(database: *mut u8) {
    let mut index = 0i32;
    while index < database.add(DB_COUNT_OFFSET).cast::<i32>().read() {
        let record = target_pointer(database.add(DATABASES_OFFSET))
            .add(index as usize * DATABASE_RECORD_SIZE);
        let btree = target_pointer(record.add(DATABASE_BTREE_OFFSET));
        if !btree.is_null() && btree.add(SHARABLE_OFFSET).read() != 0 {
            let depth = want_to_lock(btree);
            depth.write(depth.read().wrapping_add(1));
            if btree.add(LOCKED_OFFSET).read() == 0 {
                let mut head = btree;
                loop {
                    let prev = target_pointer(head.add(SHARED_PREV_OFFSET));
                    if prev.is_null() {
                        break;
                    }
                    head = prev;
                }
                let mut node = head;
                while node.add(LOCKED_OFFSET).read() != 0 {
                    let next = target_pointer(node.add(SHARED_NEXT_OFFSET));
                    if next.is_null() {
                        break;
                    }
                    node = next;
                }
                let mut peer = target_pointer(node.add(SHARED_NEXT_OFFSET));
                while !peer.is_null() {
                    if peer.add(LOCKED_OFFSET).read() != 0 {
                        peer.add(LOCKED_OFFSET).write(0);
                    }
                    peer = target_pointer(peer.add(SHARED_NEXT_OFFSET));
                }
                let mut peer = node;
                while !peer.is_null() {
                    let locked = peer.add(LOCKED_OFFSET);
                    locked.write(locked.read().wrapping_add(1));
                    peer = target_pointer(peer.add(SHARED_NEXT_OFFSET));
                }
            }
        }
        index = index.wrapping_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::{LazyLock, Mutex};

    const LEAVE_ALL_FIXTURE_LEN: usize = 0x1000;
    const LEAVE_ALL_DATABASE_OFFSET: usize = 0x100;
    const LEAVE_ALL_RECORDS_OFFSET: usize = 0x200;
    const LEAVE_ALL_BTREE0_OFFSET: usize = 0x400;
    const LEAVE_ALL_BTREE1_OFFSET: usize = 0x440;
    const LEAVE_ALL_BTREE2_OFFSET: usize = 0x480;
    static LEAVE_ALL_FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::BTREE_LEAVE_ALL, LEAVE_ALL_FIXTURE_LEN).map(|pointer| pointer as usize)
    });
    static LEAVE_ALL_FIXTURE_LOCK: Mutex<()> = Mutex::new(());

    unsafe fn initialize_leave_all_fixture(count: i32) -> Option<(*mut u8, *mut u8)> {
        let base = (*LEAVE_ALL_FIXTURE)? as *mut u8;
        base.write_bytes(0xa5, LEAVE_ALL_FIXTURE_LEN);
        let database = base.add(LEAVE_ALL_DATABASE_OFFSET);
        let records = base.add(LEAVE_ALL_RECORDS_OFFSET);
        database.add(DB_COUNT_OFFSET).cast::<i32>().write(count);
        database.add(DATABASES_OFFSET).cast::<u32>().write(records as usize as u32);
        Some((database, records))
    }

    unsafe fn set_record_btree(records: *mut u8, index: usize, btree: *mut u8) {
        records
            .add(index * DATABASE_RECORD_SIZE + DATABASE_BTREE_OFFSET)
            .cast::<u32>()
            .write(btree as usize as u32);
    }

    unsafe fn initialize_raw_btree(
        base: *mut u8,
        offset: usize,
        sharable: u8,
        locked: u8,
        depth: i32,
    ) -> *mut u8 {
        let btree = base.add(offset);
        btree.add(SHARABLE_OFFSET).write(sharable);
        btree.add(LOCKED_OFFSET).write(locked);
        want_to_lock(btree).write(depth);
        btree
    }

    /// A `Btree` handle: word-aligned so the counter load is aligned,
    /// as it is on target.
    #[repr(align(4))]
    struct Handle([u8; 0x20]);

    impl Handle {
        fn new(sharable: bool, locked: u8, depth: i32) -> Self {
            let mut handle = Handle([0xa5; 0x20]);
            handle.0[SHARABLE_OFFSET] = u8::from(sharable);
            handle.0[LOCKED_OFFSET] = locked;
            handle.0[WANT_TO_LOCK_OFFSET..WANT_TO_LOCK_OFFSET + 4]
                .copy_from_slice(&depth.to_le_bytes());
            handle
        }
        fn ptr(&mut self) -> *mut u8 {
            self.0.as_mut_ptr()
        }
        fn locked(&self) -> u8 {
            self.0[LOCKED_OFFSET]
        }
        fn depth(&self) -> i32 {
            i32::from_le_bytes(
                self.0[WANT_TO_LOCK_OFFSET..WANT_TO_LOCK_OFFSET + 4].try_into().unwrap(),
            )
        }
    }

    #[test]
    fn a_non_shared_handle_is_untouched_by_both() {
        let mut handle = Handle::new(false, 1, 5);
        unsafe { btree_enter(handle.ptr()) };
        unsafe { btree_leave(handle.ptr()) };
        assert_eq!(handle.depth(), 5);
        assert_eq!(handle.locked(), 1);
    }

    #[test]
    fn nesting_counts_up_and_back_down() {
        let mut handle = Handle::new(true, 1, 0);
        for expected in 1..=4 {
            unsafe { btree_enter(handle.ptr()) };
            assert_eq!(handle.depth(), expected);
            assert_eq!(handle.locked(), 1, "still held while nested");
        }
        for expected in (1..=3).rev() {
            unsafe { btree_leave(handle.ptr()) };
            assert_eq!(handle.depth(), expected);
            assert_eq!(handle.locked(), 1);
        }
        unsafe { btree_leave(handle.ptr()) };
        assert_eq!(handle.depth(), 0);
        assert_eq!(handle.locked(), 0, "released at the outermost leave");
    }

    #[test]
    fn the_flag_clears_only_at_exactly_zero() {
        // Over-release: the counter goes negative and `locked` stays.
        let mut handle = Handle::new(true, 1, 0);
        unsafe { btree_leave(handle.ptr()) };
        assert_eq!(handle.depth(), -1);
        assert_eq!(handle.locked(), 1, "0 -> -1 never lands on zero");

        let mut handle = Handle::new(true, 1, -1);
        unsafe { btree_leave(handle.ptr()) };
        assert_eq!(handle.depth(), -2);
        assert_eq!(handle.locked(), 1, "never hit zero, so never cleared");
    }

    #[test]
    fn the_counter_wraps_like_the_original() {
        let mut handle = Handle::new(true, 1, i32::MAX);
        unsafe { btree_enter(handle.ptr()) };
        assert_eq!(handle.depth(), i32::MIN);

        let mut handle = Handle::new(true, 1, i32::MIN);
        unsafe { btree_leave(handle.ptr()) };
        assert_eq!(handle.depth(), i32::MAX);
        assert_eq!(handle.locked(), 1);
    }

    #[test]
    fn nothing_outside_the_three_fields_is_written() {
        let mut handle = Handle::new(true, 1, 1);
        unsafe { btree_enter(handle.ptr()) };
        unsafe { btree_leave(handle.ptr()) };
        for (i, byte) in handle.0.iter().enumerate() {
            let touched = i == SHARABLE_OFFSET
                || i == LOCKED_OFFSET
                || (WANT_TO_LOCK_OFFSET..WANT_TO_LOCK_OFFSET + 4).contains(&i);
            if !touched {
                assert_eq!(*byte, 0xa5, "byte {i:#x} was clobbered");
            }
        }
    }
    #[test]
    fn leave_all_skips_null_and_non_shared_handles() {
        let _guard = LEAVE_ALL_FIXTURE_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let Some((database, records)) = (unsafe { initialize_leave_all_fixture(4) }) else {
            assert!(note_missing_u32_fixture("sqlite/btree_lock leave_all"));
            return;
        };
        let base = (*LEAVE_ALL_FIXTURE).unwrap() as *mut u8;
        unsafe {
            let non_shared = initialize_raw_btree(base, LEAVE_ALL_BTREE0_OFFSET, 0, 0x7c, 5);
            let outermost = initialize_raw_btree(base, LEAVE_ALL_BTREE1_OFFSET, 1, 0x6c, 1);
            let wrapped = initialize_raw_btree(base, LEAVE_ALL_BTREE2_OFFSET, 1, 0x5c, i32::MIN);
            set_record_btree(records, 0, core::ptr::null_mut());
            set_record_btree(records, 1, non_shared);
            set_record_btree(records, 2, outermost);
            set_record_btree(records, 3, wrapped);

            btree_leave_all(database);

            assert_eq!(want_to_lock(non_shared).read(), 5);
            assert_eq!(non_shared.add(LOCKED_OFFSET).read(), 0x7c);
            assert_eq!(want_to_lock(outermost).read(), 0);
            assert_eq!(outermost.add(LOCKED_OFFSET).read(), 0);
            assert_eq!(want_to_lock(wrapped).read(), i32::MAX);
            assert_eq!(wrapped.add(LOCKED_OFFSET).read(), 0x5c);
        }
    }

    const ENTER_ALL_FIXTURE_LEN: usize = 0x1000;
    const ENTER_ALL_DATABASE_OFFSET: usize = 0x100;
    const ENTER_ALL_RECORDS_OFFSET: usize = 0x200;
    const ENTER_ALL_HEAD_OFFSET: usize = 0x400;
    const ENTER_ALL_SIBLING1_OFFSET: usize = 0x440;
    const ENTER_ALL_SIBLING2_OFFSET: usize = 0x480;
    const ENTER_ALL_SPARE_OFFSET: usize = 0x4c0;
    static ENTER_ALL_FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::BTREE_ENTER_ALL, ENTER_ALL_FIXTURE_LEN).map(|pointer| pointer as usize)
    });
    static ENTER_ALL_FIXTURE_LOCK: Mutex<()> = Mutex::new(());

    unsafe fn initialize_enter_all_fixture(count: i32) -> Option<(*mut u8, *mut u8)> {
        let base = (*ENTER_ALL_FIXTURE)? as *mut u8;
        base.write_bytes(0xa5, ENTER_ALL_FIXTURE_LEN);
        let database = base.add(ENTER_ALL_DATABASE_OFFSET);
        let records = base.add(ENTER_ALL_RECORDS_OFFSET);
        database.add(DB_COUNT_OFFSET).cast::<i32>().write(count);
        database.add(DATABASES_OFFSET).cast::<u32>().write(records as usize as u32);
        Some((database, records))
    }

    unsafe fn initialize_node(
        base: *mut u8,
        offset: usize,
        sharable: u8,
        locked: u8,
        depth: i32,
        next: *mut u8,
        prev: *mut u8,
    ) -> *mut u8 {
        let node = initialize_raw_btree(base, offset, sharable, locked, depth);
        node.add(SHARED_NEXT_OFFSET).cast::<u32>().write(next as usize as u32);
        node.add(SHARED_PREV_OFFSET).cast::<u32>().write(prev as usize as u32);
        node
    }

    #[test]
    fn enter_all_skips_null_non_shared_and_locked_handles() {
        let _guard = ENTER_ALL_FIXTURE_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let Some((database, records)) = (unsafe { initialize_enter_all_fixture(3) }) else {
            assert!(note_missing_u32_fixture("sqlite/btree_lock enter_all"));
            return;
        };
        let base = (*ENTER_ALL_FIXTURE).unwrap() as *mut u8;
        unsafe {
            let non_shared = initialize_node(
                base, ENTER_ALL_HEAD_OFFSET, 0, 0x7c, 5,
                core::ptr::null_mut(), core::ptr::null_mut(),
            );
            let already_locked = initialize_node(
                base, ENTER_ALL_SIBLING1_OFFSET, 1, 3, 2,
                core::ptr::null_mut(), core::ptr::null_mut(),
            );
            set_record_btree(records, 0, core::ptr::null_mut());
            set_record_btree(records, 1, non_shared);
            set_record_btree(records, 2, already_locked);

            btree_enter_all(database);

            assert_eq!(want_to_lock(non_shared).read(), 5, "non-shared untouched");
            assert_eq!(non_shared.add(LOCKED_OFFSET).read(), 0x7c);
            assert_eq!(want_to_lock(already_locked).read(), 3, "depth still rises");
            assert_eq!(already_locked.add(LOCKED_OFFSET).read(), 3, "lock byte untouched");
        }
    }

    #[test]
    fn enter_all_locks_the_whole_sibling_list_from_the_head() {
        let _guard = ENTER_ALL_FIXTURE_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let Some((database, records)) = (unsafe { initialize_enter_all_fixture(1) }) else {
            assert!(note_missing_u32_fixture("sqlite/btree_lock enter_all"));
            return;
        };
        let base = (*ENTER_ALL_FIXTURE).unwrap() as *mut u8;
        unsafe {
            let sibling2 = initialize_node(
                base, ENTER_ALL_SIBLING2_OFFSET, 1, 2, 9,
                core::ptr::null_mut(), core::ptr::null_mut(),
            );
            let sibling1 = initialize_node(
                base, ENTER_ALL_SIBLING1_OFFSET, 1, 1, 8,
                sibling2, core::ptr::null_mut(),
            );
            let head = initialize_node(
                base, ENTER_ALL_HEAD_OFFSET, 1, 0, 0,
                sibling1, core::ptr::null_mut(),
            );
            set_record_btree(records, 0, head);
            btree_enter_all(database);

            assert_eq!(want_to_lock(head).read(), 1);
            assert_eq!(head.add(LOCKED_OFFSET).read(), 1, "0 -> 1");
            assert_eq!(sibling1.add(LOCKED_OFFSET).read(), 1, "cleared then re-incremented");
            assert_eq!(sibling2.add(LOCKED_OFFSET).read(), 1, "2 -> 0 -> 1");
            assert_eq!(want_to_lock(sibling1).read(), 8, "siblings are not Db records");
            assert_eq!(want_to_lock(sibling2).read(), 9);
        }
    }

    #[test]
    fn enter_all_walks_back_to_the_list_head_from_a_non_head_entry() {
        let _guard = ENTER_ALL_FIXTURE_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let Some((database, records)) = (unsafe { initialize_enter_all_fixture(1) }) else {
            assert!(note_missing_u32_fixture("sqlite/btree_lock enter_all"));
            return;
        };
        let base = (*ENTER_ALL_FIXTURE).unwrap() as *mut u8;
        unsafe {
            let entry = initialize_node(
                base, ENTER_ALL_SIBLING1_OFFSET, 1, 0, 1,
                core::ptr::null_mut(), core::ptr::null_mut(),
            );
            let head = initialize_node(
                base, ENTER_ALL_HEAD_OFFSET, 1, 1, 8,
                entry, core::ptr::null_mut(),
            );
            entry.add(SHARED_PREV_OFFSET).cast::<u32>().write(head as usize as u32);
            set_record_btree(records, 0, entry);

            btree_enter_all(database);

            assert_eq!(want_to_lock(entry).read(), 2, "depth still rises");
            assert_eq!(entry.add(LOCKED_OFFSET).read(), 1, "0 -> 1");
            assert_eq!(head.add(LOCKED_OFFSET).read(), 1, "locked head is not re-incremented");
            assert_eq!(want_to_lock(head).read(), 8, "head is not a Db record");
        }
    }

    #[test]
    fn enter_all_does_not_iterate_non_positive_counts() {
        let _guard = ENTER_ALL_FIXTURE_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let Some((database, records)) = (unsafe { initialize_enter_all_fixture(0) }) else {
            assert!(note_missing_u32_fixture("sqlite/btree_lock enter_all"));
            return;
        };
        let base = (*ENTER_ALL_FIXTURE).unwrap() as *mut u8;
        unsafe {
            let head = initialize_node(
                base, ENTER_ALL_SPARE_OFFSET, 1, 0, 1,
                core::ptr::null_mut(), core::ptr::null_mut(),
            );
            set_record_btree(records, 0, head);

            btree_enter_all(database);
            database.add(DB_COUNT_OFFSET).cast::<i32>().write(-1);
            btree_enter_all(database);

            assert_eq!(want_to_lock(head).read(), 1);
            assert_eq!(head.add(LOCKED_OFFSET).read(), 0);
        }
    }

    #[test]
    fn leave_all_does_not_iterate_non_positive_counts() {
        let _guard = LEAVE_ALL_FIXTURE_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let Some((database, records)) = (unsafe { initialize_leave_all_fixture(0) }) else {
            assert!(note_missing_u32_fixture("sqlite/btree_lock leave_all"));
            return;
        };
        let base = (*LEAVE_ALL_FIXTURE).unwrap() as *mut u8;
        unsafe {
            let btree = initialize_raw_btree(base, LEAVE_ALL_BTREE0_OFFSET, 1, 0x4b, 1);
            set_record_btree(records, 0, btree);

            btree_leave_all(database);
            database.add(DB_COUNT_OFFSET).cast::<i32>().write(-1);
            btree_leave_all(database);

            assert_eq!(want_to_lock(btree).read(), 1);
            assert_eq!(btree.add(LOCKED_OFFSET).read(), 0x4b);
        }
    }
}
