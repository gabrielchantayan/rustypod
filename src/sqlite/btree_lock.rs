//! The B-tree shared-cache lock counter — SQLite's `sqlite3BtreeEnter` /
//! `sqlite3BtreeLeave` pair, called around every b-tree operation the
//! engine performs.
//!
//! - `btree_enter` — original: `FUN_0837118c` @ 0x0837118c (28 bytes;
//!   36 `bl` call sites, binary-scanned).
//! - `btree_leave` — original: `FUN_08371da4` @ 0x08371da4 (36 bytes;
//!   41 `bl` + 1 tail `b`).
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
