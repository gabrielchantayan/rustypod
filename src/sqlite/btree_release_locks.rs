//! Release every lock held by a SQLite B-tree.
//!
//! `btree_release_locks` is retailOS `FUN_08396098` at load address
//! `0x08396098`. Raw ARM establishes the 80-byte extent
//! `0x08396098..0x083960e8`: `pop {r4-r6,pc}` is immediately followed by a
//! distinct `push {r4,lr}`. It has two inbound plain `bl` calls (from
//! `sqlite3BtreeCommitPhaseTwo` and `sqlite3BtreeRollback`), one outbound
//! plain `bl` to `tracked_free` @ `0x083906f4`, and no predicated `bl` calls.
//!
//! It unlinks each lock record in the shared B-tree's lock list whose B-tree
//! field names `btree`, freeing the removed record, then clears the shared
//! B-tree's pending-owner word if it names that B-tree. Deliberate deviations:
//! host pointer slots scale to pointer width so fixtures do not overlap; target
//! offsets remain the original four-byte slots.

use crate::heap::tracked::tracked_free;

const WORD: usize = core::mem::size_of::<*mut u8>();
const BTREE_SHARED: usize = 0x04;
const SHARED_LOCK_LIST: usize = 0x58;
const SHARED_PENDING_OWNER: usize = 0x5c;
const LOCK_OWNER: usize = 0x00;
const LOCK_NEXT: usize = 0x0c;

#[inline(always)]
const fn pointer_offset(target_offset: usize) -> usize { target_offset / 4 * WORD }

#[inline(always)]
unsafe fn pointer_at(base: *mut u8, target_offset: usize) -> *mut u8 {
    (base.add(pointer_offset(target_offset)) as *const *mut u8).read()
}

#[inline(always)]
unsafe fn set_pointer(base: *mut u8, target_offset: usize, value: *mut u8) {
    (base.add(pointer_offset(target_offset)) as *mut *mut u8).write(value);
}

/// `sqlite3BtreeReleaseLocks` — retailOS `FUN_08396098` @ `0x08396098`
/// (80 bytes; two inbound plain `bl` calls, one outbound plain `bl`, no
/// predicated `bl` calls).
///
/// `btree`, its target-layout shared-B-tree pointer, and every linked lock
/// record must be valid. Removed records must be tracked allocations.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn btree_release_locks(btree: *mut u8) {
    let shared = pointer_at(btree, BTREE_SHARED);
    let mut link = shared.add(pointer_offset(SHARED_LOCK_LIST)) as *mut *mut u8;
    let mut lock = link.read();
    while !lock.is_null() {
        if pointer_at(lock, LOCK_OWNER) == btree {
            let next = pointer_at(lock, LOCK_NEXT);
            link.write(next);
            tracked_free(lock);
            lock = next;
        } else {
            link = lock.add(pointer_offset(LOCK_NEXT)) as *mut *mut u8;
            lock = link.read();
        }
    }
    if pointer_at(shared, SHARED_PENDING_OWNER) == btree {
        set_pointer(shared, SHARED_PENDING_OWNER, core::ptr::null_mut());
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    #[test]
    fn preserves_other_locks_and_clears_pending_owner() {
        let mut btree = [0u8; 3 * WORD];
        let mut shared = [0u8; 0x60 / 4 * WORD];
        let mut other_lock = [0u8; 4 * WORD];
        unsafe {
            set_pointer(btree.as_mut_ptr(), BTREE_SHARED, shared.as_mut_ptr());
            set_pointer(shared.as_mut_ptr(), SHARED_LOCK_LIST, other_lock.as_mut_ptr());
            set_pointer(shared.as_mut_ptr(), SHARED_PENDING_OWNER, btree.as_mut_ptr());
            set_pointer(other_lock.as_mut_ptr(), LOCK_OWNER, shared.as_mut_ptr());
            set_pointer(other_lock.as_mut_ptr(), LOCK_NEXT, core::ptr::null_mut());
            btree_release_locks(btree.as_mut_ptr());
            assert_eq!(pointer_at(shared.as_mut_ptr(), SHARED_LOCK_LIST), other_lock.as_mut_ptr());
            assert!(pointer_at(shared.as_mut_ptr(), SHARED_PENDING_OWNER).is_null());
        }
    }
}
