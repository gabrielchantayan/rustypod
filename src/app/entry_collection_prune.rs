//! `entry_collection_prune` — retailOS `FUN_0810f99c` @ `0x0810f99c`.
//!
//! True extent: **84 bytes**, `[0x0810f99c, 0x0810f9f0)`; the next word
//! starts a separate push. Raw A32 decoding verifies three plain BLs and
//! zero predicated BLs in the body. Whole-image decoding finds two inbound
//! calls: plain BL at 0x0810ef80 and BLNE at 0x0812e378.
//!
//! Snapshot the signed count at owner word 2. Fetch each entry from the
//! embedded observable array at word 1, then call stock entry cleanup at
//! 0x0810f92c. Cleanup returns zero for type 3 (retain), and nonzero after
//! releasing other entries, including NULL (erase). Erasure decrements the
//! local count without advancing the index; its return value is ignored.
//!
//! No target algorithm deviations. Host tests inject array/cleanup operations
//! into the same loop: the stock cleanup seam is unavailable on the host.

#[cfg(target_os = "none")]
use crate::cxx::{array_element_at::{array_element_at, StridedArray},
    observable_array::{observable_array_erase_at, ObservableArray}};

#[inline(always)]
fn prune_with(mut remaining: i32, mut cleanup_at: impl FnMut(i32) -> u32,
    mut erase_at: impl FnMut(i32)) {
    let mut index = 0i32;
    while index < remaining {
        if cleanup_at(index) == 0 {
            index = index.wrapping_add(1);
        } else {
            erase_at(index);
            remaining = remaining.wrapping_sub(1);
        }
    }
}

/// Prune all entries except those retained by stock entry cleanup.
///
/// # Safety
/// `owner` must be an aligned retailOS owner whose embedded array at +4
/// satisfies both array helpers' contracts. Entries must satisfy cleanup
/// at 0x0810f92c. Callbacks must preserve the array except for its erasure.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn entry_collection_prune(owner: *mut u32) {
    #[cfg(target_os = "none")]
    {
        let remaining = owner.add(2).read();
        let array = owner.add(1);
        let cleanup: unsafe extern "C" fn(*mut u32, u32) -> u32 =
            core::mem::transmute(0x0810_f92cusize);
        prune_with(remaining as i32, |index| {
            let slot = array_element_at(array.cast::<StridedArray>(), index);
            cleanup(owner, (slot as *const u32).read())
        }, |index| {
            let _ = observable_array_erase_at(array.cast::<ObservableArray>(), index);
        });
    }
    #[cfg(not(target_os = "none"))]
    {
        let _ = owner;
        panic!("entry_collection_prune requires retailOS cleanup at 0x0810f92c");
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::prune_with;
    use std::{cell::RefCell, vec, vec::Vec};

    #[test]
    fn mixed_entries_revisit_shifted_index_and_preserve_retained_order() {
        let entries = RefCell::new(vec![0u32, 3, 1, 2, 3, 4]);
        let visits = RefCell::new(Vec::new());
        let erasures = RefCell::new(Vec::new());
        prune_with(6, |index| {
            let entry = entries.borrow()[index as usize];
            visits.borrow_mut().push((index, entry));
            u32::from(entry != 3)
        }, |index| {
            erasures.borrow_mut().push(index);
            entries.borrow_mut().remove(index as usize);
        });
        assert_eq!(*entries.borrow(), [3, 3]);
        assert_eq!(*visits.borrow(), [(0, 0), (0, 3), (1, 1), (1, 2), (1, 3), (2, 4)]);
        assert_eq!(*erasures.borrow(), [0, 1, 1, 2]);
    }

    #[test]
    fn signed_nonpositive_count_never_accesses_array() {
        for count in [i32::MIN, -1, 0] {
            prune_with(count, |_| panic!("unexpected lookup"), |_| panic!("unexpected erase"));
        }
    }

    #[test]
    fn all_retained_and_all_removed() {
        let mut visits = Vec::new();
        prune_with(3, |index| { visits.push(index); 0 }, |_| panic!("retained entry erased"));
        assert_eq!(visits, [0, 1, 2]);
        visits.clear();
        let mut erasures = Vec::new();
        prune_with(3, |index| { visits.push(index); 7 }, |index| erasures.push(index));
        assert_eq!(visits, [0, 0, 0]);
        assert_eq!(erasures, [0, 0, 0]);
    }
}
