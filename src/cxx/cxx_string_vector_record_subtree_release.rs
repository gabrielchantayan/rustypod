//! Releases C++ string/vector records in a tree — retailOS `FUN_083c56b8` at
//! load address `0x083c56b8`.
//!
//! Raw `osos.dec` establishes the true 64-byte extent: sixteen ARM words from
//! `stmdb sp!, {r4,r5,r6,lr}` at `0x083c56b8` through `ldmia sp!, {r4,r5,r6,pc}`
//! at `0x083c56f4`; the next independently entered function starts at
//! `0x083c56f8`. Decoding every aligned A32 branch-immediate word finds two
//! plain `bl` calls, the recursive call at `0x083c56d0` and
//! [`cxx_string_vector_record_link`] at `0x083c56e4`; there are no predicated
//! `bl` calls.
//!
//! The function postorder-traverses each node's word-three subtree, snapshots
//! word two before releasing the current record, then advances through that
//! successor chain. Deliberate deviation: target links remain 32-bit words;
//! host tests map their fixtures below 4 GiB to preserve the retail layout.

use crate::cxx::string_vector_record_link::cxx_string_vector_record_link;

const NODE_NEXT: usize = 2;
const NODE_SUBTREE: usize = 3;

type RecordLink = unsafe extern "C" fn(*mut u8, *mut u8, i32);

#[inline(always)]
unsafe fn read_word(base: *const u8, word: usize) -> u32 {
    unsafe { (base.add(word * 4) as *const u32).read() }
}

/// Releases every record in `node`'s successor chain and nested subtrees.
///
/// Original: `FUN_083c56b8` at `0x083c56b8` (64 bytes; two unconditional
/// outbound plain `bl` calls, no predicated `bl` calls).
///
/// # Safety
///
/// `owner` must provide a writable target word at +0x04. Every reachable node
/// must provide valid target-width links at +0x08/+0x0c and storage suitable
/// for [`cxx_string_vector_record_link`] with teardown enabled.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.cxx_string_vector_record_subtree_release")]
#[inline(never)]
pub unsafe extern "C" fn cxx_string_vector_record_subtree_release(
    owner: *mut u8,
    mut node: *mut u8,
) {
    while !node.is_null() {
        let subtree = unsafe { read_word(node, NODE_SUBTREE) as usize as *mut u8 };
        unsafe { cxx_string_vector_record_subtree_release(owner, subtree) };
        let next = unsafe { read_word(node, NODE_NEXT) as usize as *mut u8 };
        unsafe { cxx_string_vector_record_link(owner, node, 1) };
        node = next;
    }
}
#[inline(always)]
unsafe fn cxx_string_vector_record_subtree_release_with(
    owner: *mut u8,
    mut node: *mut u8,
    record_link: RecordLink,
) {
    while !node.is_null() {
        let subtree = unsafe { read_word(node, NODE_SUBTREE) as usize as *mut u8 };
        unsafe { cxx_string_vector_record_subtree_release_with(owner, subtree, record_link) };
        let next = unsafe { read_word(node, NODE_NEXT) as usize as *mut u8 };
        unsafe { record_link(owner, node, 1) };
        node = next;
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, try_map_u32_slab};
    use core::sync::atomic::{AtomicUsize, Ordering};

    static CALLS: AtomicUsize = AtomicUsize::new(0);
    static ORDER: [AtomicUsize; 3] = [AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0)];

    unsafe extern "C" fn record_link(owner: *mut u8, record: *mut u8, teardown: i32) {
        let call = CALLS.fetch_add(1, Ordering::Relaxed);
        ORDER[call].store(record as usize, Ordering::Relaxed);
        assert_eq!(teardown, 1);
        unsafe { (owner.add(4) as *const u32).read() };
    }

    fn word(pointer: *mut u8) -> u32 {
        pointer as usize as u32
    }

    #[test]
    fn releases_subtrees_before_successors_and_snapshots_next() {
        let Some(slab) = try_map_u32_slab(hints::CXX_STRING_VECTOR_RECORD_SUBTREE_RELEASE, 0x1000) else {
            return;
        };
        unsafe {
            slab.write_bytes(0, 0x1000);
            let owner = slab.add(0x40);
            let first = slab.add(0x100);
            let subtree = slab.add(0x180);
            let successor = slab.add(0x200);
            (first.add(NODE_NEXT * 4) as *mut u32).write(word(successor));
            (first.add(NODE_SUBTREE * 4) as *mut u32).write(word(subtree));
            (subtree.add(NODE_NEXT * 4) as *mut u32).write(0);
            (subtree.add(NODE_SUBTREE * 4) as *mut u32).write(0);
            (successor.add(NODE_NEXT * 4) as *mut u32).write(0);
            (successor.add(NODE_SUBTREE * 4) as *mut u32).write(0);
            CALLS.store(0, Ordering::Relaxed);
            cxx_string_vector_record_subtree_release_with(owner, first, record_link);
            assert_eq!(CALLS.load(Ordering::Relaxed), 3);
            assert_eq!(ORDER[0].load(Ordering::Relaxed), subtree as usize);
            assert_eq!(ORDER[1].load(Ordering::Relaxed), first as usize);
            assert_eq!(ORDER[2].load(Ordering::Relaxed), successor as usize);
        }
    }

    #[test]
    fn leaves_owner_untouched_for_null_node() {
        let mut owner = [0u32; 2];
        CALLS.store(0, Ordering::Relaxed);
        unsafe { cxx_string_vector_record_subtree_release_with(owner.as_mut_ptr().cast(), core::ptr::null_mut(), record_link) };
        assert_eq!(CALLS.load(Ordering::Relaxed), 0);
    }
}
