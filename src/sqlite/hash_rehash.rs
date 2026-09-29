//! Resizing SQLite's generic symbol-table hash — `rehash` from hash.c.
//!
//! - `hash_rehash` — original: `FUN_0836741c` @ 0x0836741c (164 bytes,
//!   0x0836741c..0x083674c0; **4 plain `bl`, 2 predicated `blgt`, and one
//!   indirect `blx`**, binary-scanned from `osos.dec`).
//!
//! `sqlite3HashInsert` grows this power-of-two bucket table by allocating a
//! zeroed `{count, chain}` array, then moves every insertion-order element to
//! the head of its new hash bucket. Allocation failure leaves the old table and
//! its chains untouched. Deliberate deviations: the stock `hashFunction`
//! dispatcher returns a firmware code address and is therefore represented by
//! a volatile callback seam for host tests; the other three direct callees are
//! already-ported Rust functions and are called directly.

use super::hash_clear::{Hash, HashElem};
use super::hash_function::{hash_function, HashFn};
use super::mem::{fault_begin_benign, fault_end_benign, sqlite3_malloc_zero};
use crate::heap::tracked::tracked_free;

#[repr(C)]
struct Bucket {
    count: u32,
    chain: *mut HashElem,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 8] = [0; core::mem::size_of::<Bucket>()];

/// Hash-function dispatcher used by [`hash_rehash`]. The retail dispatcher
/// returns a stock runtime address, which is callable only in the firmware.
pub static mut HASH_REHASH_DISPATCH: unsafe extern "C" fn(i32) -> HashFn = hash_function;

#[inline(always)]
unsafe fn hash_dispatch_op() -> unsafe extern "C" fn(i32) -> HashFn {
    core::ptr::read_volatile(core::ptr::addr_of!(HASH_REHASH_DISPATCH))
}

/// hash_rehash — original: `FUN_0836741c` @ 0x0836741c (164 bytes).
///
/// Allocate `bucket_count * 8` zeroed bytes, preserve the old table on
/// failure, then replace it and reinsert each `HashElem` from `hash.first` at
/// `hash(key, n_key) & (bucket_count - 1)`. `bucket_count` must be a positive
/// power of two; its raw ARM arithmetic intentionally has no validation.
///
/// # Safety
/// `hash` must point to a valid target-layout [`Hash`] whose insertion-order
/// chain and bucket allocation are live. Every element key must be valid for
/// the selected hash function.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn hash_rehash(hash: *mut Hash, bucket_count: i32) {
    if ((*hash).htsize as i32) > 0 {
        fault_begin_benign(0);
    }
    let buckets = sqlite3_malloc_zero(bucket_count.wrapping_shl(3));
    if ((*hash).htsize as i32) > 0 {
        fault_end_benign(0);
    }
    if buckets.is_null() {
        return;
    }

    tracked_free((*hash).ht);
    (*hash).ht = buckets;
    (*hash).htsize = bucket_count as u32;
    let hash_fn = hash_dispatch_op()((*hash).key_class as i32);
    let mut elem = (*hash).first;
    (*hash).first = core::ptr::null_mut();
    while !elem.is_null() {
        let next = (*elem).next;
        let index = (hash_fn((*elem).key, (*elem).n_key) & (bucket_count as u32 - 1)) as usize;
        let bucket = buckets.cast::<Bucket>().add(index);
        (*elem).next = (*bucket).chain;
        if (*bucket).chain.is_null() {
            (*elem).next = (*hash).first;
            if !(*hash).first.is_null() {
                (*(*hash).first).prev = elem;
            }
            (*elem).prev = core::ptr::null_mut();
            (*hash).first = elem;
        } else {
            let head = (*bucket).chain;
            (*elem).next = head;
            (*elem).prev = (*head).prev;
            if (*head).prev.is_null() {
                (*hash).first = elem;
            } else {
                (*(*head).prev).next = elem;
            }
            (*head).prev = elem;
        }
        (*bucket).count = (*bucket).count.wrapping_add(1);
        (*bucket).chain = elem;
        elem = next;
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::heap::types::HeapDescriptorDescriptor;
    use crate::heap::veneers::{tests::mock_heap, HEAP_OPS};
    use std::boxed::Box;

    unsafe extern "C" fn test_dispatch(_: i32) -> HashFn { test_hash }
    unsafe extern "C" fn test_hash(_: *const u8, length: i32) -> u32 { length as u32 }
    unsafe extern "C" fn alloc(
        _heap: *mut HeapDescriptorDescriptor, size: usize, _tag: usize,
    ) -> *mut u8 {
        if size > 128 { return core::ptr::null_mut(); }
        let block = Box::new([0u8; 128]);
        Box::into_raw(block).cast::<u8>()
    }
    unsafe extern "C" fn free(_heap: *mut HeapDescriptorDescriptor, _ptr: *mut u8, _tag: usize) {}

    #[test]
    fn rebuilds_collision_chains_and_preserves_insertion_order() {
        let _heap = mock_heap();
        let saved_dispatch = unsafe { HASH_REHASH_DISPATCH };
        unsafe {
            HEAP_OPS.alloc = alloc; HEAP_OPS.free = free;
            HASH_REHASH_DISPATCH = test_dispatch;
            let mut nodes: [HashElem; 3] = core::mem::zeroed();
            let node_ptr = nodes.as_mut_ptr();
            nodes[0].n_key = 1;
            nodes[1].n_key = 1;
            nodes[2].n_key = 2;
            nodes[0].next = node_ptr.add(1);
            nodes[1].next = node_ptr.add(2);
            let mut hash: Hash = core::mem::zeroed();
            hash.key_class = 3;
            hash.count = 3;
            hash.first = node_ptr;
            hash_rehash(&mut hash, 4);
            let buckets = hash.ht.cast::<Bucket>();
            assert_eq!((*buckets.add(1)).count, 2);
            assert_eq!((*buckets.add(1)).chain, node_ptr.add(1));
            assert_eq!(nodes[1].next, node_ptr);
            assert_eq!(nodes[0].prev, node_ptr.add(1));
            assert_eq!((*buckets.add(2)).chain, node_ptr.add(2));
            assert_eq!(hash.first, node_ptr.add(2));
            HASH_REHASH_DISPATCH = saved_dispatch;
            assert_eq!(nodes[2].next, node_ptr.add(1));
            assert_eq!(nodes[1].prev, node_ptr.add(2));
        }
    }
}
