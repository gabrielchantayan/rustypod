//! `bucket_chain_destroy_node8` — retailOS `FUN_083d360c` at load address
//! `0x083d360c`.
//!
//! Load address: `0x083d360c`; true size: 152 bytes (`0x98`), from `push
//! {r4-r8,lr}` through `pop {r4-r8,pc}` at `0x083d36a0`; `push {r2,r3,lr}`
//! at `0x083d36a4` begins the next real function. Raw ARM decoding verifies
//! two outgoing unconditional plain `bl` instructions, both to
//! `cxx_array_dealloc` @ `0x08266f2c`, and zero predicated `bl` instructions.
//! Whole-image A32 decoding finds two inbound unconditional plain `bl` sites
//! (`0x0826f3b0`, `0x083d2e38`) and zero predicated inbound `bl` sites.
//!
//! The target-width owner stores its bucket allocation at word 1, bucket count
//! at word 2, and cursor at word 3. It clears every bucket at or below the
//! cursor and below `buckets + count * 4`, walks each word-0 intrusive chain,
//! and releases each node from `node - 8`. It then releases the bucket
//! allocation with `count + 1` and returns the owner.
//!
//! # Deliberate deviation
//!
//! Rust retains the owner and chain pointers as target-width `u32` words,
//! rather than host pointers, so host pointer width cannot alter ARM offsets.
//! The retail pointer-only loop between chain destruction and final release has
//! no memory side effect and is omitted.

use crate::heap::veneers::cxx_array_dealloc;

type ArrayDealloc = unsafe extern "C" fn(*mut u8, usize, usize);

#[inline(always)]
unsafe fn word(base: *const u8, index: usize) -> u32 {
    unsafe { core::ptr::read(base.add(index * 4).cast::<u32>()) }
}

#[inline(always)]
unsafe fn set_word(base: *mut u8, index: usize, value: u32) {
    unsafe { core::ptr::write(base.add(index * 4).cast::<u32>(), value) }
}

/// Releases every node chain and the bucket allocation of `owner`.
///
/// # Safety
///
/// `owner` must identify a writable target-layout owner whose non-null bucket
/// allocation and node links are valid as described in the module header.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.bucket_chain_destroy_node8")]
#[inline(never)]
pub unsafe extern "C" fn bucket_chain_destroy_node8(owner: *mut u8) -> *mut u8 {
    unsafe { bucket_chain_destroy_node8_with(owner, cxx_array_dealloc) }
}

#[inline(always)]
unsafe fn bucket_chain_destroy_node8_with(owner: *mut u8, dealloc: ArrayDealloc) -> *mut u8 {
    unsafe {
        let buckets = word(owner, 1) as usize as *mut u8;
        if buckets.is_null() {
            return owner;
        }

        let bucket_count = word(owner, 2) as usize;
        let end = buckets.add(bucket_count * 4);
        let mut bucket = word(owner, 3) as usize as *mut u8;
        while bucket != end {
            let mut node = core::ptr::read(bucket.cast::<u32>()) as usize as *mut u8;
            core::ptr::write(bucket.cast::<u32>(), 0);
            while !node.is_null() {
                let next = core::ptr::read(node.cast::<u32>()) as usize as *mut u8;
                dealloc(node.sub(8), 1, 0);
                node = next;
            }
            bucket = bucket.add(4);
        }
        dealloc(buckets, bucket_count + 1, 0);
        owner
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::testing::{hints, try_map_u32_slab};
    use parking_lot::Mutex;
    use std::vec::Vec;

    static DEALLOCATIONS: Mutex<Vec<(u32, usize, usize)>> = Mutex::new(Vec::new());
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    unsafe extern "C" fn record_dealloc(ptr: *mut u8, count: usize, element_size: usize) {
        DEALLOCATIONS.lock().push((ptr as usize as u32, count, element_size));
    }

    #[test]
    fn clears_each_bucket_releases_chains_then_releases_bucket_storage() {
        let Some(slab) = try_map_u32_slab(hints::BUCKET_CHAIN_DESTROY_NODE8, 0x400) else {
            return;
        };
        let _serial = TEST_LOCK.lock();
        let mut calls = DEALLOCATIONS.lock();
        calls.clear();
        drop(calls);

        unsafe {
            slab.write_bytes(0, 0x400);
            let buckets = slab.add(0x40);
            let first = slab.add(0x100);
            let second = slab.add(0x140);
            let third = slab.add(0x180);
            set_word(slab, 1, buckets as usize as u32);
            set_word(slab, 2, 2);
            set_word(slab, 3, buckets as usize as u32);
            core::ptr::write(buckets.cast::<u32>(), first as usize as u32);
            core::ptr::write(buckets.add(4).cast::<u32>(), third as usize as u32);
            core::ptr::write(first.cast::<u32>(), second as usize as u32);
            core::ptr::write(second.cast::<u32>(), 0);
            core::ptr::write(third.cast::<u32>(), 0);

            assert_eq!(bucket_chain_destroy_node8_with(slab, record_dealloc), slab);
            assert_eq!(core::ptr::read(buckets.cast::<u32>()), 0);
            assert_eq!(core::ptr::read(buckets.add(4).cast::<u32>()), 0);
        }

        assert_eq!(
            *DEALLOCATIONS.lock(),
            std::vec![
                (slab_addr(hints::BUCKET_CHAIN_DESTROY_NODE8, 0x100 - 8), 1, 0),
                (slab_addr(hints::BUCKET_CHAIN_DESTROY_NODE8, 0x140 - 8), 1, 0),
                (slab_addr(hints::BUCKET_CHAIN_DESTROY_NODE8, 0x180 - 8), 1, 0),
                (slab_addr(hints::BUCKET_CHAIN_DESTROY_NODE8, 0x40), 3, 0),
            ]
        );
    }

    #[test]
    fn null_bucket_allocation_returns_without_observing_other_owner_words() {
        let Some(slab) = try_map_u32_slab(hints::BUCKET_CHAIN_DESTROY_NODE8, 0x400) else {
            return;
        };
        let _serial = TEST_LOCK.lock();
        let mut calls = DEALLOCATIONS.lock();
        calls.clear();
        drop(calls);
        unsafe {
            set_word(slab, 1, 0);
            assert_eq!(bucket_chain_destroy_node8_with(slab, record_dealloc), slab);
        }
        assert!(DEALLOCATIONS.lock().is_empty());
    }

    fn slab_addr(hint: usize, offset: usize) -> u32 {
        (hint + offset) as u32
    }
}
