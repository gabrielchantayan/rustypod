//! Chained hash-table destructor — retailOS `FUN_083d3174` at load address
//! `0x083d3174` (152 bytes, `0x083d3174..0x083d320b`; the next independently
//! linked function begins at `0x083d320c`). Raw words verify two unconditional
//! `bl` instructions, both to `cxx_array_dealloc` @ `0x08266f2c`, and zero
//! predicated calls. Three unconditional inbound `bl` call sites were also
//! verified.
//!
//! The target-width table stores its bucket allocation at word 1, bucket count
//! at word 2, and the current bucket cursor at word 3. For each bucket below
//! `buckets + count * 4`, it clears the bucket then walks its intrusive chain.
//! Each chain node links through word 0 but was allocated 16 bytes before that
//! link, so it releases `node - 16`. It finally releases the bucket allocation
//! with `count + 1`, then returns the table. Deliberate deviation: target
//! pointers remain `u32` words instead of host pointers, preserving the ARM
//! layout on 64-bit host test builds.

use crate::heap::veneers::cxx_array_dealloc;

#[inline(always)]
unsafe fn word(base: *const u8, index: usize) -> u32 {
    core::ptr::read(base.add(index * 4).cast::<u32>())
}

#[inline(always)]
unsafe fn set_word(base: *mut u8, index: usize, value: u32) {
    core::ptr::write(base.add(index * 4).cast::<u32>(), value);
}

/// Releases every node chain and the bucket allocation of `table`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn hash_table_chain_destroy(table: *mut u8) -> *mut u8 {
    let buckets = word(table, 1) as usize as *mut u8;
    if buckets.is_null() {
        return table;
    }

    let bucket_count = word(table, 2) as usize;
    let end = buckets.add(bucket_count * 4);
    let mut bucket = word(table, 3) as usize as *mut u8;
    while bucket != end {
        let mut node = core::ptr::read(bucket.cast::<u32>()) as usize as *mut u8;
        core::ptr::write(bucket.cast::<u32>(), 0);
        while !node.is_null() {
            let next = core::ptr::read(node.cast::<u32>()) as usize as *mut u8;
            cxx_array_dealloc(node.sub(16), 1, 0);
            node = next;
        }
        bucket = bucket.add(4);
    }

    cxx_array_dealloc(buckets, bucket_count + 1, 0);
    table
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::veneers::tests::{free_log, mock_heap};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::LazyLock;

    const SLAB_LEN: usize = 0x1000;
    const TABLE: usize = 0;
    const BUCKETS: usize = 0x40;
    const NODE_A: usize = 0x110;
    const NODE_B: usize = 0x160;
    const NODE_C: usize = 0x1b0;
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::HASH_TABLE_CHAIN_DESTROY, SLAB_LEN).map(|pointer| pointer as usize)
    });

    unsafe fn fixture() -> Option<*mut u8> {
        let slab = (*SLAB)? as *mut u8;
        slab.write_bytes(0, SLAB_LEN);
        Some(slab)
    }

    unsafe fn put_word(base: *mut u8, offset: usize, value: *mut u8) {
        core::ptr::write(base.add(offset).cast::<u32>(), value as u32);
    }

    #[test]
    fn null_bucket_allocation_returns_without_freeing() {
        let _heap = mock_heap();
        let Some(slab) = (unsafe { fixture() }) else {
            assert!(note_missing_u32_fixture("util/hash_table_chain_destroy"));
            return;
        };
        let table = unsafe { slab.add(TABLE) };
        unsafe { put_word(table, 4, core::ptr::null_mut()) };

        assert_eq!(unsafe { hash_table_chain_destroy(table) }, table);
        assert_eq!(free_log().0, 0);
    }

    #[test]
    fn clears_every_bucket_and_releases_each_node_then_bucket_block() {
        let _heap = mock_heap();
        let Some(slab) = (unsafe { fixture() }) else {
            assert!(note_missing_u32_fixture("util/hash_table_chain_destroy"));
            return;
        };
        let table = unsafe { slab.add(TABLE) };
        let buckets = unsafe { slab.add(BUCKETS) };
        let node_a = unsafe { slab.add(NODE_A) };
        let node_b = unsafe { slab.add(NODE_B) };
        let node_c = unsafe { slab.add(NODE_C) };
        unsafe {
            put_word(table, 4, buckets);
            put_word(table, 8, 2usize as *mut u8);
            put_word(table, 12, buckets);
            put_word(buckets, 0, node_a);
            put_word(buckets, 4, node_c);
            put_word(node_a, 0, node_b);
            put_word(node_b, 0, core::ptr::null_mut());
            put_word(node_c, 0, core::ptr::null_mut());
        }

        assert_eq!(unsafe { hash_table_chain_destroy(table) }, table);
        assert_eq!(unsafe { core::ptr::read(buckets.cast::<u32>()) }, 0);
        assert_eq!(unsafe { core::ptr::read(buckets.add(4).cast::<u32>()) }, 0);
        let (calls, pointer, tag) = free_log();
        assert_eq!(calls, 4);
        assert_eq!(pointer, buckets);
        assert_eq!(tag, 2);
    }
}
