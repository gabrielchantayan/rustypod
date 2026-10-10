//! Bucket-chain visitor — `FUN_080846f4` @ **0x080846f4**, **104 bytes**
//! (`0x080846f4..0x0808475b`; next function starts at `0x0808475c`).
//! Raw A32 decoding: two inbound plain BLs at 0x082d7bcc/0x082d7be8,
//! zero predicated inbound BLs; zero outbound plain/predicated BLs and two
//! unconditional register BLX calls at 0x08084734/0x0808473c.
//!
//! Visits buckets in descending signed index order, following each chain in
//! forward order. Loads both value and successor before calling the selected
//! callback: mode zero takes one argument, every other mode takes context too.
//! Count is captured once; the bucket-array pointer is reloaded per bucket.
//! Deliberate deviations: none. Pointer slots remain four-byte firmware words.
//! ARM codegen review: LLVM emits 30 instructions versus the original's 26;
//! both retain signed bucket termination, four-byte indexing, cached successor,
//! and two register BLX callback sites. Differences are register/frame layout
//! and loop rotation, not traversal behavior.

pub type HashTableVisitCallback = unsafe extern "C" fn(u32);
pub type HashTableValueCallback = unsafe extern "C" fn(u32, u32);

/// `table` must be word-aligned with bucket pointer at +0 and count at +12.
/// Every visited bucket/node must be valid; nodes hold value and next at +0/+4.
/// The selected callback must be present. Callbacks may destroy the current
/// node, but must keep the cached successor and remaining table storage valid.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn hash_table_bucket_chain_visitor(
    table: *mut u8,
    mode: u32,
    mode_zero_callback: Option<HashTableVisitCallback>,
    callback: Option<HashTableValueCallback>,
    context: u32,
) {
    let table = table.cast::<u32>();
    let mut index = table.add(3).read().wrapping_sub(1) as i32;
    while index >= 0 {
        let buckets = table.read() as usize as *const u32;
        let mut node = buckets.add(index as usize).read();
        while node != 0 {
            let words = node as usize as *const u32;
            let value = words.read();
            let next = words.add(1).read();
            if mode == 0 {
                mode_zero_callback.unwrap_unchecked()(value);
            } else {
                callback.unwrap_unchecked()(value, context);
            }
            node = next;
        }
        index = index.wrapping_sub(1);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::LazyLock;
    use parking_lot::Mutex;
    use std::vec::Vec;

    static LOCK: Mutex<()> = Mutex::new(());
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        crate::testing::try_map_u32_slab(
            crate::testing::hints::HASH_TABLE_BUCKET_CHAIN_VISITOR, 0x1000,
        ).map(|p| p as usize)
    });
    static mut EVENTS: Vec<(u32, u32)> = Vec::new();
    static mut CURRENT_NODE: *mut u32 = core::ptr::null_mut();
    static mut TABLE: *mut u32 = core::ptr::null_mut();
    static mut REPLACEMENT_BUCKETS: u32 = 0;

    unsafe extern "C" fn record(value: u32) {
        (*core::ptr::addr_of_mut!(EVENTS)).push((value, 0));
    }
    unsafe extern "C" fn record_context(value: u32, context: u32) {
        (*core::ptr::addr_of_mut!(EVENTS)).push((value, context));
    }
    unsafe extern "C" fn mutate(value: u32) {
        record(value);
        if value == 30 {
            CURRENT_NODE.add(1).write(0);
            TABLE.write(REPLACEMENT_BUCKETS);
            TABLE.add(3).write(0);
        }
    }

    #[test]
    fn traverses_reverse_buckets_forward_chains_and_survives_callback_mutation() {
        let _lock = LOCK.lock();
        let Some(base) = *SLAB else {
            assert!(crate::testing::note_missing_u32_fixture("hash_table_bucket_chain_visitor"));
            return;
        };
        unsafe {
            let table = base as *mut u32;
            let buckets = table.add(8);
            let replacement = table.add(16);
            let nodes = table.add(24);
            nodes.write(30);
            nodes.add(1).write(nodes.add(2) as u32);
            nodes.add(2).write(31);
            nodes.add(3).write(0);
            nodes.add(4).write(10);
            nodes.add(5).write(0);
            nodes.add(6).write(11);
            nodes.add(7).write(0);
            buckets.write(nodes.add(4) as u32);
            buckets.add(1).write(0);
            buckets.add(2).write(nodes as u32);
            replacement.write(nodes.add(6) as u32);
            replacement.add(1).write(0);
            replacement.add(2).write(0);
            for mode in [0, 1, u32::MAX] {
                table.write(buckets as u32);
                table.add(3).write(3);
                (*core::ptr::addr_of_mut!(EVENTS)).clear();
                if mode == 0 {
                    crate::cxx::hash_table_visit::hash_table_visit(table.cast(), record);
                } else if mode == 1 {
                    crate::cxx::hash_table_visit_with_context::hash_table_visit_with_context(
                        table.cast(), record_context, u32::MAX,
                    );
                } else {
                    hash_table_bucket_chain_visitor(table.cast(), mode, None, Some(record_context), u32::MAX);
                }
                let context = if mode == 0 { 0 } else { u32::MAX };
                assert_eq!(*core::ptr::addr_of!(EVENTS), [(30, context), (31, context), (10, context)]);
            }
            TABLE = table;
            CURRENT_NODE = nodes;
            REPLACEMENT_BUCKETS = replacement as u32;
            (*core::ptr::addr_of_mut!(EVENTS)).clear();
            hash_table_bucket_chain_visitor(table.cast(), 0, Some(mutate), None, 0);
            assert_eq!(*core::ptr::addr_of!(EVENTS), [(30, 0), (31, 0), (11, 0)]);
        }
    }

    #[test]
    fn signed_decremented_count_skips_buckets_and_unused_callbacks() {
        let mut table = [0u32; 4];
        for count in [0, 0x8000_0001, u32::MAX] {
            table[3] = count;
            unsafe { hash_table_bucket_chain_visitor(table.as_mut_ptr().cast(), 0, None, None, 0) };
        }
        // A nonzero count with only empty buckets also needs no callback.
        let _lock = LOCK.lock();
        if let Some(base) = *SLAB {
            unsafe {
                let buckets = (base as *mut u32).add(8);
                buckets.write(0);
                table[0] = buckets as u32;
                table[3] = 1;
                hash_table_bucket_chain_visitor(table.as_mut_ptr().cast(), 7, None, None, 0);
            }
        }
    }
}
