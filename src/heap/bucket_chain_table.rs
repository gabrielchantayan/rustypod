//! `bucket_chain_table_destroy` — release every chain node, bucket array, and table.
//!
//! Original: `FUN_082d7bf0` @ 0x082d7bf0 (88 bytes exactly,
//! 0x082d7bf0..0x082d7c48; `FUN_082d7c48` begins at the next word). Raw ARM
//! has two plain `bl traced_free` instructions, no predicated `bl`, and a
//! final tail `b traced_free`; its three direct release transfers are the
//! source of Ghidra's three-call report.
//!
//! Algorithm: return for NULL; for each of the `bucket_count` heads in the
//! target-width bucket array, save each node's +0x04 next word before freeing
//! the node. Then free the bucket array and the table itself.
//!
//! Deliberate deviation: the retail final tail branch to `traced_free` is an
//! ordinary returning Rust call. `traced_free` returns normally, so this does
//! not change observable behavior.

use crate::drivers::ata_cmd::traced_free;

/// (88 bytes; 2 plain `bl`, 0 predicated `bl`, and 1 tail `b` release transfer.)
///
/// Destroys a target-layout chained bucket table. `table` is NULL or points to
/// at least four aligned target words: bucket-array pointer at +0x00 and
/// bucket count at +0x0c. Each non-NULL bucket entry is a node whose aligned
/// +0x04 word is the next node pointer. Every node, the bucket array, and the
/// table must belong to the `traced_free` allocation family.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn bucket_chain_table_destroy(table: *mut u32) {
    if table.is_null() {
        return;
    }

    let bucket_count = unsafe { table.add(3).read_volatile() };
    let buckets = unsafe { table.read_volatile() as usize as *mut u32 };
    let mut bucket_index = 0;
    while bucket_index < bucket_count {
        let mut node = unsafe { buckets.add(bucket_index as usize).read_volatile() as usize as *mut u32 };
        while !node.is_null() {
            let next = unsafe { node.add(1).read_volatile() as usize as *mut u32 };
            unsafe { traced_free(node.cast()) };
            node = next;
        }
        bucket_index += 1;
    }

    unsafe { traced_free(buckets.cast()) };
    unsafe { traced_free(table.cast()) };
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::drivers::ata_cmd::{TracedFreeHooks, TRACED_FREE_HOOKS};
    use crate::testing::TRACED_ALLOC_TEST_LOCK;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut FREED: Vec<usize> = Vec::new();

    unsafe extern "C" fn record_free(block: *mut u8) {
        unsafe { (*core::ptr::addr_of_mut!(FREED)).push(block as usize) };
    }

    fn install() -> (MutexGuard<'static, ()>, MutexGuard<'static, ()>, TracedFreeHooks) {
        let alloc_guard = TRACED_ALLOC_TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let guard = TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        unsafe {
            let old = core::ptr::read_volatile(core::ptr::addr_of!(TRACED_FREE_HOOKS));
            TRACED_FREE_HOOKS = TracedFreeHooks { free: record_free, trace: None };
            (*core::ptr::addr_of_mut!(FREED)).clear();
            (guard, alloc_guard, old)
        }
    }

    unsafe fn restore(guard: MutexGuard<'static, ()>, alloc_guard: MutexGuard<'static, ()>, old: TracedFreeHooks) {
        unsafe { TRACED_FREE_HOOKS = old };
        drop(guard);
        drop(alloc_guard);
    }

    fn try_slab() -> Option<*mut u8> {
        static SLAB: std::sync::LazyLock<Option<usize>> = std::sync::LazyLock::new(|| {
            crate::testing::try_map_u32_slab(crate::testing::hints::BUCKET_CHAIN_TABLE_DESTROY, 0x1000)
                .map(|pointer| pointer as usize)
        });
        (*SLAB).map(|pointer| pointer as *mut u8)
    }

    #[test]
    fn null_table_does_not_free() {
        let (guard, alloc_guard, old) = install();
        unsafe { bucket_chain_table_destroy(core::ptr::null_mut()) };
        assert!(unsafe { (*core::ptr::addr_of!(FREED)).is_empty() });
        unsafe { restore(guard, alloc_guard, old) };
    }

    #[test]
    fn releases_each_chain_in_bucket_order_then_bucket_array_and_table() {
        let Some(slab) = try_slab() else { return };
        let (guard, alloc_guard, old) = install();
        let buckets = slab.cast::<u32>();
        let first = unsafe { slab.add(0x20).cast::<u32>() };
        let second = unsafe { slab.add(0x30).cast::<u32>() };
        let third = unsafe { slab.add(0x40).cast::<u32>() };
        unsafe {
            buckets.add(0).write(first as usize as u32);
            buckets.add(1).write(0);
            buckets.add(2).write(third as usize as u32);
            first.add(1).write(second as usize as u32);
            second.add(1).write(0);
            third.add(1).write(0);
        }
        let mut table = [buckets as usize as u32, 0x1111_1111, 0x2222_2222, 3];

        unsafe { bucket_chain_table_destroy(table.as_mut_ptr()) };

        assert_eq!(unsafe { (*core::ptr::addr_of!(FREED)).as_slice() }, &[first as usize, second as usize, third as usize, buckets as usize, table.as_ptr() as usize]);
        assert_eq!(table[1..], [0x1111_1111, 0x2222_2222, 3], "only +0x00 and +0x0c are read");
        unsafe { restore(guard, alloc_guard, old) };
    }
}
