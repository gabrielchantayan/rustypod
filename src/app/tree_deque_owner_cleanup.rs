//! Enabled tree/deque owner cleanup — `FUN_0815aa00` @ **0x0815aa00**.
//! Raw extent: **132 bytes**, [0x0815aa00,0x0815aa84), ending in pop
//! before the next independent push. Two inbound plain BLs (0x0815b0f8,
//! 0x0815ba80), five outbound plain BLs, zero predicated BLs.
//!
//! If byte +0x5a is nonzero, erase [header.left, header) from the tree
//! at +0x84, drain the deque at +0xa0, then destroy and delete the optional
//! file record at +0xcc. Neither the enable byte nor the record slot is cleared.
//! Deliberate deviations: Rust omits redundant stack copies of the iterators;
//! two unported collection operations use literal retail veneers on ARM and
//! explicit host fixtures. Already ported emptiness, destruction and deletion
//! remain direct calls. No more specific owner class identity is asserted.

use crate::cxx::templates::container_is_empty;
use crate::app::vtable_set::vtable_file_record_destruct;
use crate::heap::veneers::operator_delete;

#[cfg(target_os = "none")]
extern "C" {
    fn owner_tree_erase_range(result: *mut u32, tree: *mut u8, first: *mut u32, last: *mut u32);
    fn owner_deque_pop(owner: *mut u8);
}

#[cfg(target_os = "none")]
core::arch::global_asm!(r#"
    .syntax unified
    .arm
    .text
    .p2align 2
owner_tree_erase_range:
    ldr pc, [pc, #-4]
    .word 0x083c3bd8
owner_deque_pop:
    ldr pc, [pc, #-4]
    .word 0x0815b850
"#);

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct OwnerCollectionCleanupOps {
    pub erase_range: unsafe extern "C" fn(*mut u32, *mut u8, *mut u32, *mut u32),
    pub pop: unsafe extern "C" fn(*mut u8),
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_erase(_: *mut u32, _: *mut u8, _: *mut u32, _: *mut u32) {
    panic!("tree_deque_owner_cleanup requires a tree fixture")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_pop(_: *mut u8) {
    panic!("tree_deque_owner_cleanup requires a deque fixture")
}
#[cfg(not(target_os = "none"))]
pub static mut OWNER_COLLECTION_CLEANUP_OPS: OwnerCollectionCleanupOps =
    OwnerCollectionCleanupOps { erase_range: missing_erase, pop: missing_pop };

/// Clear enabled owner collections and release its optional file record.
///
/// # Safety
/// `owner` is aligned target-layout storage through +0xcf. When enabled,
/// +0x94 holds a valid tree header, collection operations must be configured
/// on hosts, and +0xcc is NULL or a valid heap-owned file record. Like retail,
/// this does not clear the freed slot and must not be repeated on that slot.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn tree_deque_owner_cleanup(owner: *mut u8) {
    if owner.add(0x5a).read() == 0 { return; }
    let mut last = owner.add(0x94).cast::<u32>().read();
    let mut first = (last as usize as *const u32).add(2).read();
    let mut result = 0u32;
    #[cfg(not(target_os = "none"))]
    let ops = core::ptr::read_volatile(core::ptr::addr_of!(OWNER_COLLECTION_CLEANUP_OPS));
    #[cfg(target_os = "none")]
    owner_tree_erase_range(&mut result, owner.add(0x84), &mut first, &mut last);
    #[cfg(not(target_os = "none"))]
    (ops.erase_range)(&mut result, owner.add(0x84), &mut first, &mut last);
    while container_is_empty(owner.add(0xa0)) == 0 {
        #[cfg(target_os = "none")]
        owner_deque_pop(owner);
        #[cfg(not(target_os = "none"))]
        (ops.pop)(owner);
    }
    let record = owner.add(0xcc).cast::<u32>().read() as usize as *mut u8;
    if !record.is_null() {
        operator_delete(vtable_file_record_destruct(record));
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::Mutex;
    static LOCK: Mutex<()> = Mutex::new(());

    unsafe extern "C" fn erase(result: *mut u32, tree: *mut u8, first: *mut u32, last: *mut u32) {
        let header = tree.add(0x10).cast::<u32>().read();
        assert_eq!(last.read(), header);
        assert_eq!(first.read(), (header as usize as *const u32).add(2).read());
        // Model the full-range erase's externally visible empty tree state.
        let node = header as usize as *mut u32;
        node.add(1).write(0);
        node.add(2).write(header);
        node.add(3).write(header);
        tree.add(0x14).cast::<u32>().write(0);
        result.write(header);
    }
    unsafe extern "C" fn pop(owner: *mut u8) {
        // The loop must observe the changed count, and must erase before pop.
        assert_eq!(owner.add(0x98).cast::<u32>().read(), 0);
        let count = owner.add(0xc0).cast::<u32>();
        assert_ne!(count.read(), 0);
        count.write(count.read() - 1);
    }

    #[test]
    fn disabled_owner_does_not_dereference_invalid_members() {
        let mut owner = [0xffff_ffffu32; 52];
        unsafe {
            let p = owner.as_mut_ptr().cast::<u8>();
            p.add(0x5a).write(0);
            let before = owner;
            tree_deque_owner_cleanup(p);
            assert_eq!(owner, before);
        }
    }

    #[test]
    fn enabled_cleanup_erases_before_draining_zero_one_and_many_items() {
        let _guard = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some(p) = crate::testing::try_map_u32_slab(
            crate::testing::hints::TREE_DEQUE_OWNER_CLEANUP, 4096) else { return; };
        unsafe {
            let saved = OWNER_COLLECTION_CLEANUP_OPS;
            OWNER_COLLECTION_CLEANUP_OPS = OwnerCollectionCleanupOps { erase_range: erase, pop };
            let header = p.add(0x100).cast::<u32>();
            for count in [0, 1, 7] {
                p.cast::<u32>().write_bytes(0, 52);
                p.add(0x5a).write(0x80);
                p.add(0x94).cast::<u32>().write(header as usize as u32);
                p.add(0x98).cast::<u32>().write(3);
                p.add(0xc0).cast::<u32>().write(count);
                header.add(1).write(123);
                header.add(2).write(456);
                header.add(3).write(789);
                tree_deque_owner_cleanup(p);
                assert_eq!(p.add(0xc0).cast::<u32>().read(), 0);
                assert_eq!(p.add(0x98).cast::<u32>().read(), 0);
                assert_eq!(header.add(1).read(), 0);
                assert_eq!(header.add(2).read(), header as usize as u32);
                assert_eq!(header.add(3).read(), header as usize as u32);
                assert_eq!(p.add(0x5a).read(), 0x80);
            }
            OWNER_COLLECTION_CLEANUP_OPS = saved;
        }
    }
}
