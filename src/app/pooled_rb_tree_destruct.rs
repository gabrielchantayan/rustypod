//! Pooled red-black tree destructor, original `FUN_082a7ec8` @ 0x082a7ec8.
//!
//! Raw extent: 136 bytes, 0x082a7ec8..0x082a7f4f; the next prologue is
//! 0x082a7f50. Three plain internal BLs, zero predicated BLs; two plain
//! inbound BLs at 0x08124f40 and 0x0812529c, zero predicated inbound BLs.
//! Erase [header->left, header), reload and prepend the header to the
//! recycled-node list, then unlink each pool chunk before freeing its block
//! and the chunk itself. A null header preserves all owner fields.
//!
//! Deliberate deviations: scratch r1/r2/r3 saves are not arguments or a
//! double-word result; return only the owner in r0. Target pointers remain
//! aligned u32 words. Share the identical teardown algorithm with the
//! 0x082a8280 specialization, but retain the verified, unnamed 0x083bc500
//! erase address seam. Host tests inject the erase/deallocation boundary.

use super::pooled_tree_destruct::destruct_with;

type EraseRange = unsafe extern "C" fn(*mut u32, *mut u32, *mut u32, *mut u32);

#[cfg(target_os = "none")]
unsafe extern "C" fn erase_range(out: *mut u32, tree: *mut u32, first: *mut u32, last: *mut u32) {
    let erase: EraseRange = unsafe { core::mem::transmute(0x083b_c500usize) };
    unsafe { erase(out, tree, first, last) };
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn erase_range(_: *mut u32, _: *mut u32, _: *mut u32, _: *mut u32) {
    panic!("stock pooled RB-tree erase requires firmware");
}

/// # Safety
/// `tree` is an aligned six-word firmware owner with valid target-width
/// header and chunk pointers, owned by the firmware allocator.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn pooled_rb_tree_destruct(tree: *mut u32) -> *mut u32 {
    unsafe { destruct_with(tree, erase_range, crate::heap::veneers::cxx_array_dealloc) }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use parking_lot::Mutex;
    static EVENTS: Mutex<std::vec::Vec<(usize, usize, usize)>> = Mutex::new(std::vec::Vec::new());
    static OWNER: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

    unsafe extern "C" fn erase(out: *mut u32, tree: *mut u32, first: *mut u32, last: *mut u32) {
        unsafe {
            assert_eq!(first.read(), tree.add(40) as usize as u32);
            assert_eq!(last.read(), tree.add(32) as usize as u32);
            tree.add(4).write(tree.add(48) as usize as u32);
            tree.add(5).write(0);
            out.write(last.read());
        }
    }
    unsafe extern "C" fn free(ptr: *mut u8, count: usize, elem: usize) {
        // The owner must already point past the chunk being released.
        unsafe {
            let tree = OWNER.load(core::sync::atomic::Ordering::Relaxed) as *const u32;
            if count == 1 { assert_ne!(tree.read() as usize, ptr as usize); }
        }
        EVENTS.lock().push((ptr as usize, count, elem));
    }

    #[test]
    fn public_null_header_preserves_pool_and_returns_owner() {
        let mut tree = [0x1234, 0x5678, 9, 10, 0, 12];
        let before = tree;
        unsafe { assert_eq!(pooled_rb_tree_destruct(tree.as_mut_ptr()), tree.as_mut_ptr()); }
        assert_eq!(tree, before);
    }

    #[test]
    fn reloads_header_unlinks_chunks_and_releases_zero_capacity_block() {
        let Some(base) = crate::testing::try_map_u32_slab(crate::testing::hints::POOLED_RB_TREE_DESTRUCT, 0x1000) else {
            assert!(crate::testing::note_missing_u32_fixture("pooled_rb_tree_destruct")); return;
        };
        EVENTS.lock().clear();
        unsafe {
            let tree = base.cast::<u32>();
            OWNER.store(tree as usize, core::sync::atomic::Ordering::Relaxed);
            tree.write_bytes(0, 256);
            let old = tree.add(32);
            let new = tree.add(48);
            let a = tree.add(64);
            let b = tree.add(68);
            tree.write(a as usize as u32);
            tree.add(1).write(0x7654);
            tree.add(4).write(old as usize as u32);
            tree.add(5).write(2);
            old.add(2).write(tree.add(40) as usize as u32);
            a.write(b as usize as u32);
            a.add(1).write(7); a.add(2).write(tree.add(80) as usize as u32);
            b.write(0); b.add(1).write(0); b.add(2).write(0);
            let erase: EraseRange = erase;
            assert_eq!(destruct_with(tree, erase, free), tree);
            assert_eq!(tree.read(), 0);
            assert_eq!(tree.add(1).read(), new as usize as u32);
            assert_eq!(new.add(3).read(), 0x7654);
            assert_eq!(old.add(3).read(), 0);
            assert_eq!(tree.add(5).read(), 0);
            assert_eq!(*EVENTS.lock(), [(tree.add(80) as usize, 7, 0), (a as usize, 1, 0), (0, 0, 0), (b as usize, 1, 0)]);
        }
    }
}
