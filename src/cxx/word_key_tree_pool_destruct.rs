//! Word-key red-black-tree pool destructor, `FUN_082a8418` @ `0x082a8418`.
//!
//! Raw A32: 88 bytes, ending immediately before the next prologue at
//! `0x082a8470`; two plain BLs (0x082a844c, 0x082a8464), zero predicated
//! BLs. Two inbound plain BLs occur at 0x0819f228 and 0x0819fd10.
//! With a non-null header, erase [header->left, header) through the
//! type-specific range helper at 0x083bfa44, reload the header, prepend it
//! to the recycle chain at tree word 1 using header word 3, then release
//! the pool through 0x083bf5a0. A null header skips all cleanup. Return tree.
//! Deliberate deviations: Rust locals replace stack iterator slots; target
//! pointer fields remain u32 on hosts. Unported helpers remain verified
//! retail address seams, with private injected operations for host tests.
//! Ghidra's extra arguments and u64 return are stack-save artifacts: the
//! original restores r1-r3 and returns the input in r0.

type EraseRange = unsafe extern "C" fn(*mut u32, *mut u32, *mut u32, *mut u32) -> *mut u32;
type ReleasePool = unsafe extern "C" fn(*mut u32);

#[cfg(target_os = "none")]
unsafe extern "C" fn erase_range(out: *mut u32, tree: *mut u32, first: *mut u32, last: *mut u32) -> *mut u32 {
    let erase: EraseRange = unsafe { core::mem::transmute(0x083b_fa44usize) };
    unsafe { erase(out, tree, first, last) }
}
#[cfg(target_os = "none")]
unsafe extern "C" fn release_pool(tree: *mut u32) {
    let release: ReleasePool = unsafe { core::mem::transmute(0x083b_f5a0usize) };
    unsafe { release(tree) }
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn erase_range(_: *mut u32, _: *mut u32, _: *mut u32, _: *mut u32) -> *mut u32 {
    panic!("word_key_tree_pool_destruct requires retail erase operation")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn release_pool(_: *mut u32) {
    panic!("word_key_tree_pool_destruct requires retail pool operation")
}

/// Destroys the tree's contents and pool, returning its original address.
///
/// # Safety
/// `tree` must contain at least five aligned target-width words. Its header
/// and pool must satisfy the retail helpers' ownership contracts. This is
/// terminal cleanup: the header field is not cleared and must not be reused.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn word_key_tree_pool_destruct(tree: *mut u32) -> *mut u32 {
    unsafe { destruct_with(tree, erase_range, release_pool) }
}

unsafe fn destruct_with(tree: *mut u32, erase: EraseRange, release: ReleasePool) -> *mut u32 {
    let mut header = unsafe { tree.add(4).read() };
    if header != 0 {
        let mut first = unsafe { (header as usize as *const u32).add(2).read() };
        let mut out = core::mem::MaybeUninit::<u32>::uninit();
        unsafe { erase(out.as_mut_ptr(), tree, &mut first, &mut header) };
        let header = unsafe { tree.add(4).read() };
        unsafe {
            (header as usize as *mut u32).add(3).write(tree.add(1).read());
            tree.add(1).write(header);
            release(tree);
        }
    }
    tree
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::LazyLock;
    use parking_lot::Mutex;
    static LOCK: Mutex<()> = Mutex::new(());
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        crate::testing::try_map_u32_slab(crate::testing::hints::WORD_KEY_TREE_POOL_DESTRUCT, 4096).map(|p| p as usize)
    });

    unsafe extern "C" fn forbidden_erase(_: *mut u32, _: *mut u32, _: *mut u32, _: *mut u32) -> *mut u32 {
        panic!("null header must skip erase")
    }
    unsafe extern "C" fn forbidden_release(_: *mut u32) { panic!("null header must preserve pool") }

    #[test]
    fn null_header_preserves_nonempty_pool_and_recycle_chain() {
        let mut tree = [0x1234, 0x5678, 9, 10, 0, 77];
        let before = tree;
        let ptr = tree.as_mut_ptr();
        assert_eq!(unsafe { destruct_with(ptr, forbidden_erase, forbidden_release) }, ptr);
        assert_eq!(tree, before);
        assert_eq!(unsafe { word_key_tree_pool_destruct(ptr) }, ptr);
    }

    unsafe extern "C" fn clear_and_replace_header(out: *mut u32, tree: *mut u32, first: *mut u32, last: *mut u32) -> *mut u32 {
        unsafe {
            let old = tree.add(4).read() as usize as *mut u32;
            assert_eq!(first.read(), old.add(2).read());
            assert_eq!(last.read(), old as usize as u32);
            let replacement = old.add(8);
            replacement.add(1).write(0);
            replacement.add(2).write(replacement as usize as u32);
            replacement.add(3).write(replacement as usize as u32);
            tree.add(4).write(replacement as usize as u32);
            tree.add(5).write(0);
            tree.add(1).write(0x8765);
            // Neither the input iterator slot nor the output is the new header.
            last.write(0x9999);
            out.write(0x8888);
            out
        }
    }
    unsafe extern "C" fn release_after_recycle(tree: *mut u32) {
        unsafe {
            let header = tree.add(4).read() as usize as *mut u32;
            assert_eq!(tree.add(1).read(), header as usize as u32);
            assert_eq!(header.add(3).read(), 0x8765);
            assert_eq!(tree.add(5).read(), 0);
            // Model terminal pool release; retain the recycle/header fields.
            tree.write(0);
        }
    }

    #[test]
    fn reloads_header_and_recycle_chain_after_erase_before_pool_release() {
        let _lock = LOCK.lock();
        let Some(slab) = *SLAB else {
            assert!(crate::testing::note_missing_u32_fixture("cxx::word_key_tree_pool_destruct"));
            return;
        };
        unsafe {
            let tree = slab as *mut u32;
            core::ptr::write_bytes(tree, 0, 64);
            let old = tree.add(16);
            tree.write(0x1234);
            tree.add(1).write(0x5678);
            tree.add(4).write(old as usize as u32);
            tree.add(5).write(3);
            old.add(2).write(old.add(4) as usize as u32);
            old.add(3).write(0xabcd);
            assert_eq!(destruct_with(tree, clear_and_replace_header, release_after_recycle), tree);
            assert_eq!(tree.read(), 0);
            assert_eq!(tree.add(4).read(), old.add(8) as usize as u32);
            assert_eq!(tree.add(1).read(), old.add(8) as usize as u32);
            assert_eq!(old.add(3).read(), 0xabcd);
        }
    }
}
