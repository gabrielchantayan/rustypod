//! Pooled RB-tree teardown.
//!
//! `FUN_082a8280` @ `0x082a8280`, 136 bytes, ending before the next
//! function at `0x082a8308`. Raw decoding verifies three unconditional
//! internal BL instructions and zero predicated BLs. Two unconditional
//! inbound BLs occur at `0x081e1608` and `0x081e1610`.
//!
//! With a non-null header, erase [header->left, header) through the
//! unported specialization at 0x083cdc44, reread and recycle the header,
//! then unlink and deallocate each chunk's block and the chunk itself.
//! A null header leaves the whole owner untouched. Return the owner.
//!
//! Deliberate deviations: Ghidra's extra arguments and double-word return
//! are scratch-stack artifacts; only the owner pointer is part of the ABI.
//! Iterator/result temporaries are explicit target words. The verified,
//! unnamed erase specialization stays an address seam; host tests inject
//! an erase model rather than calling firmware.

type EraseRange = unsafe extern "C" fn(*mut u32, *mut u32, *mut u32, *mut u32);
type Dealloc = unsafe extern "C" fn(*mut u8, usize, usize);

#[cfg(target_arch = "arm")]
unsafe extern "C" fn erase_range(out: *mut u32, tree: *mut u32, first: *mut u32, last: *mut u32) {
    let erase: EraseRange = unsafe { core::mem::transmute(0x083c_dc44usize) };
    unsafe { erase(out, tree, first, last) };
}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn erase_range(_: *mut u32, _: *mut u32, _: *mut u32, _: *mut u32) {
    panic!("stock tree erase requires ARM firmware");
}

/// # Safety
/// `tree` is an aligned six-word target owner; its header and chunk chain
/// must be valid for erase and deallocation. All stored pointers are u32.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn pooled_tree_destruct(tree: *mut u32) -> *mut u32 {
    unsafe { destruct_with(tree, erase_range, crate::heap::veneers::cxx_array_dealloc) }
}

pub(super) unsafe fn destruct_with(tree: *mut u32, erase: EraseRange, free: Dealloc) -> *mut u32 {
    let mut end = unsafe { tree.add(4).read() };
    if end != 0 {
        let mut first = unsafe { (end as usize as *const u32).add(2).read() };
        let mut out = core::mem::MaybeUninit::<u32>::uninit();
        unsafe { erase(out.as_mut_ptr(), tree, &mut first, &mut end) };
        let header = unsafe { tree.add(4).read() as usize as *mut u32 };
        unsafe {
            header.add(3).write(tree.add(1).read());
            tree.add(1).write(header as usize as u32);
        }
        loop {
            let chunk = unsafe { tree.read() as usize as *mut u32 };
            if chunk.is_null() { break; }
            unsafe {
                tree.write(chunk.read());
                free(chunk.add(2).read() as usize as *mut u8, chunk.add(1).read() as usize, 0);
                free(chunk.cast(), 1, 0);
            }
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
        crate::testing::try_map_u32_slab(crate::testing::hints::POOLED_TREE_DESTRUCT, 0x1000).map(|p| p as usize)
    });
    static EVENTS: Mutex<std::vec::Vec<(usize, usize, usize)>> = Mutex::new(std::vec::Vec::new());
    unsafe extern "C" fn erase(out: *mut u32, tree: *mut u32, first: *mut u32, last: *mut u32) {
        unsafe {
            assert_eq!(first.read(), tree.add(40) as usize as u32);
            assert_eq!(last.read(), tree.add(32) as usize as u32);
            // Exercise the required post-erase header reload and pool traversal.
            tree.add(4).write(tree.add(48) as usize as u32);
            tree.add(5).write(0);
            out.write(last.read());
        }
    }
    unsafe extern "C" fn free(block: *mut u8, count: usize, elem: usize) {
        EVENTS.lock().push((block as usize, count, elem));
    }
    unsafe extern "C" fn unexpected_erase(_: *mut u32, _: *mut u32, _: *mut u32, _: *mut u32) {
        panic!("null header must not erase");
    }
    #[test]
    fn null_header_preserves_nonempty_pool_and_recycle_list() {
        let mut tree = [0x1234, 0x5678, 9, 10, 0, 12];
        let before = tree;
        let _lock = LOCK.lock();
        EVENTS.lock().clear();
        unsafe { assert_eq!(destruct_with(tree.as_mut_ptr(), unexpected_erase, free), tree.as_mut_ptr()); }
        assert_eq!(tree, before);
        assert!(EVENTS.lock().is_empty());
    }
    #[test]
    fn reloads_header_and_releases_multiple_chunks_in_order() {
        let _lock = LOCK.lock();
        let Some(base) = *SLAB else { assert!(crate::testing::note_missing_u32_fixture("pooled_tree_destruct")); return; };
        EVENTS.lock().clear();
        unsafe {
            let tree = base as *mut u32;
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
