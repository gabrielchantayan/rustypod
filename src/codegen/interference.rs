//! Code-generator interference-graph edge lists.
//!
//! The target's records use 32-bit pointer words, including on the host;
//! tests therefore map their fixtures below 4 GiB.

use crate::codegen::heap::{cg_heap_alloc, CgHeap};

/// cg_interference_edge_link — original: `FUN_082b2e98` @ 0x082b2e98
/// (80 bytes; 1 plain `bl`, no predicated `bl`; 4 plain incoming `bl`
/// call sites, no predicated incoming calls).
///
/// Treats word `+4` of `source` as an edge-list head and word `+4` of
/// `target` as the edge identity. Equal head identities return immediately.
/// Otherwise, if an edge with that identity already exists, it leaves the
/// list unchanged; a miss arena-allocates an 8-byte `{next, target_identity}`
/// edge and appends it. The raw body ends at the next real function boundary,
/// 0x082b2ee8.
///
/// Deliberate deviation: raw target pointers remain `u32` words rather than
/// host pointers, preserving target offsets on 64-bit test hosts.
///
/// # Safety
/// `heap` must be a valid [`CgHeap`]. `source`, `target`, and every existing
/// edge must be target-width records with readable words `+0` and `+4`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cg_interference_edge_link(
    heap: *mut CgHeap,
    source: *mut u32,
    target: *mut u32,
) {
    let target_identity = unsafe { target.add(1).read() };
    let mut edge_link = unsafe { source.add(1) };
    if unsafe { edge_link.read() } == target_identity {
        return;
    }

    loop {
        let edge = unsafe { edge_link.read() } as *mut u32;
        if edge.is_null() {
            let new_edge = unsafe { cg_heap_alloc(heap, 8).cast::<u32>() };
            unsafe {
                new_edge.write(0);
                new_edge.add(1).write(target_identity);
                edge_link.write(new_edge as u32);
            }
            return;
        }
        if unsafe { edge.add(1).read() } == target_identity {
            return;
        }
        edge_link = edge;
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;
    use std::boxed::Box;
    use std::sync::LazyLock;

    const SLAB_LEN: usize = 0x1000;
    const SOURCE: usize = 0x100;
    const TARGET: usize = 0x120;
    const FIRST_EDGE: usize = 0x200;
    const ARENA: usize = 0x400;
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::CG_INTERFERENCE_EDGE_LINK, SLAB_LEN).map(|p| p as usize)
    });
    static LOCK: Mutex<()> = Mutex::new(());

    unsafe fn fixture() -> Option<(*mut u32, *mut u32, CgHeap)> {
        let base = (*SLAB)? as *mut u8;
        unsafe { base.write_bytes(0, SLAB_LEN) };
        let block = Box::into_raw(Box::new(crate::codegen::heap::CgHeapBlock {
            next: core::ptr::null_mut(),
            base: unsafe { base.add(ARENA) },
            total: SLAB_LEN - ARENA,
            current: 0,
        }));
        Some((
            unsafe { base.add(SOURCE).cast() },
            unsafe { base.add(TARGET).cast() },
            CgHeap { current: block, block_size: SLAB_LEN - ARENA },
        ))
    }

    #[test]
    fn adds_only_missing_edge_identities() {
        let _lock = LOCK.lock();
        let Some((source, target, mut heap)) = (unsafe { fixture() }) else {
            assert!(note_missing_u32_fixture("codegen/interference"));
            return;
        };
        unsafe {
            target.add(1).write(0xfeed_beef);
            let old_edge = ((*SLAB).unwrap() as *mut u8).add(FIRST_EDGE).cast::<u32>();
            old_edge.write(0);
            old_edge.add(1).write(7);
            source.add(1).write(old_edge as u32);

            cg_interference_edge_link(&mut heap, source, target);
            let added = old_edge.read() as *mut u32;
            assert_ne!(added, old_edge);
            assert_eq!(source.add(1).read(), old_edge as u32);
            assert_eq!(added.read(), 0);
            assert_eq!(added.add(1).read(), 0xfeed_beef);

            let used = heap.current.as_ref().unwrap().current;
            cg_interference_edge_link(&mut heap, source, target);
            assert_eq!(heap.current.as_ref().unwrap().current, used);
            assert_eq!(source.add(1).read(), old_edge as u32);

            cg_interference_edge_link(&mut heap, source, source);
            assert_eq!(heap.current.as_ref().unwrap().current, used);
        }
    }
}
