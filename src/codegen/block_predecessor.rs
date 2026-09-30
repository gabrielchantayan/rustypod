//! Basic-block predecessor-list construction.

use super::heap::{cg_heap_alloc, CgHeap};
use super::ir::{record_size, CgBlock, CG_BLOCK_PROC, CG_MODULE_HEAP, CG_PROC_MODULE};

/// `cg_block_predecessor_prepend` — original `FUN_082b2ee8` @ 0x082b2ee8.
/// True extent: 52 bytes, ending at the next function at 0x082b2f1c.
/// Raw-word scan: two plain incoming BLs, no predicated incoming BLs;
/// the body has one plain BL to `cg_heap_alloc`, no predicated BLs.
///
/// Resolves destination -> procedure -> module -> heap, allocates an
/// eight-byte `{next, predecessor}` cell, stores the predecessor then the
/// previous head, and publishes the cell at destination +0x24. The caller
/// at 0x082c1ddc pairs this with successor insertion for branch and
/// fall-through edges. No deduplication or null checks.
/// Deliberate deviation: pointer words and the cell allocation expand to
/// native pointer width on hosts, following the existing IR layout convention.
///
/// # Safety
/// `destination` must have ten writable pointer words and a valid procedure ->
/// module -> heap chain. The heap must have enough capacity or valid allocator
/// operations. `predecessor` is stored without dereferencing it.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cg_block_predecessor_prepend(destination: *mut CgBlock, predecessor: *mut CgBlock) {
    let destination = destination.cast::<*mut u8>();
    let proc = destination.add(CG_BLOCK_PROC).read().cast::<*mut u8>();
    let module = proc.add(CG_PROC_MODULE).read().cast::<*mut u8>();
    let heap = module.add(CG_MODULE_HEAP).read().cast::<CgHeap>();
    let cell = cg_heap_alloc(heap, record_size(8)).cast::<*mut u8>();
    cell.add(1).write(predecessor.cast());
    cell.write(destination.add(9).read());
    destination.add(9).write(cell.cast());
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::heap::CgHeapBlock;

    #[test]
    fn preserves_existing_chain_and_accepts_null_self_and_duplicate_predecessors() {
        let mut arena = [0xa5a5_a5a5usize; 16];
        let mut heap_block = CgHeapBlock {
            next: core::ptr::null_mut(),
            base: arena.as_mut_ptr().cast(),
            total: core::mem::size_of_val(&arena),
            current: 0,
        };
        let mut heap = CgHeap { current: &mut heap_block, block_size: heap_block.total };
        let mut module = [&mut heap as *mut CgHeap as usize];
        let mut proc = [0usize; 2];
        proc[CG_PROC_MODULE] = module.as_mut_ptr() as usize;
        let mut destination = [0x1234usize; 12];
        destination[CG_BLOCK_PROC] = proc.as_mut_ptr() as usize;
        let mut old_tail = [0usize, 0x5678];
        let mut old_head = [old_tail.as_mut_ptr() as usize, 0x9abc];
        destination[9] = old_head.as_mut_ptr() as usize;
        let before = destination;
        let destination_ptr = destination.as_mut_ptr().cast::<CgBlock>();
        let mut previous = old_head.as_mut_ptr();
        let targets = [core::ptr::null_mut(), destination_ptr, destination_ptr];
        for (index, target) in targets.into_iter().enumerate() {
            unsafe {
                cg_block_predecessor_prepend(destination_ptr, target);
                let head = destination[9] as *mut usize;
                assert_eq!(head, arena.as_mut_ptr().add(index * 2));
                assert_eq!(head.read(), previous as usize);
                assert_eq!(head.add(1).read(), target as usize);
                previous = head;
            }
        }
        unsafe {
            let newest = destination[9] as *mut usize;
            let middle = newest.read() as *mut usize;
            let oldest = middle.read() as *mut usize;
            assert_eq!(middle.add(1).read(), destination_ptr as usize);
            assert_eq!(oldest.add(1).read(), 0);
            assert_eq!(oldest.read(), old_head.as_mut_ptr() as usize);
        }
        assert_eq!(old_head, [old_tail.as_mut_ptr() as usize, 0x9abc]);
        assert_eq!(old_tail, [0, 0x5678]);
        assert_eq!(heap_block.current, record_size(8) * 3);
        for index in (0..9).chain(10..12) {
            assert_eq!(destination[index], before[index]);
        }
    }
}
