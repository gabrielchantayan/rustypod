//! Basic-block successor-list construction.

use super::heap::{cg_heap_alloc, CgHeap};
use super::ir::{record_size, CgBlock, CG_BLOCK_PROC, CG_MODULE_HEAP, CG_PROC_MODULE};

/// `cg_block_successor_prepend` — original `FUN_082b2f60` @ 0x082b2f60.
/// True extent: 52 bytes, ending at the next function at 0x082b2f94.
/// Raw-word scan: two plain incoming BLs, no predicated incoming BLs;
/// the body has one plain BL to `cg_heap_alloc`, no predicated BLs.
///
/// Resolves source -> procedure -> module -> heap, allocates an eight-byte
/// `{next, successor}` cell, stores the successor then the previous head,
/// and publishes the cell at source +0x28. No deduplication or null checks.
/// Callers in 0x082c1ddc add explicit branch targets and fall-through blocks;
/// its later fixed-point loop consumes this list for live-out propagation.
/// Deliberate deviation: pointer words and the cell allocation expand to
/// native pointer width on hosts, following the existing IR layout convention.
///
/// # Safety
/// `source` must have eleven writable pointer words and a valid procedure ->
/// module -> heap chain. The heap must have enough capacity or valid allocator
/// operations. `successor` is stored without dereferencing it.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cg_block_successor_prepend(source: *mut CgBlock, successor: *mut CgBlock) {
    let source = source.cast::<*mut u8>();
    let proc = source.add(CG_BLOCK_PROC).read().cast::<*mut u8>();
    let module = proc.add(CG_PROC_MODULE).read().cast::<*mut u8>();
    let heap = module.add(CG_MODULE_HEAP).read().cast::<CgHeap>();
    let cell = cg_heap_alloc(heap, record_size(8)).cast::<*mut u8>();
    cell.add(1).write(successor.cast());
    cell.write(source.add(10).read());
    source.add(10).write(cell.cast());
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::heap::CgHeapBlock;

    #[test]
    fn prepends_null_self_and_duplicate_targets_without_changing_old_cells() {
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
        let mut source = [0usize; 11];
        source[CG_BLOCK_PROC] = proc.as_mut_ptr() as usize;
        let source_ptr = source.as_mut_ptr().cast::<CgBlock>();
        let mut previous = core::ptr::null_mut::<usize>();
        let targets = [core::ptr::null_mut(), source_ptr, source_ptr];
        for (index, target) in targets.into_iter().enumerate() {
            unsafe {
                cg_block_successor_prepend(source_ptr, target);
                let head = source[10] as *mut usize;
                assert_eq!(head, arena.as_mut_ptr().add(index * 2));
                assert_eq!(head.read(), previous as usize);
                assert_eq!(head.add(1).read(), target as usize);
                previous = head;
            }
        }
        unsafe {
            let newest = source[10] as *mut usize;
            let middle = newest.read() as *mut usize;
            let oldest = middle.read() as *mut usize;
            assert_eq!(middle.add(1).read(), source_ptr as usize);
            assert_eq!(oldest.add(1).read(), 0);
            assert_eq!(oldest.read(), 0);
        }
        assert_eq!(heap_block.current, record_size(8) * 3);
        assert_eq!(source[CG_BLOCK_PROC], proc.as_mut_ptr() as usize);
        assert!(source[2..10].iter().all(|&word| word == 0));
    }
}
