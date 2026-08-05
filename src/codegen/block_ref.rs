//! Indirect basic-block references for the JIT IR.
//!
//! A branch instruction (`cg_create_inst_branch_label` /
//! `cg_create_inst_branch_cond`, kinds 7/8) does not point at its target
//! `cg_block_t` directly: its target field (`cg_inst_t + 0x0c`) points at
//! a one-word cell allocated from the procedure's arena, and the cell
//! holds the block pointer. The pipeline generators in
//! 0x0823a000-0x0826f5ff allocate the cell first, emit branches that
//! reference it, and only later create the target block
//! (`cg_block_create` @ 0x082c0d2c) and store it into the cell
//! (`*cell = block`) — a forward reference, so a branch can be emitted
//! before its destination block exists. The emitter resolves the
//! indirection when it patches code: `FUN_082c6430` reads
//! `*(cg_block_t **)inst->target` and takes the block's label (`+0x08`)
//! for `cg_label_add_fixup`.
//!
//! Ported here:
//!
//! - `cg_block_ref_create` — original: `FUN_082c0d6c` @ 0x082c0d6c
//!   (16 bytes; **43 `bl` call sites**). Allocates the 4-byte cell.

use super::heap::{cg_heap_alloc, CgHeap};
use super::ir::{record_size, CgBlock, CgProc, CG_MODULE_HEAP, CG_PROC_MODULE};

/// Address of a record's pointer-sized field at word index `index`.
#[inline(always)]
unsafe fn slot(record: *mut u8, index: usize) -> *mut *mut u8 {
    (record as *mut *mut u8).add(index)
}

/// Size of the reference cell in target bytes: one word holding a
/// `cg_block_t *`.
const CG_BLOCK_REF_BYTES: usize = 4;

/// cg_block_ref_create — original: `FUN_082c0d6c` @ 0x082c0d6c
/// (16 bytes, 43 `bl` call sites).
///
/// The whole body is four instructions:
///
/// ```text
/// ldr r0, [r0, #0x4]   // proc->module
/// mov r1, #0x4         // one word
/// ldr r0, [r0, #0x0]   // module->heap
/// b   0x082c1a08       // tail call cg_heap_alloc(heap, 4)
/// ```
///
/// Resolves the arena through the same `proc -> module -> heap` chain
/// `cg_virtual_reg_create` uses, then tail-calls the bump allocator for
/// a single word. The arena rounds the 4-byte request up to its 8-byte
/// granularity and zero-fills the carve, so a fresh cell reads as a NULL
/// block pointer until the generator back-patches it. The port calls the
/// already-ported [`cg_heap_alloc`] (0x082c1a08, codegen/heap.rs)
/// directly — no seam — and returns its result verbatim, exactly like
/// the original's tail branch.
///
/// Call-site evidence for the name: all 43 callers are pipeline
/// generators (0x0823fa7c, 0x082439b0, 0x08248728, 0x082498d4,
/// 0x0824a478, 0x0824af94); they pass the returned word as the `target`
/// of `cg_create_inst_branch_label` / `cg_create_inst_branch_cond` and
/// later store a freshly created `cg_block_t *` into it (e.g.
/// `082439b0`: `local_c0 = FUN_082c0d6c(iVar1);
/// FUN_082c1878(block, 0x25, local_c0); ... *local_c0 = new_block;`),
/// and the emitter `FUN_082c6430` dereferences it twice
/// (`*(cg_block_t **)target` then `block->label`) when scheduling the
/// branch fixup.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cg_block_ref_create(proc: *mut CgProc) -> *mut *mut CgBlock {
    let proc = proc as *mut u8;
    let module = slot(proc, CG_PROC_MODULE).read();
    let heap = slot(module, CG_MODULE_HEAP).read() as *mut CgHeap;
    cg_heap_alloc(heap, record_size(CG_BLOCK_REF_BYTES)) as *mut *mut CgBlock
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::super::heap::{
        cg_heap_create, cg_heap_destroy, CgHeap, CgHeapOps, CG_HEAP_OPS, DEFAULT_CG_HEAP_OPS,
    };
    use super::*;
    use std::alloc::{alloc as host_alloc_raw, dealloc as host_dealloc_raw, Layout};
    use std::sync::{Mutex, MutexGuard};

    static LOCK: Mutex<()> = Mutex::new(());

    /// Header the test allocator prepends so `free` can rebuild the layout.
    const HDR: usize = 16;

    /// Poisons every allocation, so the arena's zero-fill of the cell is
    /// actually observable.
    unsafe extern "C" fn poisoning_alloc(size: usize) -> *mut u8 {
        let raw = host_alloc_raw(Layout::from_size_align(size + HDR, 16).unwrap());
        assert!(!raw.is_null());
        (raw as *mut usize).write(size);
        core::ptr::write_bytes(raw.add(HDR), 0x5c, size);
        raw.add(HDR)
    }

    unsafe extern "C" fn poisoning_free(ptr: *mut u8) {
        let raw = ptr.sub(HDR);
        let size = (raw as *mut usize).read();
        host_dealloc_raw(raw, Layout::from_size_align(size + HDR, 16).unwrap());
    }

    /// A module and a procedure over one real arena.
    struct Fixture {
        heap: *mut CgHeap,
        module: [usize; 1],
        proc: [usize; 9],
    }

    impl Fixture {
        fn new(block_size: usize) -> std::boxed::Box<Fixture> {
            let heap = unsafe { cg_heap_create(block_size) };
            let mut f = std::boxed::Box::new(Fixture {
                heap,
                module: [0xdead_beef; 1],
                proc: [0xdead_beef; 9],
            });
            f.module[CG_MODULE_HEAP] = heap as usize;
            f.proc[CG_PROC_MODULE] = f.module.as_ptr() as usize;
            f
        }

        fn proc_ptr(&mut self) -> *mut CgProc {
            self.proc.as_mut_ptr() as *mut CgProc
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            unsafe { cg_heap_destroy(self.heap) };
        }
    }

    fn setup() -> MutexGuard<'static, ()> {
        let guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            core::ptr::addr_of_mut!(CG_HEAP_OPS).write(CgHeapOps {
                alloc: poisoning_alloc,
                free: poisoning_free,
                zero: DEFAULT_CG_HEAP_OPS.zero,
            });
        }
        guard
    }

    fn teardown() {
        unsafe { core::ptr::addr_of_mut!(CG_HEAP_OPS).write(DEFAULT_CG_HEAP_OPS) };
    }

    /// The heap resolution chain is `proc + 0x04` -> module, module
    /// `+ 0x00` -> heap: wiring the chain to this fixture's arena (and
    /// only through those two words) must be where the cell comes from,
    /// and the returned pointer must be exactly the arena's carve —
    /// forwarded verbatim, not recomputed.
    #[test]
    fn resolves_heap_through_proc_module_and_returns_the_carve_verbatim() {
        let _guard = setup();
        let mut f = Fixture::new(0x100);
        // A second arena the function must NOT touch: only the heap
        // reached through proc->module->heap may serve the request.
        let decoy = unsafe { cg_heap_create(0x100) };
        unsafe {
            let expected = (*(*f.heap).current).base.add((*(*f.heap).current).current);
            let cell = cg_block_ref_create(f.proc_ptr());
            assert_eq!(cell as *mut u8, expected);
            // The decoy arena is still empty.
            assert_eq!((*(*decoy).current).current, 0);
            cg_heap_destroy(decoy);
        }
        drop(f);
        teardown();
    }

    /// The original requests exactly 4 bytes (`mov r1, #0x4`); the arena
    /// rounds that to its 8-byte granularity, so two consecutive cells
    /// sit exactly one carve apart and nothing more is consumed.
    #[test]
    fn requests_one_word_rounded_to_the_arena_granularity() {
        let _guard = setup();
        let mut f = Fixture::new(0x100);
        unsafe {
            let first = cg_block_ref_create(f.proc_ptr());
            let second = cg_block_ref_create(f.proc_ptr());
            assert_eq!(second as usize - first as usize, 8);
            assert_eq!((*(*f.heap).current).current, 16);
        }
        drop(f);
        teardown();
    }

    /// The zero-fill inherited from `cg_heap_alloc` leaves a fresh cell
    /// reading as a NULL block pointer, and the cell is a usable word
    /// the generator can back-patch with the target block.
    #[test]
    fn cell_is_zero_filled_and_back_patchable() {
        let _guard = setup();
        let mut f = Fixture::new(0x100);
        let mut block = [0usize; 12];
        unsafe {
            let cell = cg_block_ref_create(f.proc_ptr());
            assert_eq!((*cell).is_null(), true);
            *cell = block.as_mut_ptr() as *mut CgBlock;
            assert_eq!(*cell, block.as_mut_ptr() as *mut CgBlock);
        }
        drop(f);
        teardown();
    }
}
