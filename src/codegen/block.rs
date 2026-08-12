//! Basic-block construction for the JIT IR.
//!
//! A procedure owns its blocks as an intrusive FIFO list: the head lives
//! at `proc + 0x08`, and the tail at `proc + 0x0c`. Each 0x30-byte
//! `cg_block_t` starts with its `next` pointer, back-points to its owner
//! procedure at `+0x04`, and carries its caller-selected block kind at
//! `+0x2c`.

use super::heap::{cg_heap_alloc, CgHeap};
use super::ir::{
    record_size, CgBlock, CgProc, CG_BLOCK_NEXT, CG_BLOCK_PROC, CG_MODULE_HEAP, CG_PROC_BLOCKS,
    CG_PROC_MODULE,
};

/// Size of `cg_block_t` in target bytes: the allocator request in
/// `FUN_082c0d2c` is `mov r1, #0x30`.
const CG_BLOCK_BYTES: usize = 0x30;
/// `cg_proc_t + 0x0c` — tail of the procedure's intrusive block list.
const CG_PROC_LAST_BLOCK: usize = 3;
/// `cg_block_t + 0x2c` — caller-selected block kind.
const CG_BLOCK_KIND: usize = 0x2c / 4;

/// Address of a record's pointer-sized field at word index `index`.
#[inline(always)]
unsafe fn slot(record: *mut u8, index: usize) -> *mut *mut u8 {
    (record as *mut *mut u8).add(index)
}

/// Address of a record's word-sized scalar field at word index `index`.
#[inline(always)]
unsafe fn word(record: *mut u8, index: usize) -> *mut usize {
    (record as *mut usize).add(index)
}

/// cg_block_create — retailOS `FUN_082c0d2c` @ `0x082c0d2c` (64 bytes;
/// 66 `bl` call sites).
///
/// Allocates a 0x30-byte `cg_block_t` from `proc->module->heap`, appends
/// it to the procedure's intrusive singly linked block list, then writes
/// the block's owner back-pointer and caller-selected `kind`. The original
/// relies on [`cg_heap_alloc`]'s zero-fill to leave the fresh block's
/// `next` pointer NULL; this port does not write it. The list stores both
/// head and tail, so an empty append assigns both to the new block while a
/// non-empty append preserves the head and writes the old tail's `next`.
///
/// Call-site identification: pipeline generators pass the returned record
/// to the instruction factories and store it through `cg_block_ref_create`
/// cells for forward branches. The second argument is a small block-kind
/// enum (observed values include 1, 2, 3, 4, 5, and 9), stored verbatim at
/// `block + 0x2c`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cg_block_create(proc: *mut CgProc, kind: u32) -> *mut CgBlock {
    let proc = proc as *mut u8;
    let module = slot(proc, CG_PROC_MODULE).read();
    let heap = slot(module, CG_MODULE_HEAP).read() as *mut CgHeap;
    let block = cg_heap_alloc(heap, record_size(CG_BLOCK_BYTES));
    let has_blocks = !slot(proc, CG_PROC_BLOCKS).read().is_null();

    if has_blocks {
        slot(slot(proc, CG_PROC_LAST_BLOCK).read(), CG_BLOCK_NEXT).write(block);
    }
    slot(proc, CG_PROC_LAST_BLOCK).write(block);
    if !has_blocks {
        slot(proc, CG_PROC_BLOCKS).write(block);
    }
    slot(block, CG_BLOCK_PROC).write(proc);
    word(block, CG_BLOCK_KIND).write(kind as usize);

    block as *mut CgBlock
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use super::super::heap::{
        cg_heap_create, cg_heap_destroy, CgHeapOps, CG_HEAP_OPS, DEFAULT_CG_HEAP_OPS,
    };
    use std::alloc::{alloc as host_alloc_raw, dealloc as host_dealloc_raw, Layout};
    use std::sync::{Mutex, MutexGuard};

    static LOCK: Mutex<()> = Mutex::new(());

    /// Header the test allocator prepends so `free` can rebuild the layout.
    const HDR: usize = 16;

    /// Poisons allocations before the real heap zeroes its carves, making
    /// zero-filled `next` links observable rather than accidental.
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

    /// A module and procedure wired to a real, host-backed codegen arena.
    struct Fixture {
        heap: *mut CgHeap,
        module: [usize; 1],
        proc: [usize; 9],
    }

    impl Fixture {
        fn new(block_size: usize) -> std::boxed::Box<Self> {
            let heap = unsafe { cg_heap_create(block_size) };
            let mut fixture = std::boxed::Box::new(Self {
                heap,
                module: [0; 1],
                proc: [0; 9],
            });
            fixture.module[CG_MODULE_HEAP] = heap as usize;
            fixture.proc[CG_PROC_MODULE] = fixture.module.as_ptr() as usize;
            fixture
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

    #[test]
    fn empty_append_sets_head_tail_owner_and_kind() {
        let _guard = setup();
        let mut fixture = Fixture::new(0x100);
        unsafe {
            let block = cg_block_create(fixture.proc_ptr(), 9);
            assert_eq!(fixture.proc[CG_PROC_BLOCKS], block as usize);
            assert_eq!(fixture.proc[CG_PROC_LAST_BLOCK], block as usize);
            assert!(slot(block as *mut u8, CG_BLOCK_NEXT).read().is_null());
            assert_eq!(slot(block as *mut u8, CG_BLOCK_PROC).read(), fixture.proc_ptr() as *mut u8);
            assert_eq!(word(block as *mut u8, CG_BLOCK_KIND).read(), 9);
        }
        drop(fixture);
        teardown();
    }

    #[test]
    fn nonempty_append_preserves_head_links_old_tail_and_advances_tail() {
        let _guard = setup();
        let mut fixture = Fixture::new(0x100);
        unsafe {
            let first = cg_block_create(fixture.proc_ptr(), 1);
            let second = cg_block_create(fixture.proc_ptr(), 5);
            assert_eq!(fixture.proc[CG_PROC_BLOCKS], first as usize);
            assert_eq!(fixture.proc[CG_PROC_LAST_BLOCK], second as usize);
            assert_eq!(slot(first as *mut u8, CG_BLOCK_NEXT).read(), second as *mut u8);
            assert!(slot(second as *mut u8, CG_BLOCK_NEXT).read().is_null());
        }
        drop(fixture);
        teardown();
    }
}
