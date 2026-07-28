//! Builders for the JIT's IR nodes: virtual registers and instructions.
//! All of them carve their record out of the module's arena
//! ([`super::heap`]) and append it to a singly linked list, relying on
//! `cg_heap_alloc`'s zero-fill for the record's `next` link and for every
//! field they do not write.
//!
//! Ported here (call counts binary-scanned from osos.dec):
//!
//! - `cg_virtual_reg_create` — original: `FUN_082c23dc` @ 0x082c23dc
//!   (80 bytes; **835 `bl` call sites** — the most-called unported
//!   function in the image). Numbers and appends one virtual register.
//! - `cg_inst_create_base` — original: `FUN_082d6c24` @ 0x082d6c24
//!   (72 bytes; 11 `bl` + 1 tail `b` call sites — the twelve instruction
//!   factories at 0x082c17f4-0x082c19b8). Allocates a `size`-byte
//!   instruction record, appends it to the block and stamps its kind and
//!   opcode bytes.
//! - `cg_create_inst_binary` — original: `FUN_082c17f4` @ 0x082c17f4
//!   (48 bytes; **419 `bl` call sites**). Kind 2, 36-byte record.
//! - `cg_create_inst_load_immed` — original: `FUN_082c18ec` @ 0x082c18ec
//!   (40 bytes; **201 `bl` call sites**). Kind 6, 20-byte record.
//!
//! Layouts recovered from the assembly (byte offsets are the target's;
//! the port addresses every pointer field by WORD INDEX so the records
//! stay disjoint on a 64-bit test host, as in heap/block_region.rs):
//!
//! ```text
//! cg_module_t                 cg_proc_t                    cg_block_t
//!   +0x00 heap                  +0x04 module                 +0x04 proc
//!                               +0x10 registers (head)       +0x0c insts (head)
//!                               +0x14 last_register (tail)   +0x10 last_inst (tail)
//!                               +0x20 num_registers
//!
//! cg_virtual_reg_t (40 bytes)  cg_inst_t (base of every instruction)
//!   +0x00 next                   +0x00 next
//!   +0x10 reg_no                 +0x04 block
//!   +0x20 type (u8)              +0x08 kind (u8)
//!                                +0x09 opcode (u8)
//!                                +0x0c first derived field
//! ```
//!
//! The instruction kinds are a 21-value enum: the visitor @ 0x082c1adc
//! reads `inst + 0x8` and dispatches through `cmp r0, #20;
//! addls pc, pc, r0, lsl #2`. The twelve factories encode
//! (kind, record size): 1/32, 2/36 (twice — with and without a
//! destination-flags register), 3/32, 4/24, 5/24, 6/20, 7/20, 8/20,
//! 9/20, 11/16 (twice). That sequence — and the field counts — matches
//! Vincent's `cg_inst_kind_t` ordering (unary, binary, compare, load,
//! store, load_immed, branch_label, branch_cond, phi, ...), which is
//! where the names used here come from. Only the two ported factories'
//! numbers are asserted as fact; the rest are recorded in names.yaml as
//! scouting.
//!
//! Deviations:
//! - Neither builder writes the record's `next`: the original relies on
//!   the arena's zero-fill and so does the port. Anything that replaces
//!   `CG_HEAP_OPS.zero` with a non-zeroing stub breaks list termination.
//! - `cg_virtual_reg_create` re-reads `proc->num_registers` after storing
//!   it into the register (`ldr` / `str` / `ldr` / `add` / `str`); the
//!   port reads once, which is identical because the register record
//!   cannot alias the procedure.
//! - Record sizes are given as target byte counts and scaled by
//!   [`record_size`] so the ports work on a 64-bit host; on target the
//!   scale is 1 and the constants fold to the originals' `mov r1, #36` /
//!   `mov r1, #20` / `mov r1, #40`.

use super::heap::{cg_heap_alloc, CgHeap};

/// Width of a pointer/word field: 4 on the ARMv5TE target (matching the
/// original layout), 8 on a 64-bit test host.
const WORD: usize = core::mem::size_of::<*mut u8>();

/// Scales a record size given in the target's bytes to the host's word
/// width. Every record size in this cluster is a whole number of 32-bit
/// words, so on target this is the identity.
pub const fn record_size(target_bytes: usize) -> usize {
    target_bytes / 4 * WORD
}

// --- opaque IR objects -------------------------------------------------
// Only the fields listed in the module header are recovered, so these are
// FFI-opaque types addressed through the word indices below.

/// `cg_module_t` — owns the arena every IR record is carved from.
#[repr(C)]
pub struct CgModule {
    _opaque: [u8; 0],
}

/// `cg_proc_t` — one procedure being built: owns the virtual registers.
#[repr(C)]
pub struct CgProc {
    _opaque: [u8; 0],
}

/// `cg_block_t` — one basic block: owns a list of instructions.
#[repr(C)]
pub struct CgBlock {
    _opaque: [u8; 0],
}

/// `cg_virtual_reg_t` — an SSA-ish value of the IR.
#[repr(C)]
pub struct CgVirtualReg {
    _opaque: [u8; 0],
}

/// `cg_inst_t` — the common base of every instruction record.
#[repr(C)]
pub struct CgInst {
    _opaque: [u8; 0],
}

// --- word indices (target byte offset = index * 4) ---------------------

/// `cg_module_t + 0x00` — the IR arena.
pub const CG_MODULE_HEAP: usize = 0;

/// `cg_proc_t + 0x04` — owning module.
pub const CG_PROC_MODULE: usize = 1;
/// `cg_proc_t + 0x10` — first virtual register.
pub const CG_PROC_REGISTERS: usize = 4;
/// `cg_proc_t + 0x14` — last virtual register.
pub const CG_PROC_LAST_REGISTER: usize = 5;
/// `cg_proc_t + 0x20` — number of registers created so far.
pub const CG_PROC_NUM_REGISTERS: usize = 8;

/// `cg_block_t + 0x04` — owning procedure.
pub const CG_BLOCK_PROC: usize = 1;
/// `cg_block_t + 0x0c` — first instruction.
pub const CG_BLOCK_INSTS: usize = 3;
/// `cg_block_t + 0x10` — last instruction.
pub const CG_BLOCK_LAST_INST: usize = 4;

/// `cg_virtual_reg_t + 0x00` — next register in the procedure's list.
pub const CG_VREG_NEXT: usize = 0;
/// `cg_virtual_reg_t + 0x10` — the register's number.
pub const CG_VREG_NO: usize = 4;
/// `cg_virtual_reg_t + 0x20` — the register's type, a single byte.
pub const CG_VREG_TYPE: usize = 8;
/// Size of `cg_virtual_reg_t` in target bytes.
pub const CG_VREG_BYTES: usize = 40;

/// `cg_inst_t + 0x00` — next instruction in the block's list.
pub const CG_INST_NEXT: usize = 0;
/// `cg_inst_t + 0x04` — owning block.
pub const CG_INST_BLOCK: usize = 1;
/// `cg_inst_t + 0x08` — instruction kind, a single byte.
pub const CG_INST_KIND: usize = 2;
/// Byte offset of the opcode inside the kind word (`cg_inst_t + 0x09`).
const CG_INST_OPCODE_IN_KIND_WORD: usize = 1;

/// `cg_inst_binary_t + 0x0c` — destination register.
pub const CG_INST_BINARY_DEST: usize = 3;
/// `cg_inst_binary_t + 0x14` — first source register.
pub const CG_INST_BINARY_SOURCE0: usize = 5;
/// `cg_inst_binary_t + 0x18` — second source register.
pub const CG_INST_BINARY_SOURCE1: usize = 6;
/// Size of `cg_inst_binary_t` in target bytes.
pub const CG_INST_BINARY_BYTES: usize = 36;
/// `cg_inst_kind_t` value the binary factory stamps.
pub const CG_INST_KIND_BINARY: u32 = 2;

/// `cg_inst_load_immed_t + 0x0c` — destination register.
pub const CG_INST_LOAD_IMMED_DEST: usize = 3;
/// `cg_inst_load_immed_t + 0x10` — the immediate.
pub const CG_INST_LOAD_IMMED_VALUE: usize = 4;
/// Size of `cg_inst_load_immed_t` in target bytes.
pub const CG_INST_LOAD_IMMED_BYTES: usize = 20;
/// `cg_inst_kind_t` value the load-immediate factory stamps.
pub const CG_INST_KIND_LOAD_IMMED: u32 = 6;

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

/// The arena backing `module`'s IR (`module->heap`).
#[inline(always)]
unsafe fn module_heap(module: *mut u8) -> *mut CgHeap {
    slot(module, CG_MODULE_HEAP).read() as *mut CgHeap
}

/// cg_virtual_reg_create — original: `FUN_082c23dc` @ 0x082c23dc
/// (80 bytes, 835 `bl` call sites).
///
/// Carves a 40-byte register record out of `proc->module->heap`, stamps
/// it with the procedure's next register number (post-incrementing the
/// counter) and with `reg_type` as a byte, then appends it to the
/// procedure's register list. The record's `next` stays NULL by virtue of
/// the arena's zero-fill.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cg_virtual_reg_create(
    proc: *mut CgProc,
    reg_type: u32,
) -> *mut CgVirtualReg {
    let proc = proc as *mut u8;
    let heap = module_heap(slot(proc, CG_PROC_MODULE).read());
    let reg = cg_heap_alloc(heap, record_size(CG_VREG_BYTES));

    let counter = word(proc, CG_PROC_NUM_REGISTERS);
    word(reg, CG_VREG_NO).write(counter.read());
    counter.write(counter.read().wrapping_add(1));
    reg.add(CG_VREG_TYPE * WORD).write(reg_type as u8);

    let head = slot(proc, CG_PROC_REGISTERS);
    let tail = slot(proc, CG_PROC_LAST_REGISTER);
    if head.read().is_null() {
        head.write(reg);
    } else {
        slot(tail.read(), CG_VREG_NEXT).write(reg);
    }
    tail.write(reg);

    reg as *mut CgVirtualReg
}

/// cg_inst_create_base — original: `FUN_082d6c24` @ 0x082d6c24
/// (72 bytes, 11 `bl` + 1 tail `b` call sites).
///
/// Carves a `size`-byte instruction record out of
/// `block->proc->module->heap`, points it back at `block`, appends it to
/// the block's instruction list and writes the `kind` and `opcode`
/// discriminant bytes. `size` is in host words already scaled by
/// [`record_size`].
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cg_inst_create_base(
    block: *mut CgBlock,
    size: usize,
    kind: u32,
    opcode: u32,
) -> *mut CgInst {
    let block = block as *mut u8;
    let proc = slot(block, CG_BLOCK_PROC).read();
    let heap = module_heap(slot(proc, CG_PROC_MODULE).read());
    let inst = cg_heap_alloc(heap, size);

    slot(inst, CG_INST_BLOCK).write(block);

    let head = slot(block, CG_BLOCK_INSTS);
    let tail = slot(block, CG_BLOCK_LAST_INST);
    if head.read().is_null() {
        head.write(inst);
    } else {
        slot(tail.read(), CG_INST_NEXT).write(inst);
    }
    tail.write(inst);

    let kind_byte = inst.add(CG_INST_KIND * WORD);
    kind_byte.write(kind as u8);
    kind_byte.add(CG_INST_OPCODE_IN_KIND_WORD).write(opcode as u8);

    inst as *mut CgInst
}

/// cg_create_inst_binary — original: `FUN_082c17f4` @ 0x082c17f4
/// (48 bytes, 419 `bl` call sites).
///
/// Appends a kind-2 (binary) instruction: a 36-byte record holding the
/// destination register and two sources. The destination-flags slot
/// (`+0x10`) is left NULL — the sibling factory @ 0x082c1824 is the
/// variant that fills it.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cg_create_inst_binary(
    block: *mut CgBlock,
    opcode: u32,
    dest: *mut CgVirtualReg,
    source0: *mut CgVirtualReg,
    source1: *mut CgVirtualReg,
) -> *mut CgInst {
    let inst = cg_inst_create_base(
        block,
        record_size(CG_INST_BINARY_BYTES),
        CG_INST_KIND_BINARY,
        opcode,
    ) as *mut u8;
    slot(inst, CG_INST_BINARY_DEST).write(dest as *mut u8);
    slot(inst, CG_INST_BINARY_SOURCE0).write(source0 as *mut u8);
    slot(inst, CG_INST_BINARY_SOURCE1).write(source1 as *mut u8);
    inst as *mut CgInst
}

/// cg_create_inst_load_immed — original: `FUN_082c18ec` @ 0x082c18ec
/// (40 bytes, 201 `bl` call sites).
///
/// Appends a kind-6 (load-immediate) instruction: a 20-byte record
/// holding the destination register and the constant to materialize.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cg_create_inst_load_immed(
    block: *mut CgBlock,
    opcode: u32,
    dest: *mut CgVirtualReg,
    value: usize,
) -> *mut CgInst {
    let inst = cg_inst_create_base(
        block,
        record_size(CG_INST_LOAD_IMMED_BYTES),
        CG_INST_KIND_LOAD_IMMED,
        opcode,
    ) as *mut u8;
    slot(inst, CG_INST_LOAD_IMMED_DEST).write(dest as *mut u8);
    word(inst, CG_INST_LOAD_IMMED_VALUE).write(value);
    inst as *mut CgInst
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::super::heap::{cg_heap_create, cg_heap_destroy, CgHeap, CgHeapOps, CG_HEAP_OPS,
                             DEFAULT_CG_HEAP_OPS};
    use super::*;
    use std::alloc::{alloc as host_alloc_raw, dealloc as host_dealloc_raw, Layout};
    use std::sync::{Mutex, MutexGuard};

    static LOCK: Mutex<()> = Mutex::new(());

    /// Header the test allocator prepends so `free` can rebuild the layout.
    const HDR: usize = 16;

    /// Poisons every allocation, so the zero-fill the builders depend on
    /// (record `next` links, unwritten fields) is actually observable.
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

    /// A module, a procedure and a block over one real arena.
    struct Fixture {
        heap: *mut CgHeap,
        module: [usize; 1],
        proc: [usize; 9],
        block: [usize; 5],
    }

    impl Fixture {
        fn new(block_size: usize) -> std::boxed::Box<Fixture> {
            let heap = unsafe { cg_heap_create(block_size) };
            let mut f = std::boxed::Box::new(Fixture {
                heap,
                module: [0; 1],
                proc: [0; 9],
                block: [0; 5],
            });
            f.module[CG_MODULE_HEAP] = heap as usize;
            f.proc[CG_PROC_MODULE] = f.module.as_ptr() as usize;
            f.block[CG_BLOCK_PROC] = f.proc.as_ptr() as usize;
            f
        }

        fn proc_ptr(&mut self) -> *mut CgProc {
            self.proc.as_mut_ptr() as *mut CgProc
        }

        fn block_ptr(&mut self) -> *mut CgBlock {
            self.block.as_mut_ptr() as *mut CgBlock
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

    unsafe fn reg_no(reg: *mut CgVirtualReg) -> usize {
        word(reg as *mut u8, CG_VREG_NO).read()
    }

    unsafe fn reg_type(reg: *mut CgVirtualReg) -> u8 {
        (reg as *mut u8).add(CG_VREG_TYPE * WORD).read()
    }

    unsafe fn reg_next(reg: *mut CgVirtualReg) -> *mut CgVirtualReg {
        slot(reg as *mut u8, CG_VREG_NEXT).read() as *mut CgVirtualReg
    }

    unsafe fn inst_next(inst: *mut CgInst) -> *mut CgInst {
        slot(inst as *mut u8, CG_INST_NEXT).read() as *mut CgInst
    }

    unsafe fn inst_kind(inst: *mut CgInst) -> u8 {
        (inst as *mut u8).add(CG_INST_KIND * WORD).read()
    }

    unsafe fn inst_opcode(inst: *mut CgInst) -> u8 {
        (inst as *mut u8).add(CG_INST_KIND * WORD + 1).read()
    }

    /// Arena stride of a record: `cg_heap_alloc` rounds every request up
    /// to 8 bytes.
    fn stride(target_bytes: usize) -> usize {
        (record_size(target_bytes) + 7) & !7
    }

    #[test]
    fn the_first_register_becomes_both_head_and_tail() {
        let _g = setup();
        let mut f = Fixture::new(4096);
        unsafe {
            let reg = cg_virtual_reg_create(f.proc_ptr(), 3);
            assert_eq!(f.proc[CG_PROC_REGISTERS], reg as usize, "head");
            assert_eq!(f.proc[CG_PROC_LAST_REGISTER], reg as usize, "tail");
            assert_eq!(f.proc[CG_PROC_NUM_REGISTERS], 1);
            assert_eq!(reg_no(reg), 0, "numbers are handed out pre-increment");
            assert_eq!(reg_type(reg), 3);
            assert!(reg_next(reg).is_null(), "arena zero-fill terminates the list");
        }
        drop(f);
        teardown();
    }

    #[test]
    fn registers_append_in_order_with_ascending_numbers() {
        let _g = setup();
        let mut f = Fixture::new(4096);
        unsafe {
            let mut regs = std::vec::Vec::new();
            for i in 0..5u32 {
                regs.push(cg_virtual_reg_create(f.proc_ptr(), i));
            }
            assert_eq!(f.proc[CG_PROC_NUM_REGISTERS], 5);
            assert_eq!(f.proc[CG_PROC_REGISTERS], regs[0] as usize);
            assert_eq!(f.proc[CG_PROC_LAST_REGISTER], regs[4] as usize);
            for (i, &reg) in regs.iter().enumerate() {
                assert_eq!(reg_no(reg), i, "reg {i} number");
                assert_eq!(reg_type(reg), i as u8, "reg {i} type");
                let expected = regs.get(i + 1).copied().unwrap_or(core::ptr::null_mut());
                assert_eq!(reg_next(reg), expected, "reg {i} link");
            }
        }
        drop(f);
        teardown();
    }

    #[test]
    fn only_the_low_byte_of_the_type_survives() {
        let _g = setup();
        let mut f = Fixture::new(4096);
        unsafe {
            // `strb r5, [r0, #32]`: the argument is truncated.
            let reg = cg_virtual_reg_create(f.proc_ptr(), 0x1234_5678);
            assert_eq!(reg_type(reg), 0x78);
            // ...and it must not have spilled into the neighbouring word.
            assert_eq!(word(reg as *mut u8, CG_VREG_TYPE).read(), 0x78);
        }
        drop(f);
        teardown();
    }

    #[test]
    fn the_register_counter_survives_an_arena_block_boundary() {
        let _g = setup();
        // 40-byte records out of an 80-byte block: every third register
        // forces cg_heap_alloc to push a new block.
        let mut f = Fixture::new(record_size(CG_VREG_BYTES) * 2);
        unsafe {
            let mut regs = std::vec::Vec::new();
            for _ in 0..7 {
                regs.push(cg_virtual_reg_create(f.proc_ptr(), 1));
            }
            assert_eq!(f.proc[CG_PROC_NUM_REGISTERS], 7);
            for (i, &reg) in regs.iter().enumerate() {
                assert_eq!(reg_no(reg), i);
                let expected = regs.get(i + 1).copied().unwrap_or(core::ptr::null_mut());
                assert_eq!(reg_next(reg), expected, "reg {i} link across blocks");
            }
        }
        drop(f);
        teardown();
    }

    #[test]
    fn instructions_append_to_the_block_and_carry_kind_and_opcode() {
        let _g = setup();
        let mut f = Fixture::new(4096);
        unsafe {
            let a = cg_inst_create_base(f.block_ptr(), record_size(20), 6, 0x28);
            let b = cg_inst_create_base(f.block_ptr(), record_size(36), 2, 0x0f);
            assert_eq!(f.block[CG_BLOCK_INSTS], a as usize, "head");
            assert_eq!(f.block[CG_BLOCK_LAST_INST], b as usize, "tail");
            assert_eq!(inst_next(a), b);
            assert!(inst_next(b).is_null());
            assert_eq!(inst_kind(a), 6);
            assert_eq!(inst_opcode(a), 0x28);
            assert_eq!(inst_kind(b), 2);
            assert_eq!(inst_opcode(b), 0x0f);
            for inst in [a, b] {
                assert_eq!(
                    slot(inst as *mut u8, CG_INST_BLOCK).read(),
                    f.block_ptr() as *mut u8,
                    "back-pointer to the owning block"
                );
            }
        }
        drop(f);
        teardown();
    }

    #[test]
    fn kind_and_opcode_are_bytes_that_do_not_disturb_the_block_pointer() {
        let _g = setup();
        let mut f = Fixture::new(4096);
        unsafe {
            let inst = cg_inst_create_base(f.block_ptr(), record_size(36), 0x1ff, 0x2aa);
            assert_eq!(inst_kind(inst), 0xff);
            assert_eq!(inst_opcode(inst), 0xaa);
            assert_eq!(
                slot(inst as *mut u8, CG_INST_BLOCK).read(),
                f.block_ptr() as *mut u8
            );
            assert!(inst_next(inst).is_null());
        }
        drop(f);
        teardown();
    }

    #[test]
    fn binary_stores_dest_and_both_sources_and_leaves_dest_flags_null() {
        let _g = setup();
        let mut f = Fixture::new(4096);
        unsafe {
            let dest = cg_virtual_reg_create(f.proc_ptr(), 1);
            let s0 = cg_virtual_reg_create(f.proc_ptr(), 1);
            let s1 = cg_virtual_reg_create(f.proc_ptr(), 1);
            let inst = cg_create_inst_binary(f.block_ptr(), 0x0f, dest, s0, s1);
            let raw = inst as *mut u8;
            assert_eq!(inst_kind(inst), CG_INST_KIND_BINARY as u8);
            assert_eq!(inst_opcode(inst), 0x0f);
            assert_eq!(slot(raw, CG_INST_BINARY_DEST).read(), dest as *mut u8);
            assert_eq!(slot(raw, CG_INST_BINARY_SOURCE0).read(), s0 as *mut u8);
            assert_eq!(slot(raw, CG_INST_BINARY_SOURCE1).read(), s1 as *mut u8);
            // +0x10 (dest_flags) is untouched, so the arena's zero shows.
            assert!(slot(raw, 4).read().is_null(), "dest_flags stays NULL");
            assert_eq!(f.block[CG_BLOCK_INSTS], inst as usize);
        }
        drop(f);
        teardown();
    }

    #[test]
    fn load_immed_stores_dest_and_value() {
        let _g = setup();
        let mut f = Fixture::new(4096);
        unsafe {
            let dest = cg_virtual_reg_create(f.proc_ptr(), 2);
            let inst = cg_create_inst_load_immed(f.block_ptr(), 0x28, dest, 0);
            let raw = inst as *mut u8;
            assert_eq!(inst_kind(inst), CG_INST_KIND_LOAD_IMMED as u8);
            assert_eq!(inst_opcode(inst), 0x28);
            assert_eq!(slot(raw, CG_INST_LOAD_IMMED_DEST).read(), dest as *mut u8);
            assert_eq!(word(raw, CG_INST_LOAD_IMMED_VALUE).read(), 0);

            let other = cg_create_inst_load_immed(f.block_ptr(), 0x28, dest, 0xdead_beef);
            assert_eq!(word(other as *mut u8, CG_INST_LOAD_IMMED_VALUE).read(), 0xdead_beef);
            assert_eq!(inst_next(inst), other);
        }
        drop(f);
        teardown();
    }

    /// The emission sequence of the pipeline generator @ 0x0823a6ac,
    /// transcribed from its disassembly: two fresh registers, a
    /// load-immediate of 0 into the first, then two binary instructions.
    #[test]
    fn reproduces_the_emission_sequence_of_the_generator_at_0x0823a6ac() {
        let _g = setup();
        let mut f = Fixture::new(4096);
        unsafe {
            let zero = cg_virtual_reg_create(f.proc_ptr(), 0);
            let tmp = cg_virtual_reg_create(f.proc_ptr(), 0);
            let a = cg_virtual_reg_create(f.proc_ptr(), 0);
            let b = cg_virtual_reg_create(f.proc_ptr(), 0);
            let c = cg_virtual_reg_create(f.proc_ptr(), 0);

            let i0 = cg_create_inst_load_immed(f.block_ptr(), 0x28, zero, 0);
            let i1 = cg_create_inst_binary(f.block_ptr(), 0x0f, tmp, a, c);
            let i2 = cg_create_inst_binary(f.block_ptr(), 0x10, b, tmp, zero);

            assert_eq!(f.proc[CG_PROC_NUM_REGISTERS], 5);
            assert_eq!(reg_no(zero), 0);
            assert_eq!(reg_no(c), 4);
            assert_eq!(f.block[CG_BLOCK_INSTS], i0 as usize);
            assert_eq!(f.block[CG_BLOCK_LAST_INST], i2 as usize);
            assert_eq!(inst_next(i0), i1);
            assert_eq!(inst_next(i1), i2);
            assert!(inst_next(i2).is_null());
            // The records are distinct, contiguous arena carvings, each
            // taking its record size rounded up to 8.
            assert_eq!(
                i1 as usize - i0 as usize,
                stride(CG_INST_LOAD_IMMED_BYTES),
                "load_immed record stride"
            );
            assert_eq!(
                i2 as usize - i1 as usize,
                stride(CG_INST_BINARY_BYTES),
                "binary record stride"
            );
        }
        drop(f);
        teardown();
    }
}
