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
//! - The rest of the factory family: `cg_create_inst_unary` @ 0x082c1994
//!   (kind 1, 32 bytes), `cg_create_inst_binary_s` @ 0x082c1824 (kind 2
//!   with dest_flags, 36 bytes), `cg_create_inst_compare` @ 0x082c1898
//!   (kind 3, 32 bytes), `cg_create_inst_load` @ 0x082c18c4 (kind 4,
//!   24 bytes), `cg_create_inst_store` @ 0x082c196c (kind 5, 24 bytes),
//!   `cg_create_inst_branch_label` @ 0x082c1878 (kind 7, 20 bytes),
//!   `cg_create_inst_branch_cond` @ 0x082c1850 (kind 8, 20 bytes),
//!   `cg_create_inst_phi` @ 0x082c1914 (kind 9, 20 bytes),
//!   `cg_create_inst_ret` @ 0x082c193c (kind 11, 16 bytes),
//!   `cg_create_inst_ret_value` @ 0x082c194c (kind 11, 16 bytes).
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
//! where the names used here come from.
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

/// `cg_virtual_reg_list_t` — one cell of a NULL-terminated register
/// list, built by `cg_virtual_reg_list_create` (unported: C varargs).
#[repr(C)]
pub struct CgVirtualRegList {
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

/// `cg_inst_unary_t + 0x0c` — destination register.
pub const CG_INST_UNARY_DEST: usize = 3;
/// `cg_inst_unary_t + 0x14` — source register. `+0x10` stays NULL by
/// the arena's zero-fill (the dest_flags slot of the binary layout).
pub const CG_INST_UNARY_SOURCE: usize = 5;
/// Size of `cg_inst_unary_t` in target bytes.
pub const CG_INST_UNARY_BYTES: usize = 32;
/// `cg_inst_kind_t` value the unary factory stamps.
pub const CG_INST_KIND_UNARY: u32 = 1;

/// `cg_inst_binary_t + 0x10` — destination-flags register; only the
/// `_s` factory writes it.
pub const CG_INST_BINARY_DEST_FLAGS: usize = 4;
/// `cg_inst_kind_t` value both binary factories stamp.
pub const CG_INST_KIND_BINARY_S: u32 = 2;

/// `cg_inst_compare_t + 0x0c` — destination register.
pub const CG_INST_COMPARE_DEST: usize = 3;
/// `cg_inst_compare_t + 0x10` — first source register (compare has no
/// dest_flags slot; its sources sit one word earlier than binary's).
pub const CG_INST_COMPARE_SOURCE0: usize = 4;
/// `cg_inst_compare_t + 0x14` — second source register.
pub const CG_INST_COMPARE_SOURCE1: usize = 5;
/// Size of `cg_inst_compare_t` in target bytes.
pub const CG_INST_COMPARE_BYTES: usize = 32;
/// `cg_inst_kind_t` value the compare factory stamps.
pub const CG_INST_KIND_COMPARE: u32 = 3;

/// `cg_inst_load_t + 0x0c` — destination register.
pub const CG_INST_LOAD_DEST: usize = 3;
/// `cg_inst_load_t + 0x10` — address register.
pub const CG_INST_LOAD_ADDRESS: usize = 4;
/// Size of `cg_inst_load_t` in target bytes.
pub const CG_INST_LOAD_BYTES: usize = 24;
/// `cg_inst_kind_t` value the load factory stamps.
pub const CG_INST_KIND_LOAD: u32 = 4;

/// `cg_inst_store_t + 0x0c` — value register.
pub const CG_INST_STORE_VALUE: usize = 3;
/// `cg_inst_store_t + 0x10` — address register.
pub const CG_INST_STORE_ADDRESS: usize = 4;
/// Size of `cg_inst_store_t` in target bytes.
pub const CG_INST_STORE_BYTES: usize = 24;
/// `cg_inst_kind_t` value the store factory stamps.
pub const CG_INST_KIND_STORE: u32 = 5;

/// `cg_inst_branch_label_t + 0x0c` — target block.
pub const CG_INST_BRANCH_LABEL_TARGET: usize = 3;
/// Size of `cg_inst_branch_label_t` in target bytes.
pub const CG_INST_BRANCH_LABEL_BYTES: usize = 20;
/// `cg_inst_kind_t` value the branch-label factory stamps.
pub const CG_INST_KIND_BRANCH_LABEL: u32 = 7;

/// `cg_inst_branch_cond_t + 0x0c` — target block (same slot as the
/// branch-label target, but filled from the FOURTH argument).
pub const CG_INST_BRANCH_COND_TARGET: usize = 3;
/// `cg_inst_branch_cond_t + 0x10` — condition register (filled from the
/// third argument — the swapped order of this factory).
pub const CG_INST_BRANCH_COND_CONDITION: usize = 4;
/// Size of `cg_inst_branch_cond_t` in target bytes.
pub const CG_INST_BRANCH_COND_BYTES: usize = 20;
/// `cg_inst_kind_t` value the branch-cond factory stamps.
pub const CG_INST_KIND_BRANCH_COND: u32 = 8;

/// `cg_inst_phi_t + 0x0c` — destination register.
pub const CG_INST_PHI_DEST: usize = 3;
/// `cg_inst_phi_t + 0x10` — head of the register list built by
/// `cg_virtual_reg_list_create`.
pub const CG_INST_PHI_REGS: usize = 4;
/// Size of `cg_inst_phi_t` in target bytes.
pub const CG_INST_PHI_BYTES: usize = 20;
/// `cg_inst_kind_t` value the phi factory stamps.
pub const CG_INST_KIND_PHI: u32 = 9;

/// `cg_inst_ret_value_t + 0x0c` — returned value register.
pub const CG_INST_RET_VALUE_VALUE: usize = 3;
/// Size of both ret records in target bytes.
pub const CG_INST_RET_BYTES: usize = 16;
/// `cg_inst_kind_t` value both ret factories stamp.
pub const CG_INST_KIND_RET: u32 = 11;

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

/// cg_create_inst_unary — original: `FUN_082c1994` @ 0x082c1994
/// (40 bytes, 36 `bl` call sites).
///
/// Appends a kind-1 (unary) instruction: a 32-byte record holding the
/// destination register and one source. `+0x10` stays NULL by the
/// arena's zero-fill.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cg_create_inst_unary(
    block: *mut CgBlock,
    opcode: u32,
    dest: *mut CgVirtualReg,
    source: *mut CgVirtualReg,
) -> *mut CgInst {
    let inst = cg_inst_create_base(
        block,
        record_size(CG_INST_UNARY_BYTES),
        CG_INST_KIND_UNARY,
        opcode,
    ) as *mut u8;
    slot(inst, CG_INST_UNARY_DEST).write(dest as *mut u8);
    slot(inst, CG_INST_UNARY_SOURCE).write(source as *mut u8);
    inst as *mut CgInst
}

/// cg_create_inst_binary_s — original: `FUN_082c1824` @ 0x082c1824
/// (44 bytes, 7 `bl` call sites).
///
/// The flags-writing twin of [`cg_create_inst_binary`]: same kind-2,
/// 36-byte record, but the destination-flags slot (`+0x10`) is filled
/// too — one `stmia` writes all four derived fields. `dest_flags` and
/// `source0` arrive on the stack in the original (`ldrd r6, r7,
/// [sp, #0x18]`); the C ABI makes that invisible here.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cg_create_inst_binary_s(
    block: *mut CgBlock,
    opcode: u32,
    dest: *mut CgVirtualReg,
    dest_flags: *mut CgVirtualReg,
    source0: *mut CgVirtualReg,
    source1: *mut CgVirtualReg,
) -> *mut CgInst {
    let inst = cg_inst_create_base(
        block,
        record_size(CG_INST_BINARY_BYTES),
        CG_INST_KIND_BINARY_S,
        opcode,
    ) as *mut u8;
    slot(inst, CG_INST_BINARY_DEST).write(dest as *mut u8);
    slot(inst, CG_INST_BINARY_DEST_FLAGS).write(dest_flags as *mut u8);
    slot(inst, CG_INST_BINARY_SOURCE0).write(source0 as *mut u8);
    slot(inst, CG_INST_BINARY_SOURCE1).write(source1 as *mut u8);
    inst as *mut CgInst
}

/// cg_create_inst_compare — original: `FUN_082c1898` @ 0x082c1898
/// (44 bytes, 35 `bl` call sites).
///
/// Appends a kind-3 (compare) instruction: a 32-byte record holding the
/// destination register and two sources at `+0xc`, `+0x10`, `+0x14` —
/// one word earlier than binary's sources, because compare has no
/// dest_flags slot. `source1` arrives on the stack in the original
/// (`ldr r6, [sp, #0x10]`).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cg_create_inst_compare(
    block: *mut CgBlock,
    opcode: u32,
    dest: *mut CgVirtualReg,
    source0: *mut CgVirtualReg,
    source1: *mut CgVirtualReg,
) -> *mut CgInst {
    let inst = cg_inst_create_base(
        block,
        record_size(CG_INST_COMPARE_BYTES),
        CG_INST_KIND_COMPARE,
        opcode,
    ) as *mut u8;
    slot(inst, CG_INST_COMPARE_DEST).write(dest as *mut u8);
    slot(inst, CG_INST_COMPARE_SOURCE0).write(source0 as *mut u8);
    slot(inst, CG_INST_COMPARE_SOURCE1).write(source1 as *mut u8);
    inst as *mut CgInst
}

/// cg_create_inst_load — original: `FUN_082c18c4` @ 0x082c18c4
/// (40 bytes, 34 `bl` call sites).
///
/// Appends a kind-4 (load) instruction: a 24-byte record holding the
/// destination register and the address register.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cg_create_inst_load(
    block: *mut CgBlock,
    opcode: u32,
    dest: *mut CgVirtualReg,
    address: *mut CgVirtualReg,
) -> *mut CgInst {
    let inst = cg_inst_create_base(
        block,
        record_size(CG_INST_LOAD_BYTES),
        CG_INST_KIND_LOAD,
        opcode,
    ) as *mut u8;
    slot(inst, CG_INST_LOAD_DEST).write(dest as *mut u8);
    slot(inst, CG_INST_LOAD_ADDRESS).write(address as *mut u8);
    inst as *mut CgInst
}

/// cg_create_inst_store — original: `FUN_082c196c` @ 0x082c196c
/// (40 bytes, 5 `bl` + 2 tail `b` call sites).
///
/// Appends a kind-5 (store) instruction: a 24-byte record holding the
/// value register and the address register. The caller @ 0x0823cc40
/// passes a freshly computed value in the value slot and the address
/// computation's register in the address slot, which pins the order.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cg_create_inst_store(
    block: *mut CgBlock,
    opcode: u32,
    value: *mut CgVirtualReg,
    address: *mut CgVirtualReg,
) -> *mut CgInst {
    let inst = cg_inst_create_base(
        block,
        record_size(CG_INST_STORE_BYTES),
        CG_INST_KIND_STORE,
        opcode,
    ) as *mut u8;
    slot(inst, CG_INST_STORE_VALUE).write(value as *mut u8);
    slot(inst, CG_INST_STORE_ADDRESS).write(address as *mut u8);
    inst as *mut CgInst
}

/// cg_create_inst_branch_label — original: `FUN_082c1878` @ 0x082c1878
/// (32 bytes, 16 `bl` call sites).
///
/// Appends a kind-7 (unconditional branch) instruction: a 20-byte
/// record holding only the target block.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cg_create_inst_branch_label(
    block: *mut CgBlock,
    opcode: u32,
    target: *mut CgBlock,
) -> *mut CgInst {
    let inst = cg_inst_create_base(
        block,
        record_size(CG_INST_BRANCH_LABEL_BYTES),
        CG_INST_KIND_BRANCH_LABEL,
        opcode,
    ) as *mut u8;
    slot(inst, CG_INST_BRANCH_LABEL_TARGET).write(target as *mut u8);
    inst as *mut CgInst
}

/// cg_create_inst_branch_cond — original: `FUN_082c1850` @ 0x082c1850
/// (40 bytes, 41 `bl` call sites).
///
/// Appends a kind-8 (conditional branch) instruction: a 20-byte record
/// holding the target block and the condition register. NOTE the swap,
/// kept from the original: the third argument goes to `+0x10` (the
/// condition) and the fourth to `+0xc` (the target) — the opposite
/// order from every other factory in the family.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cg_create_inst_branch_cond(
    block: *mut CgBlock,
    opcode: u32,
    condition: *mut CgVirtualReg,
    target: *mut CgBlock,
) -> *mut CgInst {
    let inst = cg_inst_create_base(
        block,
        record_size(CG_INST_BRANCH_COND_BYTES),
        CG_INST_KIND_BRANCH_COND,
        opcode,
    ) as *mut u8;
    slot(inst, CG_INST_BRANCH_COND_CONDITION).write(condition as *mut u8);
    slot(inst, CG_INST_BRANCH_COND_TARGET).write(target as *mut u8);
    inst as *mut CgInst
}

/// cg_create_inst_phi — original: `FUN_082c1914` @ 0x082c1914
/// (40 bytes, 75 `bl` call sites).
///
/// Appends a kind-9 (phi) instruction: a 20-byte record holding the
/// destination register and the head of a register list built by
/// `cg_virtual_reg_list_create` (unported: its C varargs ABI has no
/// Rust expression on this target).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cg_create_inst_phi(
    block: *mut CgBlock,
    opcode: u32,
    dest: *mut CgVirtualReg,
    regs: *mut CgVirtualRegList,
) -> *mut CgInst {
    let inst = cg_inst_create_base(
        block,
        record_size(CG_INST_PHI_BYTES),
        CG_INST_KIND_PHI,
        opcode,
    ) as *mut u8;
    slot(inst, CG_INST_PHI_DEST).write(dest as *mut u8);
    slot(inst, CG_INST_PHI_REGS).write(regs as *mut u8);
    inst as *mut CgInst
}

/// cg_create_inst_ret — original: `FUN_082c193c` @ 0x082c193c
/// (16 bytes, 3 `bl` + 1 tail `b` call sites).
///
/// Appends a kind-11 (return) instruction: a 16-byte record with no
/// derived fields at all — the original is a pure tail branch into
/// `cg_inst_create_base`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cg_create_inst_ret(block: *mut CgBlock, opcode: u32) -> *mut CgInst {
    cg_inst_create_base(block, record_size(CG_INST_RET_BYTES), CG_INST_KIND_RET, opcode)
}

/// cg_create_inst_ret_value — original: `FUN_082c194c` @ 0x082c194c
/// (32 bytes, 2 `bl` call sites).
///
/// The value-returning twin of [`cg_create_inst_ret`]: same kind-11,
/// 16-byte record, plus the returned value register at `+0xc`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cg_create_inst_ret_value(
    block: *mut CgBlock,
    opcode: u32,
    value: *mut CgVirtualReg,
) -> *mut CgInst {
    let inst = cg_inst_create_base(
        block,
        record_size(CG_INST_RET_BYTES),
        CG_INST_KIND_RET,
        opcode,
    ) as *mut u8;
    slot(inst, CG_INST_RET_VALUE_VALUE).write(value as *mut u8);
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

    #[test]
    fn unary_stores_dest_and_source_and_leaves_word4_null() {
        let _g = setup();
        let mut f = Fixture::new(4096);
        unsafe {
            let dest = cg_virtual_reg_create(f.proc_ptr(), 1);
            let source = cg_virtual_reg_create(f.proc_ptr(), 1);
            let inst = cg_create_inst_unary(f.block_ptr(), 0x1a, dest, source);
            let raw = inst as *mut u8;
            assert_eq!(inst_kind(inst), CG_INST_KIND_UNARY as u8);
            assert_eq!(inst_opcode(inst), 0x1a);
            assert_eq!(slot(raw, CG_INST_UNARY_DEST).read(), dest as *mut u8);
            assert_eq!(slot(raw, CG_INST_UNARY_SOURCE).read(), source as *mut u8);
            assert!(slot(raw, 4).read().is_null(), "+0x10 stays NULL");
            assert_eq!(f.block[CG_BLOCK_INSTS], inst as usize);
        }
        drop(f);
        teardown();
    }

    #[test]
    fn binary_s_fills_all_four_derived_fields() {
        let _g = setup();
        let mut f = Fixture::new(4096);
        unsafe {
            let dest = cg_virtual_reg_create(f.proc_ptr(), 1);
            let flags = cg_virtual_reg_create(f.proc_ptr(), 1);
            let s0 = cg_virtual_reg_create(f.proc_ptr(), 1);
            let s1 = cg_virtual_reg_create(f.proc_ptr(), 1);
            let inst = cg_create_inst_binary_s(f.block_ptr(), 0x0f, dest, flags, s0, s1);
            let raw = inst as *mut u8;
            assert_eq!(inst_kind(inst), CG_INST_KIND_BINARY_S as u8);
            assert_eq!(inst_opcode(inst), 0x0f);
            assert_eq!(slot(raw, CG_INST_BINARY_DEST).read(), dest as *mut u8);
            assert_eq!(slot(raw, CG_INST_BINARY_DEST_FLAGS).read(), flags as *mut u8);
            assert_eq!(slot(raw, CG_INST_BINARY_SOURCE0).read(), s0 as *mut u8);
            assert_eq!(slot(raw, CG_INST_BINARY_SOURCE1).read(), s1 as *mut u8);
        }
        drop(f);
        teardown();
    }

    #[test]
    fn compare_packs_dest_and_both_sources_one_word_earlier_than_binary() {
        let _g = setup();
        let mut f = Fixture::new(4096);
        unsafe {
            let dest = cg_virtual_reg_create(f.proc_ptr(), 1);
            let s0 = cg_virtual_reg_create(f.proc_ptr(), 1);
            let s1 = cg_virtual_reg_create(f.proc_ptr(), 1);
            let inst = cg_create_inst_compare(f.block_ptr(), 0x30, dest, s0, s1);
            let raw = inst as *mut u8;
            assert_eq!(inst_kind(inst), CG_INST_KIND_COMPARE as u8);
            assert_eq!(inst_opcode(inst), 0x30);
            assert_eq!(slot(raw, CG_INST_COMPARE_DEST).read(), dest as *mut u8);
            assert_eq!(slot(raw, CG_INST_COMPARE_SOURCE0).read(), s0 as *mut u8);
            assert_eq!(slot(raw, CG_INST_COMPARE_SOURCE1).read(), s1 as *mut u8);
            assert!(slot(raw, 6).read().is_null(), "+0x18 stays NULL");
        }
        drop(f);
        teardown();
    }

    #[test]
    fn load_stores_dest_and_address() {
        let _g = setup();
        let mut f = Fixture::new(4096);
        unsafe {
            let dest = cg_virtual_reg_create(f.proc_ptr(), 1);
            let address = cg_virtual_reg_create(f.proc_ptr(), 1);
            let inst = cg_create_inst_load(f.block_ptr(), 0x29, dest, address);
            let raw = inst as *mut u8;
            assert_eq!(inst_kind(inst), CG_INST_KIND_LOAD as u8);
            assert_eq!(inst_opcode(inst), 0x29);
            assert_eq!(slot(raw, CG_INST_LOAD_DEST).read(), dest as *mut u8);
            assert_eq!(slot(raw, CG_INST_LOAD_ADDRESS).read(), address as *mut u8);
            assert!(slot(raw, 5).read().is_null(), "+0x14 stays NULL");
        }
        drop(f);
        teardown();
    }

    #[test]
    fn store_stores_value_and_address() {
        let _g = setup();
        let mut f = Fixture::new(4096);
        unsafe {
            let value = cg_virtual_reg_create(f.proc_ptr(), 1);
            let address = cg_virtual_reg_create(f.proc_ptr(), 1);
            let inst = cg_create_inst_store(f.block_ptr(), 0x2b, value, address);
            let raw = inst as *mut u8;
            assert_eq!(inst_kind(inst), CG_INST_KIND_STORE as u8);
            assert_eq!(inst_opcode(inst), 0x2b);
            assert_eq!(slot(raw, CG_INST_STORE_VALUE).read(), value as *mut u8);
            assert_eq!(slot(raw, CG_INST_STORE_ADDRESS).read(), address as *mut u8);
            assert!(slot(raw, 5).read().is_null(), "+0x14 stays NULL");
        }
        drop(f);
        teardown();
    }

    #[test]
    fn branch_label_stores_only_the_target() {
        let _g = setup();
        let mut f = Fixture::new(4096);
        unsafe {
            let inst = cg_create_inst_branch_label(f.block_ptr(), 0x40, f.block_ptr());
            let raw = inst as *mut u8;
            assert_eq!(inst_kind(inst), CG_INST_KIND_BRANCH_LABEL as u8);
            assert_eq!(inst_opcode(inst), 0x40);
            assert_eq!(slot(raw, CG_INST_BRANCH_LABEL_TARGET).read(), f.block_ptr() as *mut u8);
            assert!(slot(raw, 4).read().is_null(), "+0x10 stays NULL");
        }
        drop(f);
        teardown();
    }

    #[test]
    fn branch_cond_swaps_its_two_derived_fields() {
        // The original stores the THIRD argument at +0x10 and the
        // FOURTH at +0xc — the opposite of every sibling factory.
        let _g = setup();
        let mut f = Fixture::new(4096);
        unsafe {
            let condition = cg_virtual_reg_create(f.proc_ptr(), 1);
            let inst = cg_create_inst_branch_cond(f.block_ptr(), 0x41, condition, f.block_ptr());
            let raw = inst as *mut u8;
            assert_eq!(inst_kind(inst), CG_INST_KIND_BRANCH_COND as u8);
            assert_eq!(inst_opcode(inst), 0x41);
            assert_eq!(slot(raw, CG_INST_BRANCH_COND_CONDITION).read(), condition as *mut u8);
            assert_eq!(slot(raw, CG_INST_BRANCH_COND_TARGET).read(), f.block_ptr() as *mut u8);
        }
        drop(f);
        teardown();
    }

    #[test]
    fn phi_stores_dest_and_the_register_list() {
        let _g = setup();
        let mut f = Fixture::new(4096);
        unsafe {
            let dest = cg_virtual_reg_create(f.proc_ptr(), 1);
            let list = [0usize; 2];
            let inst = cg_create_inst_phi(
                f.block_ptr(),
                0x50,
                dest,
                list.as_ptr() as *mut CgVirtualRegList,
            );
            let raw = inst as *mut u8;
            assert_eq!(inst_kind(inst), CG_INST_KIND_PHI as u8);
            assert_eq!(inst_opcode(inst), 0x50);
            assert_eq!(slot(raw, CG_INST_PHI_DEST).read(), dest as *mut u8);
            assert_eq!(slot(raw, CG_INST_PHI_REGS).read(), list.as_ptr() as *mut u8);
        }
        drop(f);
        teardown();
    }

    #[test]
    fn ret_carries_no_derived_fields() {
        let _g = setup();
        let mut f = Fixture::new(4096);
        unsafe {
            let inst = cg_create_inst_ret(f.block_ptr(), 0x60);
            let raw = inst as *mut u8;
            assert_eq!(inst_kind(inst), CG_INST_KIND_RET as u8);
            assert_eq!(inst_opcode(inst), 0x60);
            assert!(slot(raw, 3).read().is_null(), "+0x0c stays NULL");
            assert_eq!(f.block[CG_BLOCK_INSTS], inst as usize);
        }
        drop(f);
        teardown();
    }

    #[test]
    fn ret_value_stores_the_returned_register() {
        let _g = setup();
        let mut f = Fixture::new(4096);
        unsafe {
            let value = cg_virtual_reg_create(f.proc_ptr(), 1);
            let inst = cg_create_inst_ret_value(f.block_ptr(), 0x60, value);
            let raw = inst as *mut u8;
            assert_eq!(inst_kind(inst), CG_INST_KIND_RET as u8);
            assert_eq!(inst_opcode(inst), 0x60);
            assert_eq!(slot(raw, CG_INST_RET_VALUE_VALUE).read(), value as *mut u8);
        }
        drop(f);
        teardown();
    }

    #[test]
    fn the_whole_family_appends_in_call_order() {
        let _g = setup();
        let mut f = Fixture::new(4096);
        unsafe {
            let r0 = cg_virtual_reg_create(f.proc_ptr(), 1);
            let r1 = cg_virtual_reg_create(f.proc_ptr(), 1);
            let insts = [
                cg_create_inst_unary(f.block_ptr(), 0x1a, r0, r1),
                cg_create_inst_binary_s(f.block_ptr(), 0x0f, r0, r1, r0, r1),
                cg_create_inst_compare(f.block_ptr(), 0x30, r0, r1, r0),
                cg_create_inst_load(f.block_ptr(), 0x29, r0, r1),
                cg_create_inst_store(f.block_ptr(), 0x2b, r0, r1),
                cg_create_inst_branch_label(f.block_ptr(), 0x40, f.block_ptr()),
                cg_create_inst_branch_cond(f.block_ptr(), 0x41, r0, f.block_ptr()),
                cg_create_inst_phi(f.block_ptr(), 0x50, r0, core::ptr::null_mut()),
                cg_create_inst_ret(f.block_ptr(), 0x60),
                cg_create_inst_ret_value(f.block_ptr(), 0x60, r0),
            ];
            assert_eq!(f.block[CG_BLOCK_INSTS], insts[0] as usize, "head");
            assert_eq!(f.block[CG_BLOCK_LAST_INST], insts[9] as usize, "tail");
            for pair in insts.windows(2) {
                assert_eq!(inst_next(pair[0]), pair[1]);
            }
            assert!(inst_next(insts[9]).is_null());
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
