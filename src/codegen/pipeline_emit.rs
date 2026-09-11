//! Emission sugar shared by the JIT's pipeline generators.
//!
//! The rasterizer/fragment-pipeline generators at 0x0823a000-0x0826f5ff
//! build their IR one node at a time through the factories in
//! [`super::ir`]. A handful of three-instruction idioms recur often
//! enough that the compiler emitted them as real out-of-line helpers in
//! the generators' own address block (0x0826xxxx) rather than in the IR
//! library's (0x082cxxxx); this module collects those.

use super::ir::{
    cg_create_inst_binary, cg_create_inst_load, cg_create_inst_load_immed, cg_create_inst_store,
    cg_virtual_reg_create, CgBlock, CgInst, CgProc, CgVirtualReg, CG_BLOCK_PROC,
    CG_INST_OPCODE_ADD, CG_INST_OPCODE_ASR, CG_INST_OPCODE_LDI, CG_INST_OPCODE_LDW,
    CG_INST_OPCODE_MUL, CG_INST_OPCODE_RSB, CG_INST_OPCODE_STW, CG_INST_OPCODE_SUB,
    CG_REG_TYPE_GENERAL,
};

/// The procedure owning `block` (`cg_block_t + 0x04`).
#[inline(always)]
unsafe fn block_proc(block: *mut CgBlock) -> *mut CgProc {
    (block as *mut *mut u8).add(CG_BLOCK_PROC).read() as *mut CgProc
}

/// cg_emit_load_word_at_offset — original: `FUN_082605f0` @ 0x082605f0
/// (136 bytes: 34 instruction words, no literal pool — the next function
/// starts at 0x08260678 with its own `stmdb sp!,{r3,r4,r5,r6,r7,r8,r9,lr}`).
///
/// 44 call sites, all unconditional `bl` (no predicated calls, no tail
/// `b`), binary-scanned by decoding every branch word in osos.dec. They
/// sit in three runs inside the pipeline generators — 0x08243a28-0x082447e8,
/// 0x08245680-0x0824575c and 0x08245830-0x08245cc8 — which call it as
/// `FUN_082605f0(block, base, offset)` with offsets like 0x1c, 0x20, 0x24,
/// 0x28, 0x2c and `n * 4 + 0x6c`: word-strided structure fields.
///
/// Emits the three-instruction "load the word at `base + offset`" idiom
/// into `block` and returns the register holding the loaded value:
///
/// ```text
/// LDI  offset_reg, offset
/// ADD  address_reg, base, offset_reg
/// LDW  value_reg, [address_reg]
/// ```
///
/// All three destination registers are general-purpose and are created
/// up front, before any instruction is appended — the original allocates
/// r7/r8/r9 from three back-to-back `cg_virtual_reg_create` calls and
/// only then emits, so the registers are numbered in creation order
/// rather than in use order.
///
/// # Deviations
///
/// The original reloads `block->proc` from `block + 4` before each of the
/// three register creations; the port reads it once. The field is not
/// written in between, so the observable call sequence is identical.
///
/// `FUN_082606f4` @ 0x082606f4 is a separately linked, behaviorally
/// identical emission of this helper. Its exact 136-byte (34-word) extent
/// ends at the next prologue at 0x0826077c; six `bl` encodings differ from
/// this body only by their relative displacement and reach the same six
/// callees in the same order. Raw decoding finds 12 call sites, all
/// unconditional `bl` (no predicated calls or tail branches), all within
/// `FUN_082465bc` at 0x08246624-0x08246944.
///
/// `FUN_0823a830` @ 0x0823a830 is a third 136-byte (34-word), separately
/// linked emission. Its last instruction is the `pop` at 0x0823a8b4; the
/// next sibling starts at 0x0823a8b8. A word-by-word comparison finds six
/// differences, all relative `bl` encodings to the same three
/// `cg_virtual_reg_create` calls and the same three instruction factories.
/// Decoding every ARM B/BL word in osos.dec finds nine direct call sites,
/// all unconditional `bl` (no predicated calls or tail branches):
/// 0x0823d180, 0x0823d194, 0x0823d244, 0x0823d2b0, 0x0823d308, 0x0823d7dc,
/// 0x0823db10, 0x0823eb3c, and 0x0823fcac. It therefore shares this
/// implementation and its host coverage; a duplicate export would add no
/// behavior.
///
/// `FUN_0826b198` @ 0x0826b198 is a fourth separately linked copy (136
/// bytes, 34 words, no literal pool) with 10 unconditional `bl` callers:
/// 0x08249b04, 0x08249b18, 0x08249b2c, 0x08249b50, 0x08249d04,
/// 0x08249d1c, 0x0824a250, 0x0824a264, 0x0824a278 and 0x0824a28c. Raw
/// word comparison against 0x082605f0 differs only in the six relative
/// call encodings; it shares this implementation and its host tests.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cg_emit_load_word_at_offset(
    block: *mut CgBlock,
    base: *mut CgVirtualReg,
    offset: usize,
) -> *mut CgVirtualReg {
    let proc = block_proc(block);
    let offset_reg = cg_virtual_reg_create(proc, CG_REG_TYPE_GENERAL);
    let address_reg = cg_virtual_reg_create(proc, CG_REG_TYPE_GENERAL);
    let value_reg = cg_virtual_reg_create(proc, CG_REG_TYPE_GENERAL);

    cg_create_inst_load_immed(block, CG_INST_OPCODE_LDI, offset_reg, offset);
    cg_create_inst_binary(block, CG_INST_OPCODE_ADD, address_reg, base, offset_reg);
    cg_create_inst_load(block, CG_INST_OPCODE_LDW, value_reg, address_reg);

    value_reg
}

/// cg_emit_store_word_at_offset — original: `FUN_08260678` @ 0x08260678
/// (124 bytes: 31 instruction words 0x08260678-0x082606f0, no literal
/// pool; the last word is a tail `b` to `cg_create_inst_store`, and the
/// next function's own `stmdb sp!,{r3,r4,r5,r6,r7,r8,r9,lr}` starts at
/// 0x082606f4 — Ghidra's 124-byte extent is exact).
///
/// 17 call sites: 16 unconditional `bl` plus one tail `b` at 0x08246fa8,
/// no predicated forms, binary-scanned by decoding every branch word in
/// osos.dec. They sit in one run inside the pipeline generators,
/// 0x08246f2c-0x08248538 — the same generator group that calls
/// [`cg_emit_load_matrix4x4_word`].
///
/// The store twin of [`cg_emit_load_word_at_offset`]: emits the
/// three-instruction "store `value` to the word at `base + offset`"
/// idiom into `block` and returns the appended store instruction:
///
/// ```text
/// LDI  offset_reg, offset
/// ADD  address_reg, base, offset_reg
/// STW  [address_reg], value
/// ```
///
/// Only two virtual registers are created — the value arrives as an
/// argument rather than being loaded, so there is no `value_reg`.
/// Both are general-purpose and are created up front, before any
/// instruction is appended (two back-to-back `cg_virtual_reg_create`
/// calls into r6/r7), so they are numbered in creation order rather
/// than in use order. The final store is a tail call, so the factory's
/// return value reaches the caller directly.
///
/// # Deviations
///
/// The original reloads `block->proc` from `block + 4` before each of
/// the two register creations; the port reads it once. The field is not
/// written in between, so the observable call sequence is identical
/// (same deviation as the load sibling).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cg_emit_store_word_at_offset(
    block: *mut CgBlock,
    base: *mut CgVirtualReg,
    offset: usize,
    value: *mut CgVirtualReg,
) -> *mut CgInst {
    let proc = block_proc(block);
    let offset_reg = cg_virtual_reg_create(proc, CG_REG_TYPE_GENERAL);
    let address_reg = cg_virtual_reg_create(proc, CG_REG_TYPE_GENERAL);

    cg_create_inst_load_immed(block, CG_INST_OPCODE_LDI, offset_reg, offset);
    cg_create_inst_binary(block, CG_INST_OPCODE_ADD, address_reg, base, offset_reg);
    cg_create_inst_store(block, CG_INST_OPCODE_STW, value, address_reg)
}

/// cg_emit_load_matrix4x4_word — original: `FUN_082469b8` @ 0x082469b8
/// (144 bytes: 36 instruction words 0x082469b8-0x08246a44, no literal
/// pool — the next function starts at 0x08246a48 with its own
/// `stmdb sp!,{r0,r1,r2,r3,r4,r5,r6,r7,r8,r9,sl,fp,lr}`).
///
/// 36 call sites, all unconditional `bl` (no predicated forms, no tail
/// `b`), verified by decoding every branch word in osos.dec; they sit in
/// one run inside the pipeline generators 0x082470d4-0x08248494, which
/// call it as `FUN_082469b8(ctx, block, base, col, row)` with both
/// indices in 0..=3 — the fragment pipeline's 4x4 matrix state.
///
/// The computed-offset sibling of [`cg_emit_load_word_at_offset`]:
/// emits the three-instruction "load element `col + 4*row` of a
/// row-major 4-column word matrix" idiom into `block` and returns the
/// register holding the loaded value:
///
/// ```text
/// LDI  offset_reg, 4 * (col + 4 * row)
/// ADD  address_reg, base, offset_reg
/// LDW  value_reg, [address_reg]
/// ```
///
/// All three destination registers are general-purpose and are created
/// up front (three back-to-back `cg_virtual_reg_create` calls into
/// r6/r7/r8), before any instruction is appended, so they are numbered
/// in creation order rather than in use order.
///
/// # Deviations
///
/// - The original takes a leading argument in r0 that is dead on
///   arrival: the first instruction after the prologue overwrites r0
///   with the stacked fifth argument (`ldr r0,[sp,#0x20]`) and the
///   incoming value is never read. Every caller passes its own context
///   pointer there. The port keeps the parameter for ABI parity and
///   never touches it.
/// - The original reloads `block->proc` from `block + 4` before each of
///   the three register creations; the port reads it once. The field is
///   not written in between, so the observable call sequence is
///   identical (same deviation as the sibling helper).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cg_emit_load_matrix4x4_word(
    _ctx: *mut u8,
    block: *mut CgBlock,
    base: *mut CgVirtualReg,
    col: usize,
    row: usize,
) -> *mut CgVirtualReg {
    let offset = (col + row * 4) * 4;
    let proc = block_proc(block);
    let offset_reg = cg_virtual_reg_create(proc, CG_REG_TYPE_GENERAL);
    let address_reg = cg_virtual_reg_create(proc, CG_REG_TYPE_GENERAL);
    let value_reg = cg_virtual_reg_create(proc, CG_REG_TYPE_GENERAL);

    cg_create_inst_load_immed(block, CG_INST_OPCODE_LDI, offset_reg, offset);
    cg_create_inst_binary(block, CG_INST_OPCODE_ADD, address_reg, base, offset_reg);
    cg_create_inst_load(block, CG_INST_OPCODE_LDW, value_reg, address_reg);

    value_reg
}

/// cg_emit_subtract — original: `FUN_0824035c` @ 0x0824035c
/// (60 bytes: 15 instruction words, 0x0824035c-0x082403598; raw bytes
/// verified — Ghidra's reported 64-byte extent includes four bytes past
/// the function, and the next function starts at 0x0824039c).
///
/// 20 call sites, all unconditional `bl` (no predicated forms and no tail
/// `b`), verified by decoding every branch word in osos.dec. The sites all
/// occur in the fragment-pipeline generator at 0x0823dac4-0x0823f634.
///
/// Creates one general-purpose destination virtual register from
/// `block->proc`, then appends the binary instruction `dest = lhs - rhs`
/// (IR opcode 13) to `block`, returning `dest`. Opcode 13 is subtraction:
/// the JIT emitter's opcode dispatch at 0x082c6430 maps it to ARM data
/// processing opcode 2 (`sub`).
///
/// # Deviations
///
/// The leading context argument is dead on arrival in the original (r0 is
/// overwritten by `ldr r0,[r1,#4]` before any use). The port preserves that
/// ABI parameter and intentionally never reads it.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cg_emit_subtract(
    _ctx: *mut u8,
    block: *mut CgBlock,
    lhs: *mut CgVirtualReg,
    rhs: *mut CgVirtualReg,
) -> *mut CgVirtualReg {
    let dest = cg_virtual_reg_create(block_proc(block), CG_REG_TYPE_GENERAL);
    cg_create_inst_binary(block, CG_INST_OPCODE_SUB, dest, lhs, rhs);
    dest
}

/// cg_emit_negated_sum — original: `FUN_0823c0dc` @ 0x0823c0dc
/// (144 bytes: 36 instruction words, 0x0823c0dc-0x0823c168; raw bytes
/// verified — the next function begins at 0x0823c16c with its own `push`).
///
/// 10 call sites, all unconditional `bl` (no predicated forms and no tail
/// `b`), verified by decoding every ARM B/BL word in osos.dec:
/// 0x0823e6d0, 0x0823e6e8, 0x0823e700, 0x0823e864, 0x0823e87c,
/// 0x0823e894, 0x0823f4dc, 0x0823f4f4, 0x0823f50c and 0x0823f524.
///
/// Creates three general-purpose virtual registers, then appends
/// `LDI mask_reg, 0xff`, `ADD sum_reg, lhs, rhs`, and
/// `RSB result, sum_reg, mask_reg`, returning `result`. The opcode-15
/// backend emits `rsb result, sum_reg, #0`, so its binary record's
/// `mask_reg` source is intentionally ignored; the original nevertheless
/// creates and records the 0xff source exactly as above.
///
/// # Deviations
///
/// The leading context argument is dead on arrival: the first non-prologue
/// instruction reads `block->proc` into r5 before r0 is ever read. The port
/// keeps the ABI parameter and intentionally never dereferences it.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cg_emit_negated_sum(
    _ctx: *mut u8,
    block: *mut CgBlock,
    lhs: *mut CgVirtualReg,
    rhs: *mut CgVirtualReg,
) -> *mut CgVirtualReg {
    let proc = block_proc(block);
    let sum_reg = cg_virtual_reg_create(proc, CG_REG_TYPE_GENERAL);
    let mask_reg = cg_virtual_reg_create(proc, CG_REG_TYPE_GENERAL);
    cg_create_inst_load_immed(block, CG_INST_OPCODE_LDI, mask_reg, 0xff);

    let result = cg_virtual_reg_create(proc, CG_REG_TYPE_GENERAL);
    cg_create_inst_binary(block, CG_INST_OPCODE_ADD, sum_reg, lhs, rhs);
    cg_create_inst_binary(block, CG_INST_OPCODE_RSB, result, sum_reg, mask_reg);
    result
}

/// cg_emit_lerp_u8 — original: `FUN_08240738` @ 0x08240738
/// (112 bytes: 28 instruction words, 0x08240738-0x082407a4; the next
/// function starts at 0x082407a8 with its own `push`).
///
/// 11 call sites, all unconditional `bl` (no predicated forms or tail
/// branches), verified by decoding every ARM B/BL word in osos.dec:
/// 0x0823e038, 0x0823e180, 0x0823e1a0, 0x0823e1c0, 0x0823e79c,
/// 0x0823e7bc, 0x0823e7dc, 0x0823e968, 0x0823e984, 0x0823e9a0 and
/// 0x082407f8. The ten pipeline-generator sites interpolate values, while
/// 0x082407f8 is the sibling wrapper `FUN_082407a8`.
///
/// Emits `start + (end - start) * factor / 255`. The signed product uses
/// the retailOS divide-by-255 idiom: `product + (product >> 8)`, then
/// another arithmetic shift right by 8. This is not division by 256:
/// it yields `floor(product * 257 / 65536)`, including the original's
/// signed-rounding behavior.
///
/// # Deviations
///
/// The original emits the normalized multiply through its unported helper
/// `FUN_08240658`; this port writes that helper's five register creations
/// and five instruction emissions inline, in their original order. The
/// observable IR is identical and avoids adding an unverified dispatch seam.
/// The leading context argument is dead on arrival (saved into r6 but never
/// read); it is retained for ABI parity and deliberately ignored.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cg_emit_lerp_u8(
    _ctx: *mut u8,
    block: *mut CgBlock,
    start: *mut CgVirtualReg,
    end: *mut CgVirtualReg,
    factor: *mut CgVirtualReg,
) -> *mut CgVirtualReg {
    let delta = cg_virtual_reg_create(block_proc(block), CG_REG_TYPE_GENERAL);
    cg_create_inst_binary(block, CG_INST_OPCODE_SUB, delta, end, start);

    let product = cg_virtual_reg_create(block_proc(block), CG_REG_TYPE_GENERAL);
    let shift = cg_virtual_reg_create(block_proc(block), CG_REG_TYPE_GENERAL);
    cg_create_inst_load_immed(block, CG_INST_OPCODE_LDI, shift, 8);
    let product_shifted = cg_virtual_reg_create(block_proc(block), CG_REG_TYPE_GENERAL);
    let rounded_product = cg_virtual_reg_create(block_proc(block), CG_REG_TYPE_GENERAL);
    let scaled = cg_virtual_reg_create(block_proc(block), CG_REG_TYPE_GENERAL);
    cg_create_inst_binary(block, CG_INST_OPCODE_MUL, product, delta, factor);
    cg_create_inst_binary(
        block,
        CG_INST_OPCODE_ASR,
        product_shifted,
        product,
        shift,
    );
    cg_create_inst_binary(
        block,
        CG_INST_OPCODE_ADD,
        rounded_product,
        product,
        product_shifted,
    );
    cg_create_inst_binary(block, CG_INST_OPCODE_ASR, scaled, rounded_product, shift);

    let result = cg_virtual_reg_create(block_proc(block), CG_REG_TYPE_GENERAL);
    cg_create_inst_binary(block, CG_INST_OPCODE_ADD, result, start, scaled);
    result
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::super::heap::{CgHeap, CgHeapBlock};
    use super::super::ir::{
        CG_BLOCK_INSTS, CG_INST_BINARY_DEST, CG_INST_BINARY_SOURCE0, CG_INST_BINARY_SOURCE1,
        CG_INST_KIND, CG_INST_KIND_BINARY, CG_INST_KIND_LOAD, CG_INST_KIND_LOAD_IMMED,
        CG_INST_KIND_STORE,
        CG_INST_LOAD_ADDRESS, CG_INST_LOAD_DEST, CG_INST_LOAD_IMMED_DEST,
        CG_INST_LOAD_IMMED_VALUE, CG_INST_NEXT, CG_INST_STORE_ADDRESS, CG_INST_STORE_VALUE,
        CG_MODULE_HEAP, CG_PROC_MODULE, CG_PROC_NEXT,
        CG_PROC_NUM_REGISTERS, CG_VREG_NEXT, CG_VREG_NO, CG_VREG_TYPE,
    };
    use super::*;

    const WORD: usize = core::mem::size_of::<*mut u8>();

    /// A module, a procedure and a block over one pre-sized arena block.
    ///
    /// The arena is built by hand rather than through `cg_heap_create` so
    /// the fixture never touches the crate-global `CG_HEAP_OPS` (whose
    /// wired default allocator is the firmware heap, unmapped on hosts).
    /// The payload is large enough that `cg_heap_alloc` always carves
    /// from this one block and never asks for another.
    #[repr(align(8))]
    struct Arena([u8; 8192]);

    struct Fixture {
        arena: Arena,
        block_header: CgHeapBlock,
        heap: CgHeap,
        module: [usize; 2],
        proc: [usize; 9],
        block: [usize; 5],
    }

    impl Fixture {
        fn new() -> std::boxed::Box<Fixture> {
            let mut f = std::boxed::Box::new(Fixture {
                arena: Arena([0; 8192]),
                block_header: CgHeapBlock {
                    next: core::ptr::null_mut(),
                    base: core::ptr::null_mut(),
                    total: 0,
                    current: 0,
                },
                heap: CgHeap {
                    current: core::ptr::null_mut(),
                    block_size: 8192,
                },
                module: [0; 2],
                proc: [0; 9],
                block: [0; 5],
            });
            f.block_header.base = f.arena.0.as_mut_ptr();
            f.block_header.total = f.arena.0.len();
            f.heap.current = &mut f.block_header as *mut CgHeapBlock;
            f.module[CG_MODULE_HEAP] = &mut f.heap as *mut CgHeap as usize;
            f.proc[CG_PROC_MODULE] = f.module.as_ptr() as usize;
            f.block[CG_BLOCK_PROC] = f.proc.as_ptr() as usize;
            f
        }

        fn block_ptr(&mut self) -> *mut CgBlock {
            self.block.as_mut_ptr() as *mut CgBlock
        }
    }

    unsafe fn field(record: *mut u8, index: usize) -> usize {
        (record as *mut usize).add(index).read()
    }

    unsafe fn inst_kind(inst: *mut u8) -> u8 {
        inst.add(CG_INST_KIND * WORD).read()
    }

    unsafe fn inst_opcode(inst: *mut u8) -> u8 {
        inst.add(CG_INST_KIND * WORD + 1).read()
    }

    /// The three instructions the helper appended, in block order.
    unsafe fn emitted(f: &mut Fixture) -> [*mut u8; 3] {
        let mut inst = f.block[CG_BLOCK_INSTS] as *mut u8;
        let mut out = [core::ptr::null_mut(); 3];
        for slot in out.iter_mut() {
            assert!(!inst.is_null(), "the block holds three instructions");
            *slot = inst;
            inst = field(inst, CG_INST_NEXT) as *mut u8;
        }
        assert!(inst.is_null(), "the block holds exactly three instructions");
        out
    }
    #[test]
    fn emits_subtract_with_opaque_context_and_operands() {
        let mut f = Fixture::new();
        let block = f.block_ptr();
        let dest = unsafe {
            cg_emit_subtract(
                usize::MAX as *mut u8,
                block,
                core::ptr::null_mut(),
                1 as *mut CgVirtualReg,
            )
        };

        unsafe {
            let inst = f.block[CG_BLOCK_INSTS] as *mut u8;
            assert!(!inst.is_null(), "the binary instruction was appended");
            assert!(field(inst, CG_INST_NEXT) == 0, "the block holds one instruction");
            assert_eq!(inst_kind(inst), CG_INST_KIND_BINARY as u8);
            assert_eq!(inst_opcode(inst), CG_INST_OPCODE_SUB as u8);
            assert_eq!(field(inst, CG_INST_BINARY_DEST), dest as usize);
            assert_eq!(
                field(inst, CG_INST_BINARY_SOURCE0),
                0,
                "a NULL lhs passes through unexamined"
            );
            assert_eq!(
                field(inst, CG_INST_BINARY_SOURCE1),
                1,
                "the rhs is recorded without dereferencing it"
            );
            assert_eq!(field(dest as *mut u8, CG_VREG_NO), 0);
            assert_eq!(
                (dest as *mut u8).add(CG_VREG_TYPE * WORD).read(),
                CG_REG_TYPE_GENERAL as u8
            );
        }
        assert_eq!(f.proc[CG_PROC_NUM_REGISTERS], 1);
    }

    #[test]
    fn emits_negated_sum_with_dead_mask_source() {
        const LHS: usize = 0x1234_0000;
        const RHS: usize = 0x5678_0000;

        let mut f = Fixture::new();
        let block = f.block_ptr();
        let result = unsafe {
            cg_emit_negated_sum(
                usize::MAX as *mut u8,
                block,
                LHS as *mut CgVirtualReg,
                RHS as *mut CgVirtualReg,
            )
        };

        unsafe {
            let [ldi, add, rsb] = emitted(&mut f);

            assert_eq!(inst_kind(ldi), CG_INST_KIND_LOAD_IMMED as u8);
            assert_eq!(inst_opcode(ldi), CG_INST_OPCODE_LDI as u8);
            let mask_reg = field(ldi, CG_INST_LOAD_IMMED_DEST);
            assert_eq!(field(ldi, CG_INST_LOAD_IMMED_VALUE), 0xff);
            assert_eq!(field(mask_reg as *mut u8, CG_VREG_NO), 1);

            assert_eq!(inst_kind(add), CG_INST_KIND_BINARY as u8);
            assert_eq!(inst_opcode(add), CG_INST_OPCODE_ADD as u8);
            let sum_reg = field(add, CG_INST_BINARY_DEST);
            assert_eq!(field(sum_reg as *mut u8, CG_VREG_NO), 0);
            assert_eq!(field(add, CG_INST_BINARY_SOURCE0), LHS);
            assert_eq!(field(add, CG_INST_BINARY_SOURCE1), RHS);

            assert_eq!(inst_kind(rsb), CG_INST_KIND_BINARY as u8);
            assert_eq!(inst_opcode(rsb), CG_INST_OPCODE_RSB as u8);
            assert_eq!(field(rsb, CG_INST_BINARY_DEST), result as usize);
            assert_eq!(field(result as *mut u8, CG_VREG_NO), 2);
            assert_eq!(field(rsb, CG_INST_BINARY_SOURCE0), sum_reg);
            assert_eq!(field(rsb, CG_INST_BINARY_SOURCE1), mask_reg);
        }
        assert_eq!(f.proc[CG_PROC_NUM_REGISTERS], 3);
    }


    #[test]
    fn emits_ldi_add_ldw_wired_through_fresh_registers() {
        const BASE: usize = 0xdead_be00;
        const OFFSET: usize = 0x6c;

        let mut f = Fixture::new();
        let block = f.block_ptr();
        let value = unsafe { cg_emit_load_word_at_offset(block, BASE as *mut CgVirtualReg, OFFSET) };

        unsafe {
            let [ldi, add, ldw] = emitted(&mut f);

            assert_eq!(inst_kind(ldi), CG_INST_KIND_LOAD_IMMED as u8);
            assert_eq!(inst_opcode(ldi), CG_INST_OPCODE_LDI as u8);
            assert_eq!(field(ldi, CG_INST_LOAD_IMMED_VALUE), OFFSET);

            assert_eq!(inst_kind(add), CG_INST_KIND_BINARY as u8);
            assert_eq!(inst_opcode(add), CG_INST_OPCODE_ADD as u8);
            assert_eq!(
                field(add, CG_INST_BINARY_SOURCE0),
                BASE,
                "the caller's base register is source0"
            );
            assert_eq!(
                field(add, CG_INST_BINARY_SOURCE1),
                field(ldi, CG_INST_LOAD_IMMED_DEST),
                "the materialized offset is source1"
            );

            assert_eq!(inst_kind(ldw), CG_INST_KIND_LOAD as u8);
            assert_eq!(inst_opcode(ldw), CG_INST_OPCODE_LDW as u8);
            assert_eq!(
                field(ldw, CG_INST_LOAD_ADDRESS),
                field(add, CG_INST_BINARY_DEST),
                "the load reads through the sum"
            );
            assert_eq!(
                field(ldw, CG_INST_LOAD_DEST),
                value as usize,
                "the returned register is the load's destination"
            );
        }
    }

    #[test]
    fn creates_three_general_registers_numbered_in_creation_order() {
        let mut f = Fixture::new();
        let block = f.block_ptr();
        unsafe { cg_emit_load_word_at_offset(block, core::ptr::null_mut(), 0) };

        assert_eq!(
            f.proc[CG_PROC_NUM_REGISTERS], 3,
            "exactly three registers were created"
        );

        unsafe {
            // The procedure's register list is built by prepend-at-tail in
            // cg_virtual_reg_create; walk it and check numbering and class.
            let [ldi, add, ldw] = emitted(&mut f);
            let offset_reg = field(ldi, CG_INST_LOAD_IMMED_DEST) as *mut u8;
            let address_reg = field(add, CG_INST_BINARY_DEST) as *mut u8;
            let value_reg = field(ldw, CG_INST_LOAD_DEST) as *mut u8;

            for (index, reg) in [offset_reg, address_reg, value_reg].iter().enumerate() {
                assert_eq!(field(*reg, CG_VREG_NO), index, "register numbered by creation");
                assert_eq!(
                    reg.add(CG_VREG_TYPE * WORD).read(),
                    CG_REG_TYPE_GENERAL as u8,
                    "general-purpose register class"
                );
            }
            assert_eq!(
                field(offset_reg, CG_VREG_NEXT) as *mut u8,
                address_reg,
                "the offset register is created before the address register"
            );
            assert_eq!(
                field(address_reg, CG_VREG_NEXT) as *mut u8,
                value_reg,
                "the address register is created before the value register"
            );
        }
    }

    #[test]
    fn a_zero_offset_still_materializes_a_constant_and_an_add() {
        let mut f = Fixture::new();
        let block = f.block_ptr();
        unsafe { cg_emit_load_word_at_offset(block, core::ptr::null_mut(), 0) };

        unsafe {
            let [ldi, add, _] = emitted(&mut f);
            assert_eq!(field(ldi, CG_INST_LOAD_IMMED_VALUE), 0);
            assert_eq!(
                field(add, CG_INST_BINARY_SOURCE0),
                0,
                "a NULL base is passed through unexamined"
            );
        }
    }

    #[test]
    fn successive_calls_append_and_keep_numbering_running() {
        let mut f = Fixture::new();
        let block = f.block_ptr();
        unsafe {
            cg_emit_load_word_at_offset(block, core::ptr::null_mut(), 0x1c);
            cg_emit_load_word_at_offset(block, core::ptr::null_mut(), usize::MAX);
        }

        assert_eq!(f.proc[CG_PROC_NUM_REGISTERS], 6);
        assert_eq!(
            f.proc[CG_PROC_NEXT], 0,
            "the helper never touches the procedure's list link"
        );

        unsafe {
            let mut inst = f.block[CG_BLOCK_INSTS] as *mut u8;
            let mut values = std::vec::Vec::new();
            while !inst.is_null() {
                if inst_kind(inst) == CG_INST_KIND_LOAD_IMMED as u8 {
                    values.push(field(inst, CG_INST_LOAD_IMMED_VALUE));
                }
                inst = field(inst, CG_INST_NEXT) as *mut u8;
            }
            assert_eq!(
                values,
                std::vec![0x1c, usize::MAX],
                "both offsets reached their load-immediate in call order"
            );
        }
    }

    #[test]
    fn store_emits_ldi_add_stw_wired_through_fresh_registers() {
        const BASE: usize = 0xdead_be00;
        const OFFSET: usize = 0x2c;
        const VALUE: usize = 0xc0ffee;

        let mut f = Fixture::new();
        let block = f.block_ptr();
        let store = unsafe {
            cg_emit_store_word_at_offset(
                block,
                BASE as *mut CgVirtualReg,
                OFFSET,
                VALUE as *mut CgVirtualReg,
            )
        };

        unsafe {
            let [ldi, add, stw] = emitted(&mut f);

            assert_eq!(inst_kind(ldi), CG_INST_KIND_LOAD_IMMED as u8);
            assert_eq!(inst_opcode(ldi), CG_INST_OPCODE_LDI as u8);
            assert_eq!(field(ldi, CG_INST_LOAD_IMMED_VALUE), OFFSET);

            assert_eq!(inst_kind(add), CG_INST_KIND_BINARY as u8);
            assert_eq!(inst_opcode(add), CG_INST_OPCODE_ADD as u8);
            assert_eq!(
                field(add, CG_INST_BINARY_SOURCE0),
                BASE,
                "the caller's base register is source0"
            );
            assert_eq!(
                field(add, CG_INST_BINARY_SOURCE1),
                field(ldi, CG_INST_LOAD_IMMED_DEST),
                "the materialized offset is source1"
            );

            assert_eq!(inst_kind(stw), CG_INST_KIND_STORE as u8);
            assert_eq!(inst_opcode(stw), CG_INST_OPCODE_STW as u8);
            assert_eq!(
                field(stw, CG_INST_STORE_VALUE),
                VALUE,
                "the caller's value register is stored without dereferencing it"
            );
            assert_eq!(
                field(stw, CG_INST_STORE_ADDRESS),
                field(add, CG_INST_BINARY_DEST),
                "the store writes through the sum"
            );
            assert_eq!(
                store as *mut u8, stw,
                "the tail-called factory's instruction is returned"
            );
        }
    }

    #[test]
    fn store_creates_two_general_registers_numbered_in_creation_order() {
        let mut f = Fixture::new();
        let block = f.block_ptr();
        unsafe {
            cg_emit_store_word_at_offset(
                block,
                core::ptr::null_mut(),
                0,
                core::ptr::null_mut(),
            )
        };

        assert_eq!(
            f.proc[CG_PROC_NUM_REGISTERS], 2,
            "exactly two registers were created — the value is an argument"
        );

        unsafe {
            let [ldi, add, _] = emitted(&mut f);
            let offset_reg = field(ldi, CG_INST_LOAD_IMMED_DEST) as *mut u8;
            let address_reg = field(add, CG_INST_BINARY_DEST) as *mut u8;

            for (index, reg) in [offset_reg, address_reg].iter().enumerate() {
                assert_eq!(field(*reg, CG_VREG_NO), index, "register numbered by creation");
                assert_eq!(
                    reg.add(CG_VREG_TYPE * WORD).read(),
                    CG_REG_TYPE_GENERAL as u8,
                    "general-purpose register class"
                );
            }
            assert_eq!(
                field(offset_reg, CG_VREG_NEXT) as *mut u8,
                address_reg,
                "the offset register is created before the address register"
            );
        }
    }

    #[test]
    fn store_with_zero_offset_and_null_operands_still_emits_all_three() {
        let mut f = Fixture::new();
        let block = f.block_ptr();
        unsafe {
            cg_emit_store_word_at_offset(
                block,
                core::ptr::null_mut(),
                0,
                core::ptr::null_mut(),
            )
        };

        unsafe {
            let [ldi, add, stw] = emitted(&mut f);
            assert_eq!(field(ldi, CG_INST_LOAD_IMMED_VALUE), 0);
            assert_eq!(
                field(add, CG_INST_BINARY_SOURCE0),
                0,
                "a NULL base is passed through unexamined"
            );
            assert_eq!(
                field(stw, CG_INST_STORE_VALUE),
                0,
                "a NULL value is passed through unexamined"
            );
        }
    }

    #[test]
    fn successive_store_calls_append_and_keep_numbering_running() {
        let mut f = Fixture::new();
        let block = f.block_ptr();
        unsafe {
            cg_emit_store_word_at_offset(block, core::ptr::null_mut(), 0x1c, 1 as *mut CgVirtualReg);
            cg_emit_store_word_at_offset(
                block,
                core::ptr::null_mut(),
                usize::MAX,
                core::ptr::null_mut(),
            );
        }

        assert_eq!(f.proc[CG_PROC_NUM_REGISTERS], 4);
        assert_eq!(
            f.proc[CG_PROC_NEXT], 0,
            "the helper never touches the procedure's list link"
        );

        unsafe {
            let mut inst = f.block[CG_BLOCK_INSTS] as *mut u8;
            let mut values = std::vec::Vec::new();
            while !inst.is_null() {
                if inst_kind(inst) == CG_INST_KIND_LOAD_IMMED as u8 {
                    values.push(field(inst, CG_INST_LOAD_IMMED_VALUE));
                }
                inst = field(inst, CG_INST_NEXT) as *mut u8;
            }
            assert_eq!(
                values,
                std::vec![0x1c, usize::MAX],
                "both offsets reached their load-immediate in call order"
            );
        }
    }

    #[test]
    fn matrix_load_emits_ldi_add_ldw_with_computed_offset() {
        const BASE: usize = 0xdead_be00;

        let mut f = Fixture::new();
        let block = f.block_ptr();
        // col = 3, row = 2 -> element 11 -> byte offset 44.
        let value = unsafe {
            cg_emit_load_matrix4x4_word(usize::MAX as *mut u8, block, BASE as *mut CgVirtualReg, 3, 2)
        };

        unsafe {
            let [ldi, add, ldw] = emitted(&mut f);

            assert_eq!(inst_kind(ldi), CG_INST_KIND_LOAD_IMMED as u8);
            assert_eq!(inst_opcode(ldi), CG_INST_OPCODE_LDI as u8);
            assert_eq!(field(ldi, CG_INST_LOAD_IMMED_VALUE), 44);

            assert_eq!(inst_kind(add), CG_INST_KIND_BINARY as u8);
            assert_eq!(inst_opcode(add), CG_INST_OPCODE_ADD as u8);
            assert_eq!(field(add, CG_INST_BINARY_SOURCE0), BASE);
            assert_eq!(
                field(add, CG_INST_BINARY_SOURCE1),
                field(ldi, CG_INST_LOAD_IMMED_DEST)
            );

            assert_eq!(inst_kind(ldw), CG_INST_KIND_LOAD as u8);
            assert_eq!(inst_opcode(ldw), CG_INST_OPCODE_LDW as u8);
            assert_eq!(field(ldw, CG_INST_LOAD_ADDRESS), field(add, CG_INST_BINARY_DEST));
            assert_eq!(field(ldw, CG_INST_LOAD_DEST), value as usize);
        }
    }

    #[test]
    fn matrix_load_offset_is_col_plus_4_times_row_scaled_by_word() {
        let mut f = Fixture::new();
        let block = f.block_ptr();
        for row in 0..4usize {
            for col in 0..4usize {
                unsafe {
                    cg_emit_load_matrix4x4_word(
                        core::ptr::null_mut(),
                        block,
                        core::ptr::null_mut(),
                        col,
                        row,
                    )
                };
            }
        }

        assert_eq!(f.proc[CG_PROC_NUM_REGISTERS], 48, "16 loads x 3 registers");

        unsafe {
            let mut inst = f.block[CG_BLOCK_INSTS] as *mut u8;
            let mut immediates = std::vec::Vec::new();
            while !inst.is_null() {
                if inst_kind(inst) == CG_INST_KIND_LOAD_IMMED as u8 {
                    immediates.push(field(inst, CG_INST_LOAD_IMMED_VALUE));
                }
                inst = field(inst, CG_INST_NEXT) as *mut u8;
            }
            let expected: std::vec::Vec<usize> =
                (0..4).flat_map(|row| (0..4).map(move |col| (col + row * 4) * 4)).collect();
            assert_eq!(immediates, expected, "row-major byte offsets in call order");
        }
    }

    #[test]
    fn matrix_load_registers_are_general_and_numbered_in_creation_order() {
        let mut f = Fixture::new();
        let block = f.block_ptr();
        unsafe { cg_emit_load_matrix4x4_word(core::ptr::null_mut(), block, core::ptr::null_mut(), 0, 0) };

        assert_eq!(f.proc[CG_PROC_NUM_REGISTERS], 3);

        unsafe {
            let [ldi, add, ldw] = emitted(&mut f);
            let offset_reg = field(ldi, CG_INST_LOAD_IMMED_DEST) as *mut u8;
            let address_reg = field(add, CG_INST_BINARY_DEST) as *mut u8;
            let value_reg = field(ldw, CG_INST_LOAD_DEST) as *mut u8;

            for (index, reg) in [offset_reg, address_reg, value_reg].iter().enumerate() {
                assert_eq!(field(*reg, CG_VREG_NO), index);
                assert_eq!(reg.add(CG_VREG_TYPE * WORD).read(), CG_REG_TYPE_GENERAL as u8);
            }
            assert_eq!(field(offset_reg, CG_VREG_NEXT) as *mut u8, address_reg);
            assert_eq!(field(address_reg, CG_VREG_NEXT) as *mut u8, value_reg);
        }
    }

    #[test]
    fn matrix_load_ignores_its_leading_argument() {
        // The original's r0 is dead on arrival; a dangling value must not
        // be dereferenced. Two calls with different garbage produce
        // byte-identical instruction streams.
        let mut f = Fixture::new();
        let block = f.block_ptr();
        unsafe {
            cg_emit_load_matrix4x4_word(1 as *mut u8, block, core::ptr::null_mut(), 1, 1);
            cg_emit_load_matrix4x4_word(usize::MAX as *mut u8, block, core::ptr::null_mut(), 1, 1);
        }

        unsafe {
            let mut inst = f.block[CG_BLOCK_INSTS] as *mut u8;
            let mut immediates = std::vec::Vec::new();
            while !inst.is_null() {
                if inst_kind(inst) == CG_INST_KIND_LOAD_IMMED as u8 {
                    immediates.push(field(inst, CG_INST_LOAD_IMMED_VALUE));
                }
                inst = field(inst, CG_INST_NEXT) as *mut u8;
            }
            assert_eq!(immediates, std::vec![20, 20]);
        }
    }
    #[test]
    fn emits_u8_lerp_with_signed_divide_by_255_sequence() {
        const START: usize = 0x1111_0000;
        const END: usize = 0x2222_0000;
        const FACTOR: usize = 0x3333_0000;

        let mut f = Fixture::new();
        let block = f.block_ptr();
        let result = unsafe {
            cg_emit_lerp_u8(
                usize::MAX as *mut u8,
                block,
                START as *mut CgVirtualReg,
                END as *mut CgVirtualReg,
                FACTOR as *mut CgVirtualReg,
            )
        };

        unsafe {
            let mut inst = f.block[CG_BLOCK_INSTS] as *mut u8;
            let mut instructions = [core::ptr::null_mut(); 7];
            for slot in instructions.iter_mut() {
                assert!(!inst.is_null(), "the seven-step interpolation was appended");
                *slot = inst;
                inst = field(inst, CG_INST_NEXT) as *mut u8;
            }
            assert!(inst.is_null(), "no extra IR instruction was appended");

            let [subtract, shift_constant, multiply, product_shift, rounded_sum, scaled_shift, add] =
                instructions;
            let delta = field(subtract, CG_INST_BINARY_DEST);
            let product = field(multiply, CG_INST_BINARY_DEST);
            let shift = field(shift_constant, CG_INST_LOAD_IMMED_DEST);
            let product_shifted = field(product_shift, CG_INST_BINARY_DEST);
            let rounded_product = field(rounded_sum, CG_INST_BINARY_DEST);
            let scaled = field(scaled_shift, CG_INST_BINARY_DEST);

            assert_eq!(inst_kind(subtract), CG_INST_KIND_BINARY as u8);
            assert_eq!(inst_opcode(subtract), CG_INST_OPCODE_SUB as u8);
            assert_eq!(field(subtract, CG_INST_BINARY_SOURCE0), END);
            assert_eq!(field(subtract, CG_INST_BINARY_SOURCE1), START);

            assert_eq!(inst_kind(shift_constant), CG_INST_KIND_LOAD_IMMED as u8);
            assert_eq!(inst_opcode(shift_constant), CG_INST_OPCODE_LDI as u8);
            assert_eq!(field(shift_constant, CG_INST_LOAD_IMMED_VALUE), 8);

            assert_eq!(inst_opcode(multiply), CG_INST_OPCODE_MUL as u8);
            assert_eq!(field(multiply, CG_INST_BINARY_SOURCE0), delta);
            assert_eq!(field(multiply, CG_INST_BINARY_SOURCE1), FACTOR);
            assert_eq!(inst_opcode(product_shift), CG_INST_OPCODE_ASR as u8);
            assert_eq!(field(product_shift, CG_INST_BINARY_SOURCE0), product);
            assert_eq!(field(product_shift, CG_INST_BINARY_SOURCE1), shift);
            assert_eq!(inst_opcode(rounded_sum), CG_INST_OPCODE_ADD as u8);
            assert_eq!(field(rounded_sum, CG_INST_BINARY_SOURCE0), product);
            assert_eq!(field(rounded_sum, CG_INST_BINARY_SOURCE1), product_shifted);
            assert_eq!(inst_opcode(scaled_shift), CG_INST_OPCODE_ASR as u8);
            assert_eq!(field(scaled_shift, CG_INST_BINARY_SOURCE0), rounded_product);
            assert_eq!(field(scaled_shift, CG_INST_BINARY_SOURCE1), shift);
            assert_eq!(inst_opcode(add), CG_INST_OPCODE_ADD as u8);
            assert_eq!(field(add, CG_INST_BINARY_SOURCE0), START);
            assert_eq!(field(add, CG_INST_BINARY_SOURCE1), scaled);
            assert_eq!(field(add, CG_INST_BINARY_DEST), result as usize);

            for (number, register) in [
                delta,
                product,
                shift,
                product_shifted,
                rounded_product,
                scaled,
                result as usize,
            ]
            .iter()
            .enumerate()
            {
                assert_eq!(field(*register as *mut u8, CG_VREG_NO), number);
                assert_eq!(
                    (*register as *mut u8).add(CG_VREG_TYPE * WORD).read(),
                    CG_REG_TYPE_GENERAL as u8
                );
            }
        }
        assert_eq!(f.proc[CG_PROC_NUM_REGISTERS], 7);
    }
}
