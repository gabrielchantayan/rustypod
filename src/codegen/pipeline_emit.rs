//! Emission sugar shared by the JIT's pipeline generators.
//!
//! The rasterizer/fragment-pipeline generators at 0x0823a000-0x0826f5ff
//! build their IR one node at a time through the factories in
//! [`super::ir`]. A handful of three-instruction idioms recur often
//! enough that the compiler emitted them as real out-of-line helpers in
//! the generators' own address block (0x0826xxxx) rather than in the IR
//! library's (0x082cxxxx); this module collects those.

use super::ir::{
    cg_create_inst_binary, cg_create_inst_load, cg_create_inst_load_immed,
    cg_virtual_reg_create, CgBlock, CgProc, CgVirtualReg, CG_BLOCK_PROC,
    CG_INST_OPCODE_ADD, CG_INST_OPCODE_LDI, CG_INST_OPCODE_LDW, CG_REG_TYPE_GENERAL,
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

#[cfg(test)]
mod tests {
    extern crate std;

    use super::super::heap::{CgHeap, CgHeapBlock};
    use super::super::ir::{
        CG_BLOCK_INSTS, CG_INST_BINARY_DEST, CG_INST_BINARY_SOURCE0, CG_INST_BINARY_SOURCE1,
        CG_INST_KIND, CG_INST_KIND_BINARY, CG_INST_KIND_LOAD, CG_INST_KIND_LOAD_IMMED,
        CG_INST_LOAD_ADDRESS, CG_INST_LOAD_DEST, CG_INST_LOAD_IMMED_DEST,
        CG_INST_LOAD_IMMED_VALUE, CG_INST_NEXT, CG_MODULE_HEAP, CG_PROC_MODULE, CG_PROC_NEXT,
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
}
