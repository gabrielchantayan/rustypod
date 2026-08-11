//! JIT stack-slot offset resolver — original `FUN_082cf274` @ 0x082cf274
//! (84 bytes).
//!
//! A code generator operand stores a cached signed frame offset at `+0x14`.
//! When that offset is unbound (`-1`), this helper first resolves the
//! operand's canonical parent at `+0x04`; an unbound parent consumes one
//! four-byte slot from `codegen +0x208`'s stack-slot allocator
//! (`context +0x04`, cursor `+0x28`).  The allocator cursor advances by four
//! and the parent receives `-(cursor + 0x28)`, an ARM frame-pointer-relative
//! displacement.  The operand then caches and returns the parent's value.
//! This preserves both lazy allocation and sharing across operands that have
//! the same canonical parent.
//!
//! Target records use four-byte pointer/word slots.  The host test seam uses
//! pointer-sized slots so independently allocated mock records stay disjoint;
//! all stored arithmetic remains explicitly 32-bit, as on ARMv5.

use crate::codegen::ir::CgCodegen;

/// Opaque operand descriptor whose canonical parent and cached stack offset
/// are addressed by the recovered target-word offsets below.
#[repr(C)]
pub struct CgStackOperand {
    _opaque: [u8; 0],
}

const CODEGEN_STACK_SLOT_CONTEXT: usize = 0x208 / 4;
const STACK_SLOT_CONTEXT_ALLOCATOR: usize = 0x04 / 4;
const STACK_SLOT_ALLOCATOR_CURSOR: usize = 0x28 / 4;
const OPERAND_CANONICAL_PARENT: usize = 0x04 / 4;
const OPERAND_STACK_OFFSET: usize = 0x14 / 4;

#[inline(always)]
unsafe fn slot(record: *mut u8, index: usize) -> *mut *mut u8 {
    (record as *mut *mut u8).add(index)
}

#[inline(always)]
unsafe fn word(record: *mut u8, index: usize) -> *mut usize {
    (record as *mut usize).add(index)
}

/// Resolve an operand's cached ARM stack-frame offset.
///
/// `operand +0x14` is returned unchanged once bound.  Otherwise the canonical
/// parent at `+0x04` owns the allocation: its offset is either copied into the
/// operand or filled from the stack-slot allocator reachable from
/// `codegen +0x208`.  The return and cache are signed 32-bit frame offsets.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn cg_operand_stack_offset(
    codegen: *mut CgCodegen,
    operand: *mut CgStackOperand,
) -> i32 {
    let operand = operand as *mut u8;
    let operand_offset = word(operand, OPERAND_STACK_OFFSET);

    if operand_offset.read() as i32 == -1 {
        let parent = slot(operand, OPERAND_CANONICAL_PARENT).read();
        let parent_offset = word(parent, OPERAND_STACK_OFFSET);

        if parent_offset.read() as i32 == -1 {
            let context = slot(codegen as *mut u8, CODEGEN_STACK_SLOT_CONTEXT).read();
            let allocator = slot(context, STACK_SLOT_CONTEXT_ALLOCATOR).read();
            let cursor = word(allocator, STACK_SLOT_ALLOCATOR_CURSOR);
            let next_slot = (cursor.read() as u32).wrapping_add(4);

            cursor.write(next_slot as usize);
            parent_offset.write(next_slot.wrapping_add(0x28).wrapping_neg() as usize);
        }

        operand_offset.write(parent_offset.read());
    }

    operand_offset.read() as i32
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    const POISON: usize = 0xa5a5_a5a5_a5a5_a5a5;

    /// Target words are 32-bit; keep upper host bits clear in fixtures.
    fn cached(value: i32) -> usize {
        value as u32 as usize
    }

    #[test]
    fn copies_a_canonical_parents_existing_offset_without_allocating() {
        let mut child = [POISON; OPERAND_STACK_OFFSET + 2];
        let mut parent = [POISON; OPERAND_STACK_OFFSET + 2];
        let mut codegen = [POISON; CODEGEN_STACK_SLOT_CONTEXT + 2];

        child[OPERAND_CANONICAL_PARENT] = parent.as_mut_ptr() as usize;
        child[OPERAND_STACK_OFFSET] = cached(-0x6c);
        parent[OPERAND_STACK_OFFSET] = cached(-0x6c);
        child[OPERAND_STACK_OFFSET] = cached(-1);

        let offset = unsafe {
            cg_operand_stack_offset(
                codegen.as_mut_ptr() as *mut CgCodegen,
                child.as_mut_ptr() as *mut CgStackOperand,
            )
        };

        assert_eq!(offset, -0x6c);
        assert_eq!(child[OPERAND_STACK_OFFSET], cached(-0x6c));
        assert_eq!(parent[OPERAND_STACK_OFFSET], cached(-0x6c));
        assert_eq!(codegen[CODEGEN_STACK_SLOT_CONTEXT], POISON);
        assert_eq!(child[OPERAND_CANONICAL_PARENT], parent.as_mut_ptr() as usize);
        assert_eq!(child[OPERAND_STACK_OFFSET + 1], POISON);
        assert_eq!(parent[OPERAND_STACK_OFFSET + 1], POISON);
    }

    #[test]
    fn allocates_one_slot_for_an_unbound_parent_and_shares_it() {
        let mut first_child = [POISON; OPERAND_STACK_OFFSET + 2];
        let mut second_child = [POISON; OPERAND_STACK_OFFSET + 2];
        let mut parent = [POISON; OPERAND_STACK_OFFSET + 2];
        let mut codegen = [POISON; CODEGEN_STACK_SLOT_CONTEXT + 2];
        let mut context = [POISON; STACK_SLOT_CONTEXT_ALLOCATOR + 2];
        let mut allocator = [POISON; STACK_SLOT_ALLOCATOR_CURSOR + 2];

        first_child[OPERAND_CANONICAL_PARENT] = parent.as_mut_ptr() as usize;
        first_child[OPERAND_STACK_OFFSET] = cached(-1);
        second_child[OPERAND_CANONICAL_PARENT] = parent.as_mut_ptr() as usize;
        second_child[OPERAND_STACK_OFFSET] = cached(-1);
        parent[OPERAND_STACK_OFFSET] = cached(-1);
        codegen[CODEGEN_STACK_SLOT_CONTEXT] = context.as_mut_ptr() as usize;
        context[STACK_SLOT_CONTEXT_ALLOCATOR] = allocator.as_mut_ptr() as usize;
        allocator[STACK_SLOT_ALLOCATOR_CURSOR] = 0x20;

        let first = unsafe {
            cg_operand_stack_offset(
                codegen.as_mut_ptr() as *mut CgCodegen,
                first_child.as_mut_ptr() as *mut CgStackOperand,
            )
        };
        let second = unsafe {
            cg_operand_stack_offset(
                codegen.as_mut_ptr() as *mut CgCodegen,
                second_child.as_mut_ptr() as *mut CgStackOperand,
            )
        };

        assert_eq!(first, -0x4c, "-(0x20 + 4 + 0x28)");
        assert_eq!(second, first, "siblings share their canonical slot");
        assert_eq!(parent[OPERAND_STACK_OFFSET], cached(-0x4c));
        assert_eq!(first_child[OPERAND_STACK_OFFSET], cached(-0x4c));
        assert_eq!(second_child[OPERAND_STACK_OFFSET], cached(-0x4c));
        assert_eq!(allocator[STACK_SLOT_ALLOCATOR_CURSOR], 0x24);
        assert_eq!(allocator[STACK_SLOT_ALLOCATOR_CURSOR - 1], POISON);
        assert_eq!(allocator[STACK_SLOT_ALLOCATOR_CURSOR + 1], POISON);
        assert_eq!(context[0], POISON);
        assert_eq!(context[STACK_SLOT_CONTEXT_ALLOCATOR + 1], POISON);
        assert_eq!(codegen[CODEGEN_STACK_SLOT_CONTEXT - 1], POISON);
        assert_eq!(codegen[CODEGEN_STACK_SLOT_CONTEXT + 1], POISON);
    }

    #[test]
    fn uses_wrapping_32_bit_frame_offset_arithmetic() {
        let mut child = [0usize; OPERAND_STACK_OFFSET + 1];
        let mut parent = [0usize; OPERAND_STACK_OFFSET + 1];
        let mut codegen = [0usize; CODEGEN_STACK_SLOT_CONTEXT + 1];
        let mut context = [0usize; STACK_SLOT_CONTEXT_ALLOCATOR + 1];
        let mut allocator = [0usize; STACK_SLOT_ALLOCATOR_CURSOR + 1];

        child[OPERAND_CANONICAL_PARENT] = parent.as_mut_ptr() as usize;
        child[OPERAND_STACK_OFFSET] = cached(-1);
        parent[OPERAND_STACK_OFFSET] = cached(-1);
        codegen[CODEGEN_STACK_SLOT_CONTEXT] = context.as_mut_ptr() as usize;
        context[STACK_SLOT_CONTEXT_ALLOCATOR] = allocator.as_mut_ptr() as usize;
        allocator[STACK_SLOT_ALLOCATOR_CURSOR] = 0xffff_fffc;

        let offset = unsafe {
            cg_operand_stack_offset(
                codegen.as_mut_ptr() as *mut CgCodegen,
                child.as_mut_ptr() as *mut CgStackOperand,
            )
        };

        assert_eq!(allocator[STACK_SLOT_ALLOCATOR_CURSOR], 0);
        assert_eq!(offset, -0x28, "-((0xffff_fffc + 4) + 0x28) modulo u32");
        assert_eq!(parent[OPERAND_STACK_OFFSET], cached(-0x28));
    }
}
