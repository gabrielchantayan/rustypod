//! Emit index affinity conversion and mark affected column-cache registers.

use super::expr_cache_affinity_change::expr_cache_affinity_change;
use super::index_affinity::vdbe_attach_index_affinity;
use super::vdbe::{vdbe_add_op3, Vdbe};

/// code_apply_index_affinity — `FUN_082c39e0` @ 0x082c39e0.
/// True extent: 88 bytes, ending at the next prologue at 0x082c3a38.
/// Two inbound BL sites (0x0838e840, 0x0838e8d8), both unconditional;
/// three internal unconditional BL instructions, no predicated BL.
///
/// For a positive signed register count, load Parse.pVdbe (+0x0c), emit
/// opcode 2 with (first_reg, count, 0), attach the index affinity string to
/// that operation, then mark cached registers whose affinities changed.
/// Nonpositive counts return without reading either pointer. Deliberate
/// deviation: the Parse pointer field is read as a target-width u32; Vdbe
/// itself uses the existing repr(C) Rust layout for host pointer safety.
///
/// # Safety
/// For positive counts, `parse` must be an aligned target-layout Parse with
/// a valid pVdbe and column cache; `index` must satisfy the affinity helper's
/// target-layout Index contract. No valid pointers are required otherwise.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn code_apply_index_affinity(
    parse: *mut u8,
    first_reg: i32,
    count: i32,
    index: *mut u8,
) {
    if count > 0 {
        let vdbe = parse.add(0x0c).cast::<u32>().read() as usize as *mut Vdbe;
        vdbe_add_op3(vdbe, 2, first_reg, count, 0);
        vdbe_attach_index_affinity(vdbe, index);
        expr_cache_affinity_change(parse, first_reg, count);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::sqlite::mem::{DbMemOps, DEFAULT_DB_MEM_OPS, DB_MEM_OPS};
    use crate::sqlite::mem::tests::OPS_LOCK;
    use crate::sqlite::vdbe::{VdbeOp, P4_DYNAMIC};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    static mut COPY: *mut u8 = core::ptr::null_mut();
    unsafe extern "C" fn allocate_copy(_n: i32) -> *mut u8 { COPY }
    struct ResetAllocator;
    impl Drop for ResetAllocator {
        fn drop(&mut self) {
            unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!(DB_MEM_OPS), DEFAULT_DB_MEM_OPS) };
        }
    }

    #[test]
    fn nonpositive_counts_do_not_dereference_arguments() {
        for count in [i32::MIN, -1, 0] {
            unsafe { code_apply_index_affinity(core::ptr::null_mut(), 5, count, core::ptr::null_mut()) };
        }
    }

    #[test]
    fn emits_affinity_and_marks_only_the_signed_register_interval() {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let Some(slab) = try_map_u32_slab(hints::SQLITE_CODE_APPLY_INDEX_AFFINITY, 0x2000) else {
            if note_missing_u32_fixture(module_path!()) { return; }
            unreachable!();
        };
        let _reset = ResetAllocator;
        unsafe {
            core::ptr::write_bytes(slab, 0, 0x2000);
            COPY = slab.add(0x1000);
            core::ptr::write_volatile(core::ptr::addr_of_mut!(DB_MEM_OPS), DbMemOps {
                malloc: allocate_copy, realloc: DEFAULT_DB_MEM_OPS.realloc,
            });
            let parse = slab;
            let vdbe = slab.add(0x200).cast::<Vdbe>();
            let index = slab.add(0x600);
            let affinity = slab.add(0x700);
            core::ptr::copy_nonoverlapping(b"ACb\0".as_ptr(), affinity, 4);
            index.add(0x1c).cast::<u32>().write(affinity as u32);
            parse.add(0x0c).cast::<u32>().write(vdbe as u32);
            parse.add(0x58).cast::<i32>().write(4);
            let mut ops: [VdbeOp; 3] = core::mem::zeroed();
            ops[0].opcode = 0x55;
            (*vdbe).db = slab.add(0x800);
            (*vdbe).a_op = ops.as_mut_ptr();
            (*vdbe).n_op = 1;
            (*vdbe).n_op_alloc = 3;
            for (first, count, registers, expected) in [
                (5, 2, [4, 5, 6, 7], [0, 1, 1, 0]),
                (i32::MAX, 2, [i32::MAX - 1, i32::MAX, i32::MIN, 0], [0, 0, 0, 0]),
            ] {
                for (i, reg) in registers.iter().enumerate() {
                    let record = parse.add(0x60 + i * 16);
                    record.add(12).cast::<i32>().write(*reg);
                    record.add(8).write(0);
                }
                code_apply_index_affinity(parse, first, count, index);
                let op = &ops[(*vdbe).n_op as usize - 1];
                assert_eq!((op.opcode, op.p1, op.p2, op.p3), (2, first, count, 0));
                assert_eq!(op.p4type, P4_DYNAMIC as i8);
                assert_eq!(core::slice::from_raw_parts(op.p4, 4), b"ACb\0");
                for (i, mark) in expected.iter().enumerate() {
                    assert_eq!(parse.add(0x60 + i * 16 + 8).read(), *mark);
                }
            }
            assert_eq!((*vdbe).n_op, 3);
            assert_eq!(ops[0].opcode, 0x55);
            assert_eq!(index.add(0x1c).cast::<u32>().read(), affinity as u32);
        }
    }
}
