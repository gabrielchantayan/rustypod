//! Emit trigger subprogram opcodes.
//!
//! `emit_trigger_programs` — original: `FUN_082ce1c0` @ `0x082ce1c0`.
//! Raw `osos.dec` words establish the 96-byte extent
//! `0x082ce1c0..0x082ce220`; the next function begins at `0x082ce220`.
//! It has one unconditional direct `bl` (to `vdbe_add_op4` @ `0x083868c8`)
//! and no predicated `bl` instructions. The function walks the 16-byte
//! trigger-program records at `programs + 0x20`, dereferences each record's
//! program field at +0x00 only when its +0x10 pointer is non-NULL, and emits
//! `OP_Program` with the record's +0x08, +0x04, and subprogram operands.
//!
//! Deliberate deviation: the retailOS target's 32-bit object pointers are
//! decoded from words instead of host pointers, preserving target offsets on
//! 64-bit host tests. `vdbe_add_op4` is already ported and is called directly.

use crate::sqlite::vdbe::{vdbe_add_op4, Vdbe};

const PARSE_VDBE_OFFSET: usize = 0x0c;
const PROGRAMS_RECORDS_OFFSET: usize = 0x20;
const PROGRAMS_COUNT_OFFSET: usize = 0x24;
const TRIGGER_PROGRAM_RECORD_SIZE: usize = 0x10;
const RECORD_PROGRAM_OFFSET: usize = 0x00;
const RECORD_P4_OFFSET: usize = 0x04;
const RECORD_P1_OFFSET: usize = 0x08;
const SUBPROGRAM_N_MEM_POINTER_OFFSET: usize = 0x10;
const OP_PROGRAM: i32 = 0x5a;
const P4_SUBPROGRAM: i32 = -5;

/// Emits one `OP_Program` for each trigger subprogram record.
///
/// # Safety
/// `parse` and `programs` must be target-layout objects. Their pointer fields
/// are 32-bit words; each record must be 16 bytes and its program object, when
/// it supplies a non-NULL +0x10 pointer, must point to a readable `i32`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn emit_trigger_programs(parse: *mut u8, programs: *const u8) {
    let vdbe = parse.add(PARSE_VDBE_OFFSET).cast::<u32>().read() as usize as *mut Vdbe;
    let mut record = programs
        .add(PROGRAMS_RECORDS_OFFSET)
        .cast::<u32>()
        .read() as usize as *const u8;
    let count = programs.add(PROGRAMS_COUNT_OFFSET).cast::<i32>().read();

    let mut index = 0;
    while index < count {
        let program = record.add(RECORD_PROGRAM_OFFSET).cast::<u32>().read() as usize as *const u8;
        let n_mem_pointer = program.add(SUBPROGRAM_N_MEM_POINTER_OFFSET).cast::<u32>().read() as usize as *const i32;
        let n_mem = if n_mem_pointer.is_null() { 0 } else { n_mem_pointer.read() };
        let p1 = record.add(RECORD_P1_OFFSET).cast::<i32>().read();
        let p4 = record.add(RECORD_P4_OFFSET).cast::<u32>().read() as usize as *const u8;

        vdbe_add_op4(vdbe, OP_PROGRAM, p1, n_mem, 0, p4, P4_SUBPROGRAM);
        record = record.add(TRIGGER_PROGRAM_RECORD_SIZE);
        index = index.wrapping_add(1);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::sqlite::vdbe::VdbeOp;
    use crate::testing::{hints, try_map_u32_slab};
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    static SLAB_LOCK: Mutex<()> = Mutex::new(());
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::SQLITE_EMIT_TRIGGER_PROGRAMS, 0x1000).map(|pointer| pointer as usize)
    });

    #[test]
    fn emits_program_ops_and_keeps_null_n_mem_at_zero() {
        let _lock = SLAB_LOCK.lock();
        let Some(address) = *SLAB else { return };
        let slab = address as *mut u8;
        let db = unsafe { slab.add(0x700) };
        let parse = slab;
        let programs = unsafe { slab.add(0x40) };
        let vdbe = unsafe { slab.add(0x100).cast::<Vdbe>() };
        let ops = unsafe { slab.add(0x300).cast::<VdbeOp>() };
        let records = unsafe { slab.add(0x400) };
        let program_a = unsafe { slab.add(0x500) };
        let program_b = unsafe { slab.add(0x540) };
        let n_mem = unsafe { slab.add(0x580).cast::<i32>() };
        let payload_a = unsafe { slab.add(0x5c0) };
        let payload_b = unsafe { slab.add(0x600) };

        unsafe {
            vdbe.write(core::mem::zeroed());
            (*vdbe).db = db;
            (*vdbe).a_op = ops;
            (*vdbe).n_op_alloc = 2;
            parse.add(PARSE_VDBE_OFFSET).cast::<u32>().write(vdbe as u32);
            programs.add(PROGRAMS_RECORDS_OFFSET).cast::<u32>().write(records as u32);
            programs.add(PROGRAMS_COUNT_OFFSET).cast::<i32>().write(2);
            n_mem.write(17);
            program_a.add(SUBPROGRAM_N_MEM_POINTER_OFFSET).cast::<u32>().write(n_mem as u32);
            records.add(RECORD_PROGRAM_OFFSET).cast::<u32>().write(program_a as u32);
            records.add(RECORD_P4_OFFSET).cast::<u32>().write(payload_a as u32);
            records.add(RECORD_P1_OFFSET).cast::<i32>().write(-3);
            let second = records.add(TRIGGER_PROGRAM_RECORD_SIZE);
            second.add(RECORD_PROGRAM_OFFSET).cast::<u32>().write(program_b as u32);
            second.add(RECORD_P4_OFFSET).cast::<u32>().write(payload_b as u32);
            second.add(RECORD_P1_OFFSET).cast::<i32>().write(9);

            emit_trigger_programs(parse, programs);

            assert_eq!((*vdbe).n_op, 2);
            assert_eq!((*ops).opcode, OP_PROGRAM as u8);
            assert_eq!((*ops).p1, -3);
            assert_eq!((*ops).p2, 17);
            assert_eq!((*ops).p3, 0);
            assert_eq!((*ops).p4, payload_a);
            assert_eq!((*ops).p4type, P4_SUBPROGRAM as i8);
            let second_op = ops.add(1);
            assert_eq!((*second_op).p1, 9);
            assert_eq!((*second_op).p2, 0);
            assert_eq!((*second_op).p4, payload_b);
            assert_eq!((*second_op).p4type, P4_SUBPROGRAM as i8);
        }
    }

    #[test]
    fn zero_count_does_not_read_the_record_array() {
        let _lock = SLAB_LOCK.lock();
        let Some(address) = *SLAB else { return };
        let slab = address as *mut u8;
        let vdbe = unsafe { slab.add(0x100).cast::<Vdbe>() };
        unsafe {
            core::ptr::write_bytes(slab, 0, 0x1000);
            vdbe.write(core::mem::zeroed());
            slab.add(PARSE_VDBE_OFFSET).cast::<u32>().write(vdbe as u32);
            slab.add(0x40 + PROGRAMS_COUNT_OFFSET).cast::<i32>().write(0);
            emit_trigger_programs(slab, slab.add(0x40));
            assert_eq!((*vdbe).n_op, 0);
        }
    }
}
