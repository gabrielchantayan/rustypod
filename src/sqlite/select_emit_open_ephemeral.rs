//! Emit a temporary-table VDBE operation for a SELECT — original:
//! `FUN_082c5444` @ 0x082c5444 (68 bytes; 2 plain inbound `bl`, no predicated
//! inbound `bl`; one unconditional outbound `bl`).
//!
//! The function returns when `temporary` is NULL. Otherwise it assigns
//! `Parse.nTab` (+0x44) to `temporary[2]`, increments `nTab`, emits opcode
//! `0x70` with `p1 = temporary[2]` and `p2 = temporary[0] + 1`, then stores
//! the emitted instruction address at `Select + 0x44`.
//!
//! Deliberate deviation: target-layout Parse, Select, and temporary records
//! are represented as `u32` word offsets rather than host pointer-bearing
//! structs, preserving their 32-bit field offsets on 64-bit host tests.

use crate::sqlite::vdbe::{vdbe_add_op2, Vdbe};

const PARSE_N_TAB_WORD: usize = 0x44 / 4;
const SELECT_OPEN_EPHEMERAL_ADDRESS_WORD: usize = 0x44 / 4;
const OP_OPEN_EPHEMERAL: i32 = 0x70;

/// `select_emit_open_ephemeral` — original `FUN_082c5444` @ 0x082c5444.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn select_emit_open_ephemeral(
    parse: *mut u32,
    select: *mut u32,
    temporary: *mut u32,
) {
    if temporary.is_null() {
        return;
    }

    let table = parse.add(PARSE_N_TAB_WORD).read();
    temporary.add(2).write(table);
    parse.add(PARSE_N_TAB_WORD).write(table.wrapping_add(1));

    let vdbe = parse.add(3).read() as usize as *mut Vdbe;
    let address = vdbe_add_op2(
        vdbe,
        OP_OPEN_EPHEMERAL,
        table as i32,
        temporary.read().wrapping_add(1) as i32,
    );
    select.add(SELECT_OPEN_EPHEMERAL_ADDRESS_WORD).write(address as u32);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::sqlite::vdbe::VdbeOp;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    const SLAB_LEN: usize = 0x1000;
    const SELECT_OFFSET: usize = 0x80;
    const TEMPORARY_OFFSET: usize = 0x100;
    const VDBE_OFFSET: usize = 0x200;
    const OP_OFFSET: usize = 0x400;

    #[test]
    fn null_temporary_leaves_parse_and_select_unchanged() {
        let mut parse = [0u32; 18];
        let mut select = [0u32; 18];
        parse[PARSE_N_TAB_WORD] = 9;
        select[SELECT_OPEN_EPHEMERAL_ADDRESS_WORD] = 17;

        unsafe { select_emit_open_ephemeral(parse.as_mut_ptr(), select.as_mut_ptr(), core::ptr::null_mut()) };

        assert_eq!(parse[PARSE_N_TAB_WORD], 9);
        assert_eq!(select[SELECT_OPEN_EPHEMERAL_ADDRESS_WORD], 17);
    }

    #[test]
    fn assigns_wrapped_table_and_emits_open_ephemeral() {
        let Some(base) = try_map_u32_slab(hints::SQLITE_SELECT_EMIT_OPEN_EPHEMERAL, SLAB_LEN) else {
            assert!(note_missing_u32_fixture(module_path!()));
            return;
        };

        unsafe {
            base.write_bytes(0, SLAB_LEN);
            let parse = base.cast::<u32>();
            let select = base.add(SELECT_OFFSET).cast::<u32>();
            let temporary = base.add(TEMPORARY_OFFSET).cast::<u32>();
            let vdbe = base.add(VDBE_OFFSET).cast::<Vdbe>();
            let op = base.add(OP_OFFSET).cast::<VdbeOp>();
            vdbe.write(core::mem::zeroed());
            (*vdbe).n_op_alloc = 1;
            (*vdbe).a_op = op;
            parse.add(3).write(vdbe as usize as u32);
            parse.add(PARSE_N_TAB_WORD).write(u32::MAX);
            temporary.write(u32::MAX);

            select_emit_open_ephemeral(parse, select, temporary);

            assert_eq!(temporary.add(2).read(), u32::MAX);
            assert_eq!(parse.add(PARSE_N_TAB_WORD).read(), 0);
            assert_eq!(select.add(SELECT_OPEN_EPHEMERAL_ADDRESS_WORD).read(), 0);
            assert_eq!((*vdbe).n_op, 1);
            assert_eq!((*op).opcode, OP_OPEN_EPHEMERAL as u8);
            assert_eq!((*op).p1, -1);
            assert_eq!((*op).p2, 0);
        }
    }
}
