//! Opening SQLite's schema table for a write operation.
//!
//! - `open_master_table` — original: `FUN_0837d884` @ 0x0837d884
//!   (112 bytes, 0x0837d884..0x0837d8f3; `sqlite_master` at 0x0837d8f4
//!   begins the following data). Two direct inbound `bl` sites, both plain;
//!   the body has three plain `bl` instructions and no predicated `bl`.
//!
//! SQLite's `sqlite3OpenMasterTable`: get the VDBE, record a write lock on
//! root page one of the selected schema table, then append `OP_SetNumColumns`
//! with five columns and `OP_OpenWrite` for cursor zero. Database one uses
//! `sqlite_temp_master`; every other database index uses `sqlite_master`.
//!
//! Deliberate deviation: `sqlite3GetVdbe` @ 0x0837acf4 has no Rust export
//! despite its ledger entry, so this reuses `BEGIN_WRITE_OPS.get_vdbe`, whose
//! default is the documented stored-`pVdbe` equivalent. The two `Parse` views
//! have different host layouts; they are ABI-identical on the 32-bit target,
//! and each is cast only at its corresponding recovered callee boundary.

use crate::sqlite::begin_write_operation::{get_vdbe_op, Parse as VdbeParse};
use crate::sqlite::table_lock::{vdbe_add_table_lock, Parse};
use crate::sqlite::vdbe::vdbe_add_op3;

const SQLITE_MASTER: &[u8] = b"sqlite_master\0";
const SQLITE_TEMP_MASTER: &[u8] = b"sqlite_temp_master\0";
const OP_SET_NUM_COLUMNS: i32 = 0x62;
const OP_OPEN_WRITE: i32 = 9;

/// sqlite3OpenMasterTable — original: `FUN_0837d884` @ 0x0837d884
/// (112 bytes; two plain inbound `bl` sites).
///
/// # Safety
/// `parse` must name a writable recovered SQLite `Parse`. Its VDBE and
/// table-lock list must satisfy the contracts of the called helpers.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn open_master_table(parse: *mut Parse, database_index: i32) {
    let vdbe = get_vdbe_op()(parse.cast::<VdbeParse>());
    let table_name = if database_index == 1 { SQLITE_TEMP_MASTER } else { SQLITE_MASTER };

    vdbe_add_table_lock(parse, database_index, 1, 1, table_name.as_ptr());
    vdbe_add_op3(vdbe, OP_SET_NUM_COLUMNS, 0, 5, 0);
    vdbe_add_op3(vdbe, OP_OPEN_WRITE, 0, 1, database_index);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::sqlite::table_lock::TableLock;
    use crate::sqlite::vdbe::{Vdbe, VdbeOp};

    unsafe fn fixture(
        database_index: i32,
        expected_name: *const u8,
    ) -> (Parse, TableLock, Vdbe, [VdbeOp; 2]) {
        let mut ops: [VdbeOp; 2] = core::mem::zeroed();
        let mut vdbe: Vdbe = core::mem::zeroed();
        vdbe.n_op_alloc = 2;
        vdbe.a_op = ops.as_mut_ptr();

        let mut lock = TableLock {
            i_db: database_index,
            i_tab: 1,
            is_write_lock: 0,
            _pad_09: [0; 3],
            z_name: expected_name,
        };
        let mut parse = Parse {
            db: core::ptr::null_mut(),
            _gap_04: [0; 0x13c - 0x04],
            n_table_lock: 1,
            a_table_lock: core::ptr::addr_of_mut!(lock),
        };
        (*core::ptr::addr_of_mut!(parse).cast::<VdbeParse>()).p_vdbe = core::ptr::addr_of_mut!(vdbe);

        open_master_table(core::ptr::addr_of_mut!(parse), database_index);
        (parse, lock, vdbe, ops)
    }

    #[test]
    fn opens_main_schema_for_non_temp_database() {
        unsafe {
            let (_parse, lock, vdbe, ops) = fixture(0, SQLITE_MASTER.as_ptr());
            assert_eq!(lock.is_write_lock, 1);
            assert_eq!(lock.z_name, SQLITE_MASTER.as_ptr());
            assert_eq!(vdbe.n_op, 2);
            assert_eq!(ops[0].opcode, OP_SET_NUM_COLUMNS as u8);
            assert_eq!((ops[0].p1, ops[0].p2, ops[0].p3), (0, 5, 0));
            assert_eq!(ops[1].opcode, OP_OPEN_WRITE as u8);
            assert_eq!((ops[1].p1, ops[1].p2, ops[1].p3), (0, 1, 0));
        }
    }

    #[test]
    fn opens_temp_schema_only_for_database_one() {
        unsafe {
            let (_parse, lock, vdbe, ops) = fixture(1, SQLITE_TEMP_MASTER.as_ptr());
            assert_eq!(lock.is_write_lock, 1);
            assert_eq!(lock.z_name, SQLITE_TEMP_MASTER.as_ptr());
            assert_eq!(vdbe.n_op, 2);
            assert_eq!((ops[0].opcode, ops[0].p1, ops[0].p2, ops[0].p3), (0x62, 0, 5, 0));
            assert_eq!((ops[1].opcode, ops[1].p1, ops[1].p2, ops[1].p3), (9, 0, 1, 1));
        }
    }

    #[test]
    fn negative_database_skips_lock_but_still_emits_main_open() {
        unsafe {
            let (_parse, lock, vdbe, ops) = fixture(-1, SQLITE_MASTER.as_ptr());
            assert_eq!(lock.is_write_lock, 0);
            assert_eq!(vdbe.n_op, 2);
            assert_eq!(ops[1].p3, -1);
        }
    }
}
