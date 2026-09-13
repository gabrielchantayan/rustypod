//! SQLite's ordinary-table VDBE cursor opener.
//!
//! `open_table` — original: `FUN_0837d918` @ 0x0837d918 (132 bytes,
//! 0x0837d918..0x0837d998; the next separately linked function begins at
//! 0x0837d99c). Raw ARM decoding finds **10 `bl` call sites, all
//! unconditional**: 0x082b56b8, 0x082b57f8, 0x08374dfc, 0x08378db8,
//! 0x0837d9f0, 0x0838193c, 0x08385aac, 0x0838df14, 0x08399060, and
//! 0x083990e0.
//!
//! SQLite's `sqlite3OpenTable`: virtual tables return before touching the
//! parse state. Otherwise, fetch the VDBE, record a shared-cache table lock,
//! append `OP_SetNumColumns 0, table.nCol`, then append the caller-selected
//! open opcode with `(cursor, table.tnum, database_index)`. The lock is a
//! write lock precisely for opcode 9 (`OP_OpenWrite`); every other opcode is
//! recorded as a read lock.
//!
//! Deliberate deviation: the raw function calls `sqlite3GetVdbe`
//! (@ 0x0837acf4). Its ledger entry is marked ported but no Rust symbol
//! exists; `begin_write_operation` documents the same defect and its shipped
//! replacement reads `Parse.pVdbe`. This port reads that field directly. It
//! is identical whenever a VDBE is already present, and preserves the
//! unported constructor's configured OOM end state (NULL, no emitted ops).
//! The host-only adapter preserves the target's direct table-lock call while
//! avoiding an invalid cast between independently recovered 64-bit host
//! layouts.

use crate::sqlite::table_lock::{vdbe_add_table_lock, Parse as TableLockParse, TableLock};
use crate::sqlite::vdbe::{vdbe_add_op2, vdbe_add_op3, Vdbe};

/// The firmware's `OP_SetNumColumns` literal (`mov r1,#0x62`).
pub const OP_SET_NUM_COLUMNS: i32 = 0x62;
/// `OP_OpenWrite`, the sole opcode that makes the recorded table lock write.
pub const OP_OPEN_WRITE: i32 = 9;

/// The `Parse` fields the cursor opener and table-lock recorder jointly use.
///
/// On target, this is the same prefix/extension used by `table_lock::Parse`.
/// Named fields deliberately replace raw byte offsets so host pointer width
/// cannot make the VDBE and lock-list fields overlap.
#[repr(C)]
pub struct Parse {
    /// +0x00: owning SQLite connection.
    pub db: *mut u8,
    /// +0x04..+0x0c: parse result and error-message state.
    pub _gap_04: [u8; 0x0c - 0x04],
    /// +0x0c: the VDBE being compiled.
    pub p_vdbe: *mut Vdbe,
    /// +0x10..+0x13c: unrelated parse state.
    pub _gap_10: [u8; 0x13c - 0x10],
    /// +0x13c: number of shared-cache table locks.
    pub n_table_lock: i32,
    /// +0x140: shared-cache table-lock array.
    pub a_table_lock: *mut TableLock,
}

/// The `Table` fields this helper reads.
#[repr(C)]
pub struct Table {
    /// +0x00: schema-owned table name.
    pub z_name: *const u8,
    /// +0x04: number of declared columns.
    pub n_col: i32,
    /// +0x08..+0x14: column/index metadata and integer-primary-key index.
    pub _gap_08: [u8; 0x14 - 0x08],
    /// +0x14: root B-tree page.
    pub tnum: i32,
    /// +0x18..+0x39: view, trigger, foreign-key and table-flag metadata.
    pub _gap_18: [u8; 0x39 - 0x18],
    /// +0x39: non-zero for a virtual table.
    pub is_virtual: u8,
}

#[cfg(target_pointer_width = "32")]
const _: () = {
    assert!(core::mem::offset_of!(Parse, p_vdbe) == 0x0c);
    assert!(core::mem::offset_of!(Parse, n_table_lock) == 0x13c);
    assert!(core::mem::offset_of!(Parse, a_table_lock) == 0x140);
    assert!(core::mem::offset_of!(Table, n_col) == 0x04);
    assert!(core::mem::offset_of!(Table, tnum) == 0x14);
    assert!(core::mem::offset_of!(Table, is_virtual) == 0x39);
};

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn add_table_lock(
    parse: *mut Parse,
    database_index: i32,
    table_index: i32,
    is_write_lock: i32,
    table_name: *const u8,
) {
    vdbe_add_table_lock(
        parse.cast::<TableLockParse>(),
        database_index,
        table_index,
        is_write_lock,
        table_name,
    );
}

/// The separately reconstructed Parse records have different valid host
/// layouts because pointer fields widen. Adapt only on host; target code
/// invokes the ported table-lock function directly through the matching ABI.
#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn add_table_lock(
    parse: *mut Parse,
    database_index: i32,
    table_index: i32,
    is_write_lock: i32,
    table_name: *const u8,
) {
    let mut lock_parse = TableLockParse {
        db: (*parse).db,
        _gap_04: [0; 0x13c - 0x04],
        n_table_lock: (*parse).n_table_lock,
        a_table_lock: (*parse).a_table_lock,
    };
    vdbe_add_table_lock(
        &mut lock_parse,
        database_index,
        table_index,
        is_write_lock,
        table_name,
    );
    (*parse).n_table_lock = lock_parse.n_table_lock;
    (*parse).a_table_lock = lock_parse.a_table_lock;
}

/// sqlite3OpenTable — original: `FUN_0837d918` @ 0x0837d918 (132 bytes;
/// 10 unconditional `bl` call sites, binary-verified).
///
/// # Safety
/// `parse` must name a writable recovered [`Parse`] and `table` a readable
/// recovered [`Table`]. When `table.is_virtual == 0` and `parse.p_vdbe` is
/// non-NULL, the VDBE must have room for two ops and the parse lock list must
/// be valid for [`vdbe_add_table_lock`].
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn open_table(
    parse: *mut Parse,
    cursor: i32,
    database_index: i32,
    table: *mut Table,
    opcode: i32,
) {
    if (*table).is_virtual != 0 {
        return;
    }

    let vdbe = (*parse).p_vdbe;
    if vdbe.is_null() {
        return;
    }

    add_table_lock(
        parse,
        database_index,
        (*table).tnum,
        (opcode == OP_OPEN_WRITE) as i32,
        (*table).z_name,
    );
    vdbe_add_op2(vdbe, OP_SET_NUM_COLUMNS, 0, (*table).n_col);
    vdbe_add_op3(vdbe, opcode, cursor, (*table).tnum, database_index);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::sqlite::mem::tests::{install_recorder, Connection};

    fn blank_op() -> crate::sqlite::vdbe::VdbeOp {
        crate::sqlite::vdbe::VdbeOp {
            opcode: 0,
            p4type: 0,
            opflags: 0,
            p5: 0,
            p1: 0,
            p2: 0,
            p3: 0,
            p4: core::ptr::null_mut(),
        }
    }

    fn table(name: *const u8, n_col: i32, tnum: i32, is_virtual: u8) -> Table {
        Table {
            z_name: name,
            n_col,
            _gap_08: [0; 0x14 - 0x08],
            tnum,
            _gap_18: [0; 0x39 - 0x18],
            is_virtual,
        }
    }

    #[test]
    fn ordinary_table_records_write_lock_and_emits_two_ops() {
        let mut db = Connection::healthy();
        let mut ops = [blank_op(), blank_op(), blank_op()];
        let mut vdbe = Vdbe {
            db: (&mut db as *mut Connection).cast(),
            _gap_04: [0; 4],
            p_next: core::ptr::null_mut(),
            n_op: 0,
            n_op_alloc: ops.len() as i32,
            a_op: ops.as_mut_ptr(),
            n_label: 0,
            n_label_alloc: 0,
            a_label: core::ptr::null_mut(),
            _gap_24: [0; 4],
            a_col_name: core::ptr::null_mut(),
            _gap_2c: [0; 0xec - 0x2c],
            n_res_column: 0,
            _gap_f0: [0; 8],
            p_result_set: core::ptr::null_mut(),
            _gap_fc: [0; 3],
            expired: 1,
        };
        let mut locks = [TableLock {
            i_db: -1,
            i_tab: -1,
            is_write_lock: 0,
            _pad_09: [0; 3],
            z_name: core::ptr::null(),
        }];
        let mut parse = Parse {
            db: (&mut db as *mut Connection).cast(),
            _gap_04: [0; 8],
            p_vdbe: &mut vdbe,
            _gap_10: [0; 0x13c - 0x10],
            n_table_lock: 0,
            a_table_lock: locks.as_mut_ptr(),
        };
        let name = b"songs\0";
        let mut tab = table(name.as_ptr(), 7, 42, 0);
        let _guard = install_recorder(locks.as_mut_ptr().cast());

        unsafe { open_table(&mut parse, 5, 2, &mut tab, OP_OPEN_WRITE) };

        assert_eq!(parse.n_table_lock, 1);
        assert_eq!(locks[0].i_db, 2);
        assert_eq!(locks[0].i_tab, 42);
        assert_eq!(locks[0].is_write_lock, 1);
        assert_eq!(locks[0].z_name, name.as_ptr());
        assert_eq!(vdbe.n_op, 2);
        assert_eq!((ops[0].opcode, ops[0].p1, ops[0].p2, ops[0].p3), (0x62, 0, 7, 0));
        assert_eq!((ops[1].opcode, ops[1].p1, ops[1].p2, ops[1].p3), (9, 5, 42, 2));
        assert_eq!(vdbe.expired, 0);
    }

    #[test]
    fn non_write_opcode_records_a_read_lock() {
        let mut db = Connection::healthy();
        let mut ops = [blank_op(), blank_op()];
        let mut vdbe = Vdbe {
            db: (&mut db as *mut Connection).cast(),
            _gap_04: [0; 4],
            p_next: core::ptr::null_mut(),
            n_op: 0,
            n_op_alloc: ops.len() as i32,
            a_op: ops.as_mut_ptr(),
            n_label: 0,
            n_label_alloc: 0,
            a_label: core::ptr::null_mut(),
            _gap_24: [0; 4],
            a_col_name: core::ptr::null_mut(),
            _gap_2c: [0; 0xec - 0x2c],
            n_res_column: 0,
            _gap_f0: [0; 8],
            p_result_set: core::ptr::null_mut(),
            _gap_fc: [0; 3],
            expired: 1,
        };
        let mut locks = [TableLock {
            i_db: -1,
            i_tab: -1,
            is_write_lock: 0xa5,
            _pad_09: [0; 3],
            z_name: core::ptr::null(),
        }];
        let mut parse = Parse {
            db: (&mut db as *mut Connection).cast(),
            _gap_04: [0; 8],
            p_vdbe: &mut vdbe,
            _gap_10: [0; 0x13c - 0x10],
            n_table_lock: 0,
            a_table_lock: locks.as_mut_ptr(),
        };
        let mut tab = table(b"albums\0".as_ptr(), 4, 17, 0);
        let _guard = install_recorder(locks.as_mut_ptr().cast());

        unsafe { open_table(&mut parse, 3, 1, &mut tab, 0x0d) };

        assert_eq!(locks[0].is_write_lock, 0);
        assert_eq!((ops[0].opcode, ops[0].p2), (OP_SET_NUM_COLUMNS as u8, 4));
        assert_eq!((ops[1].opcode, ops[1].p1, ops[1].p2, ops[1].p3), (0x0d, 3, 17, 1));
    }

    #[test]
    fn virtual_table_and_missing_vdbe_are_noops() {
        let mut db = Connection::healthy();
        let mut locks = [TableLock {
            i_db: -1,
            i_tab: -1,
            is_write_lock: 0xa5,
            _pad_09: [0; 3],
            z_name: core::ptr::null(),
        }];
        let mut parse = Parse {
            db: (&mut db as *mut Connection).cast(),
            _gap_04: [0; 8],
            p_vdbe: core::ptr::null_mut(),
            _gap_10: [0; 0x13c - 0x10],
            n_table_lock: 0,
            a_table_lock: locks.as_mut_ptr(),
        };
        let name = b"virtual\0";
        let mut virtual_table = table(name.as_ptr(), 3, 9, 1);
        let _guard = install_recorder(locks.as_mut_ptr().cast());

        unsafe { open_table(&mut parse, 1, 0, &mut virtual_table, OP_OPEN_WRITE) };
        virtual_table.is_virtual = 0;
        unsafe { open_table(&mut parse, 1, 0, &mut virtual_table, 0x0d) };

        assert_eq!(parse.n_table_lock, 0);
        assert_eq!(locks[0].is_write_lock, 0xa5);
    }
}
