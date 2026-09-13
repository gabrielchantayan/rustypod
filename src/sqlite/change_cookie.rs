//! SQLite schema-cookie increment bytecode emitter.
//!
//! - `change_cookie` — original: `FUN_08372e54` @ 0x08372e54 (108 bytes,
//!   0x08372e54..0x08372ebc; the independently linked sibling begins at
//!   0x08372ec0). Raw ARM decoding finds **9 `bl` call sites**: eight plain
//!   `bl` and one `blne` (0x0836eb78); callers, not this function, gate that
//!   conditional invocation.
//!
//! SQLite's `sqlite3ChangeCookie`: reserve a temporary register, load it with
//! the selected schema's cookie plus one, emit `OP_SetCookie`, then return the
//! temporary register to the Parse free list. The cookie increment wraps as
//! the original ARM `add` does. No NULL or index checks exist in the firmware.
//!
//! Deliberate deviation: recovered object links are stored as `u32` fields,
//! rather than host pointers, so their target offsets remain correct in host
//! tests. The target is 32-bit, where those words are the original pointers.

use crate::sqlite::get_temp_reg::get_temp_reg;
use crate::sqlite::parse::release_temp_reg;
use crate::sqlite::vdbe::{vdbe_add_op2, vdbe_add_op3, Vdbe};

/// `OP_Integer` in this build (`mov r1,#0x2f`).
pub const OP_INTEGER: i32 = 0x2f;
/// `OP_SetCookie` in this build (`mov r1,#4`).
pub const OP_SET_COOKIE: i32 = 4;

/// Fields of SQLite's parser context used by [`change_cookie`].
///
/// Link fields deliberately remain target-width words: [`get_temp_reg`] and
/// [`release_temp_reg`] read `nTempReg`, `aTempReg`, and `nMem` at the
/// firmware's fixed offsets even in host tests.
#[repr(C)]
pub struct Parse {
    /// +0x00: owning `sqlite3 *`.
    pub db: u32,
    /// +0x04..+0x0c: unmodeled parse state.
    pub _gap_04: [u8; 0x0c - 0x04],
    /// +0x0c: VDBE under construction.
    pub p_vdbe: u32,
    /// +0x10..+0x15: unmodeled parse state.
    pub _gap_10: [u8; 0x15 - 0x10],
    /// +0x15: free temporary-register count.
    pub n_temp_reg: u8,
    /// +0x16..+0x18: alignment padding.
    pub _gap_16: [u8; 2],
    /// +0x18: free temporary-register stack.
    pub a_temp_reg: [i32; 8],
    /// +0x38..+0x48: unmodeled parse state.
    pub _gap_38: [u8; 0x48 - 0x38],
    /// +0x48: highest VDBE register allocated so far.
    pub n_mem: i32,
}

/// The `sqlite3` field used to locate attached databases.
#[repr(C)]
pub struct Connection {
    /// +0x00..+0x08: VFS and database-count state.
    pub _gap_00: [u8; 8],
    /// +0x08: `Db[]` attachment array.
    pub a_db: u32,
}

/// One attached database. The 0x18-byte stride is material to the ARM index.
#[repr(C)]
pub struct Db {
    /// +0x00: attachment name.
    pub z_name: u32,
    /// +0x04: B-tree handle.
    pub p_bt: u32,
    /// +0x08..+0x14: transaction and safety state.
    pub _gap_08: [u8; 0x14 - 0x08],
    /// +0x14: schema object.
    pub p_schema: u32,
}

/// The first schema word is the persistent schema cookie.
#[repr(C)]
pub struct Schema {
    /// +0x00: schema version cookie.
    pub schema_cookie: i32,
}

const _: () = {
    assert!(core::mem::offset_of!(Parse, p_vdbe) == 0x0c);
    assert!(core::mem::offset_of!(Parse, n_temp_reg) == 0x15);
    assert!(core::mem::offset_of!(Parse, a_temp_reg) == 0x18);
    assert!(core::mem::offset_of!(Parse, n_mem) == 0x48);
    assert!(core::mem::offset_of!(Connection, a_db) == 0x08);
    assert!(core::mem::size_of::<Db>() == 0x18);
    assert!(core::mem::offset_of!(Db, p_schema) == 0x14);
};

/// sqlite3ChangeCookie — original: `FUN_08372e54` @ 0x08372e54 (108 bytes;
/// 9 `bl` call sites: 8 unconditional, 1 `blne`, raw-binary verified).
///
/// Reserves `++Parse.nMem`, appends `OP_Integer(schemaCookie + 1, reg)`, then
/// `OP_SetCookie(iDb, 0, reg)`, and releases the temporary register. All
/// pointer and index preconditions are the caller's responsibility, matching
/// the unchecked firmware body.
///
/// # Safety
/// `parse` must name a valid target-layout [`Parse`], whose 32-bit links name
/// a [`Connection`], enough [`Db`] elements for `database_index`, a live
/// [`Schema`], and a writable [`Vdbe`].
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn change_cookie(parse: *mut Parse, database_index: i32) {
    let temp_reg = get_temp_reg(parse.cast());
    let db = (*parse).db as usize as *mut Connection;
    let database = ((*db).a_db as usize as *mut Db).offset(database_index as isize);
    let schema = (*database).p_schema as usize as *mut Schema;
    let vdbe = (*parse).p_vdbe as usize as *mut Vdbe;

    vdbe_add_op2(
        vdbe,
        OP_INTEGER,
        (*schema).schema_cookie.wrapping_add(1),
        temp_reg,
    );
    vdbe_add_op3(vdbe, OP_SET_COOKIE, database_index, 0, temp_reg);
    release_temp_reg(parse.cast(), temp_reg);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::sqlite::mem::tests::Connection as VdbeConnection;
    use crate::sqlite::vdbe::VdbeOp;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::{LazyLock, Mutex};

    const SLAB_LEN: usize = 0x1000;
    const CONNECTION_OFFSET: usize = 0x80;
    const DATABASES_OFFSET: usize = 0x100;
    const SCHEMAS_OFFSET: usize = 0x200;
    const VDBE_OFFSET: usize = 0x400;
    const OPS_OFFSET: usize = 0x600;
    const OPS_LEN: usize = 4;

    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::SQLITE_CHANGE_COOKIE, SLAB_LEN).map(|pointer| pointer as usize)
    });
    static FIXTURE_LOCK: Mutex<()> = Mutex::new(());

    fn low_address(pointer: *mut u8) -> u32 {
        u32::try_from(pointer as usize).unwrap()
    }

    fn blank_op() -> VdbeOp {
        VdbeOp {
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

    unsafe fn fixture(n_mem: i32, n_temp_reg: u8) -> Option<(*mut u8, *mut Parse, *mut Vdbe)> {
        let base = (*SLAB)? as *mut u8;
        base.write_bytes(0, SLAB_LEN);

        let parse = base.cast::<Parse>();
        let connection = base.add(CONNECTION_OFFSET).cast::<Connection>();
        let databases = base.add(DATABASES_OFFSET).cast::<Db>();
        let schemas = base.add(SCHEMAS_OFFSET).cast::<Schema>();
        let vdbe = base.add(VDBE_OFFSET).cast::<Vdbe>();
        let ops = base.add(OPS_OFFSET).cast::<VdbeOp>();
        for index in 0..OPS_LEN {
            ops.add(index).write(blank_op());
        }
        for index in 0..3 {
            databases.add(index).write(Db {
                z_name: 0,
                p_bt: 0,
                _gap_08: [0; 0x14 - 0x08],
                p_schema: low_address(schemas.add(index).cast()),
            });
            schemas.add(index).write(Schema { schema_cookie: 0 });
        }
        connection.write(Connection {
            _gap_00: [0; 8],
            a_db: low_address(databases.cast()),
        });
        let mut vdbe_connection = VdbeConnection::healthy();
        vdbe.write(Vdbe {
            db: core::ptr::null_mut(),
            _gap_04: [0; 4],
            p_next: core::ptr::null_mut(),
            n_op: 0,
            n_op_alloc: OPS_LEN as i32,
            a_op: ops,
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
        });
        // `Vdbe.db` is read only during this call; retain the backing
        // connection by copying it into the otherwise unused tail of the slab.
        base.add(0x800).cast::<VdbeConnection>().write(vdbe_connection);
        (*vdbe).db = base.add(0x800).cast::<VdbeConnection>().cast();
        parse.write(Parse {
            db: low_address(connection.cast()),
            _gap_04: [0; 0x0c - 0x04],
            p_vdbe: low_address(vdbe.cast()),
            _gap_10: [0; 0x15 - 0x10],
            n_temp_reg,
            _gap_16: [0; 2],
            a_temp_reg: [0; 8],
            _gap_38: [0; 0x48 - 0x38],
            n_mem,
        });
        Some((base, parse, vdbe))
    }

    #[test]
    fn emits_cookie_increment_and_set_cookie_for_selected_database() {
        let fixture_guard = FIXTURE_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some((base, parse, vdbe)) = (unsafe { fixture(8, 0) }) else {
            assert!(note_missing_u32_fixture("sqlite/change_cookie"));
            return;
        };
        unsafe { (base.add(SCHEMAS_OFFSET).cast::<Schema>().add(2)).write(Schema { schema_cookie: 41 }) };

        unsafe { change_cookie(parse, 2) };

        let ops = unsafe { (*vdbe).a_op };
        assert_eq!(unsafe { (*vdbe).n_op }, 2);
        assert_eq!(unsafe { ((*ops).opcode, (*ops).p1, (*ops).p2, (*ops).p3) }, (OP_INTEGER as u8, 42, 9, 0));
        assert_eq!(unsafe { ((*ops.add(1)).opcode, (*ops.add(1)).p1, (*ops.add(1)).p2, (*ops.add(1)).p3) }, (OP_SET_COOKIE as u8, 2, 0, 9));
        assert_eq!(unsafe { (*parse).n_mem }, 9);
        assert_eq!(unsafe { ((*parse).n_temp_reg, (*parse).a_temp_reg[0]) }, (1, 9));
        assert_eq!(unsafe { (*vdbe).expired }, 0);
        drop(fixture_guard);
    }

    #[test]
    fn wrapping_cookie_and_full_temp_pool_preserve_arm_edges() {
        let fixture_guard = FIXTURE_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some((base, parse, vdbe)) = (unsafe { fixture(i32::MAX, 8) }) else {
            assert!(note_missing_u32_fixture("sqlite/change_cookie"));
            return;
        };
        unsafe {
            let schemas = base.add(SCHEMAS_OFFSET).cast::<Schema>();
            schemas.add(1).write(Schema { schema_cookie: i32::MAX });
            (*parse).a_temp_reg = [-1, -2, -3, -4, -5, -6, -7, -8];
            change_cookie(parse, 1);
        }

        let ops = unsafe { (*vdbe).a_op };
        assert_eq!(unsafe { ((*ops).p1, (*ops).p2) }, (i32::MIN, i32::MIN));
        assert_eq!(unsafe { ((*ops.add(1)).p1, (*ops.add(1)).p2, (*ops.add(1)).p3) }, (1, 0, i32::MIN));
        assert_eq!(unsafe { (*parse).n_mem }, i32::MIN);
        assert_eq!(unsafe { (*parse).n_temp_reg }, 8);
        assert_eq!(unsafe { (*parse).a_temp_reg }, [-1, -2, -3, -4, -5, -6, -7, -8]);
        drop(fixture_guard);
    }
}
