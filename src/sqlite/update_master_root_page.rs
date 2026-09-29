//! Emits the schema update after a table's root page moves.
//!
//! - `update_master_root_page` — original: `FUN_082c5fbc` @ 0x082c5fbc
//!   (132 bytes; 2 incoming plain `bl` call sites, no predicated `bl`).
//!
//! The original obtains the statement, reserves a temporary register, emits
//! `OP_ParseSchema` (106), then nested-parses an UPDATE of the appropriate
//! master table. It tail-calls `release_temp_reg` with the reserved register.
//! Raw words establish the extent `0x082c5fbc..0x082c6040`: four internal
//! plain `bl` calls and one tail `b`; the following bytes are string data.
//!
//! Deliberate deviation: `get_vdbe` remains the existing volatile seam in
//! `begin_write_operation`; its default reads `Parse.pVdbe`. The original
//! `sqlite3GetVdbe` has no Rust symbol yet.

use super::begin_write_operation::{get_vdbe_op, Connection, Parse};
use super::error_msg::VaList;
use super::get_temp_reg::get_temp_reg;
use super::nested_parse::{sqlite_nested_parse, NestedParse};
use super::parse::release_temp_reg;
use super::vdbe::vdbe_add_op3;

const OP_PARSE_SCHEMA: i32 = 0x6a;
const SQLITE_MASTER: &[u8] = b"sqlite_master\0";
const SQLITE_TEMP_MASTER: &[u8] = b"sqlite_temp_master\0";
const UPDATE_ROOT_PAGE: &[u8] = b"UPDATE %Q.%s SET rootpage=%d WHERE #%d AND rootpage=#%d\0";

/// update_master_root_page — original: `FUN_082c5fbc` @ 0x082c5fbc (132
/// bytes; 2 incoming plain `bl` call sites, no predicated `bl`).
///
/// Emit `OP_ParseSchema` for `root_page`, then compile the corresponding
/// `sqlite_master`/`sqlite_temp_master` root-page update. `database_index ==
/// 1` selects the temporary master table; every other value selects the main
/// master table, exactly matching the original's `cmp r5,#1`.
///
/// # Safety
/// `parse` must point to the target-layout SQLite `Parse`; its connection and
/// attached-database array must be valid for `database_index`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn update_master_root_page(
    parse: *mut u8,
    root_page: i32,
    database_index: i32,
) {
    let vdbe = (get_vdbe_op())(parse.cast::<Parse>());
    let temp_reg = get_temp_reg(parse);
    vdbe_add_op3(vdbe, OP_PARSE_SCHEMA, root_page, temp_reg, database_index);

    let connection = (parse as *const NestedParse).read().db as usize as *mut Connection;
    let database = (*connection).a_db.offset(database_index as isize);
    let master = if database_index == 1 { SQLITE_TEMP_MASTER } else { SQLITE_MASTER };
    let args = [(*database).z_name as usize as u32, master.as_ptr() as usize as u32, root_page as u32, temp_reg as u32, temp_reg as u32];
    sqlite_nested_parse(parse.cast::<NestedParse>(), UPDATE_ROOT_PAGE.as_ptr(), args.as_ptr() as VaList);
    release_temp_reg(parse, temp_reg);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::sqlite::begin_write_operation::{BeginWriteOps, Db, DEFAULT_BEGIN_WRITE_OPS, BEGIN_WRITE_OPS};
    use crate::sqlite::vdbe::{Vdbe, VdbeOp};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr;
    use std::sync::{LazyLock, Mutex, MutexGuard};

    const SLAB_LEN: usize = 0x1000;
    const DB_OFFSET: usize = 0x300;
    const DBS_OFFSET: usize = 0x400;
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| try_map_u32_slab(hints::SQLITE_UPDATE_MASTER_ROOT_PAGE, SLAB_LEN).map(|p| p as usize));
    static LOCK: Mutex<()> = Mutex::new(());
    static mut VDBE: *mut Vdbe = ptr::null_mut();

    unsafe extern "C" fn recording_get_vdbe(_parse: *mut Parse) -> *mut Vdbe { VDBE }


    struct Fixture { _guard: MutexGuard<'static, ()> }
    impl Fixture {
        fn new(vdbe: *mut Vdbe) -> Self {
            let guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
            unsafe {
                VDBE = vdbe;
                ptr::write_volatile(ptr::addr_of_mut!(BEGIN_WRITE_OPS), BeginWriteOps { get_vdbe: recording_get_vdbe, ..DEFAULT_BEGIN_WRITE_OPS });
            }
            Self { _guard: guard }
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            unsafe {
                ptr::write_volatile(ptr::addr_of_mut!(BEGIN_WRITE_OPS), DEFAULT_BEGIN_WRITE_OPS);
            }
        }
    }

    unsafe fn run(database_index: i32) -> (VdbeOp, u8) {
        let Some(slab) = *SLAB else { note_missing_u32_fixture("update_master_root_page"); return (core::mem::zeroed(), 0); };
        ptr::write_bytes(slab as *mut u8, 0, SLAB_LEN);
        let mut ops: [VdbeOp; 1] = core::mem::zeroed();
        let mut vdbe: Vdbe = core::mem::zeroed();
        vdbe.n_op_alloc = 1;
        vdbe.a_op = ops.as_mut_ptr();
        let _fixture = Fixture::new(&mut vdbe);
        let parse = slab as *mut u8;
        let connection = parse.add(DB_OFFSET).cast::<Connection>();
        let databases = parse.add(DBS_OFFSET).cast::<Db>();
        (*connection).a_db = databases;
        (*databases.offset(database_index as isize)).z_name = b"main\0".as_ptr();
        (parse as *mut NestedParse).write(NestedParse { db: connection as usize as u32, _before_nested: [0; 0x0f], nested: 1, _before_parser_state: [0; 0x138], parser_state: [0; 0x5c] });
        (parse.add(0x48) as *mut i32).write(40);
        parse.add(0x15).write(0);
        update_master_root_page(parse, 77, database_index);
        (ops[0], parse.add(0x15).read())
    }

    #[test]
    fn emits_parse_schema_and_main_master_update() {
        unsafe {
            let (op, temps) = run(0);
            assert_eq!((op.opcode, op.p1, op.p2, op.p3), (OP_PARSE_SCHEMA as u8, 77, 41, 0));
            assert_eq!(temps, 1);
        }
    }

    #[test]
    fn selects_temp_master_only_for_database_one() {
        unsafe {
            let (op, _) = run(1);
            assert_eq!((op.p1, op.p2, op.p3), (77, 41, 1));
        }
    }
}
