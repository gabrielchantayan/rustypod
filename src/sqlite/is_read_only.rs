//! Rejecting writes to protected SQLite relations.
//!
//! - `sqlite_is_read_only` — original: `FUN_0837cc74` @ `0x0837cc74`
//!   (**120 bytes**; raw body is 30 ARM words through `pop {r4,pc}` at
//!   `0x0837ccf0`, followed by inline diagnostic literals). It has **3
//!   direct inbound `bl` call sites**, all unconditional (0x08374b68,
//!   0x0837bb00, 0x08385480), and makes **1 unconditional `bl`** to the
//!   ported [`sqlite_error_msg`] @ `0x083767a0`.
//!
//! SQLite's `sqlite3IsReadOnly`: report and return 1 for a read-only table
//! outside nested parsing and schema writes, or for a materialized ordinary
//! view when `view_ok` is clear. A compound view (`pPrior != NULL`) and an
//! unmaterialized view are accepted. Otherwise return 0.
//!
//! Deliberate deviation: the C variadic error calls use the project's
//! explicit one-word `VaList`; typed `#[repr(C)]` views preserve target
//! offsets on ARM while allowing host pointers to widen safely.

use super::check_object_name::{Connection, Parse};
use super::error_msg::{sqlite_error_msg, Parse as ErrorParse};

const WRITE_SCHEMA_FLAG: u32 = 0x800;
const READ_ONLY_TABLE_FORMAT: &[u8; 29] = b"table %s may not be modified\0";
const VIEW_FORMAT: &[u8; 38] = b"cannot modify %s because it is a view\0";

/// SQLite's target-layout `Table` fields used by `sqlite3IsReadOnly`.
#[repr(C)]
pub struct Table {
    /// +0x00: relation name.
    pub name: *const u8,
    /// +0x04..+0x18: unmodeled.
    pub _gap_04: [u8; 0x18 - 0x04],
    /// +0x18: column array; NULL means the view has not been materialized.
    pub columns: *mut u8,
    /// +0x1c..+0x34: unmodeled.
    pub _gap_1c: [u8; 0x34 - 0x1c],
    /// +0x34: schema-table read-only flag.
    pub read_only: u8,
    /// +0x35..+0x3c: unmodeled.
    pub _gap_35: [u8; 0x3c - 0x35],
    /// +0x3c: SELECT defining a view, if this relation is a view.
    pub select: *mut Select,
}

/// SQLite's target-layout `Select` field used by `sqlite3IsReadOnly`.
#[repr(C)]
pub struct Select {
    /// +0x00..+0x34: unmodeled.
    pub _gap_00: [u8; 0x34],
    /// +0x34: prior SELECT in a compound query.
    pub prior: *mut Select,
}

#[cfg(target_pointer_width = "32")]
const _: () = {
    assert!(core::mem::offset_of!(Table, columns) == 0x18);
    assert!(core::mem::offset_of!(Table, read_only) == 0x34);
    assert!(core::mem::offset_of!(Table, select) == 0x3c);
    assert!(core::mem::offset_of!(Select, prior) == 0x34);
};

/// sqlite_is_read_only — original: `FUN_0837cc74` @ `0x0837cc74` (120
/// bytes; 3 unconditional direct inbound `bl` call sites).
///
/// # Safety
///
/// `parse`, `table`, `parse->db`, and a non-NULL `table->select` must point
/// to live firmware objects, as the original dereferences them directly.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn sqlite_is_read_only(parse: *mut Parse, table: *mut Table, view_ok: i32) -> i32 {
    let parse_ref = &mut *parse;
    let table_ref = &*table;
    if table_ref.read_only != 0
        && ((*parse_ref.db).flags & WRITE_SCHEMA_FLAG == 0)
        && parse_ref.nested == 0
    {
        let args = [table_ref.name as usize as u32];
        sqlite_error_msg(parse.cast::<ErrorParse>(), READ_ONLY_TABLE_FORMAT.as_ptr(), args.as_ptr());
        return 1;
    }
    if !table_ref.select.is_null()
        && (*table_ref.select).prior.is_null()
        && view_ok == 0
        && !table_ref.columns.is_null()
    {
        let args = [table_ref.name as usize as u32];
        sqlite_error_msg(parse.cast::<ErrorParse>(), VIEW_FORMAT.as_ptr(), args.as_ptr());
        return 1;
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sqlite::error_msg::Parse as ErrorParse;

    struct Fixture {
        parse: Parse,
        error_parse: ErrorParse,
        db: Connection,
        table: Table,
        select: Select,
    }

    impl Fixture {
        fn new() -> Self {
            let mut fixture = Self {
                parse: Parse { db: core::ptr::null_mut(), _gap_04: [0; 0x0f], nested: 0 },
                error_parse: ErrorParse {
                    db: core::ptr::null_mut(), rc: 0, z_err_msg: core::ptr::null_mut(),
                    _gap_0c: [0; 6], check_schema: 0, _gap_13: [0; 0x2d], n_err: 0,
                },
                db: Connection { _gap_00: [0; 12], flags: 0, _gap_10: [0; 0x70], init_busy: 0 },
                table: Table { name: b"t\0".as_ptr(), _gap_04: [0; 20], columns: core::ptr::null_mut(), _gap_1c: [0; 24], read_only: 0, _gap_35: [0; 7], select: core::ptr::null_mut() },
                select: Select { _gap_00: [0; 0x34], prior: core::ptr::null_mut() },
            };
            fixture.parse.db = &mut fixture.db;
            fixture.error_parse.db = (&mut fixture.db as *mut Connection).cast();
            fixture
        }

        fn parse_ptr(&mut self) -> *mut Parse {
            // The two views have host-widened layouts; synchronize the fields
            // observed by their respective users before each invocation.
            self.parse.db = &mut self.db;
            self.error_parse.db = (&mut self.db as *mut Connection).cast();
            &mut self.parse
        }
    }

    #[test]
    fn read_only_table_reports_unless_schema_write_or_nested_parse() {
        let mut fixture = Fixture::new();
        fixture.table.read_only = 1;
        assert_eq!(unsafe { sqlite_is_read_only(fixture.parse_ptr(), &mut fixture.table, 0) }, 1);
        fixture.db.flags = WRITE_SCHEMA_FLAG;
        assert_eq!(unsafe { sqlite_is_read_only(fixture.parse_ptr(), &mut fixture.table, 0) }, 0);
        fixture.db.flags = 0;
        fixture.parse.nested = 1;
        assert_eq!(unsafe { sqlite_is_read_only(fixture.parse_ptr(), &mut fixture.table, 0) }, 0);
    }

    #[test]
    fn only_materialized_single_select_view_requires_view_permission() {
        let mut fixture = Fixture::new();
        fixture.table.select = &mut fixture.select;
        fixture.table.columns = core::ptr::dangling_mut();
        assert_eq!(unsafe { sqlite_is_read_only(fixture.parse_ptr(), &mut fixture.table, 0) }, 1);
        assert_eq!(unsafe { sqlite_is_read_only(fixture.parse_ptr(), &mut fixture.table, 1) }, 0);
        fixture.select.prior = core::ptr::dangling_mut();
        assert_eq!(unsafe { sqlite_is_read_only(fixture.parse_ptr(), &mut fixture.table, 0) }, 0);
        fixture.select.prior = core::ptr::null_mut();
        fixture.table.columns = core::ptr::null_mut();
        assert_eq!(unsafe { sqlite_is_read_only(fixture.parse_ptr(), &mut fixture.table, 0) }, 0);
    }
}
