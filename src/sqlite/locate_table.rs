//! Resolving a table or view name from a parser context.
//!
//! - `sqlite_locate_table` — original: `FUN_0837d250` @ 0x0837d250 (120
//!   bytes; 9 `bl` call sites, verified by decoding every ARM B/BL word in
//!   osos.dec: all nine are unconditional `bl`, with no predicated forms,
//!   tail branches, or aligned data-word references). SQLite's
//!   `sqlite3LocateTable` family helper.
//!
//! Algorithm: load the schema through `sqlite_read_schema`; on failure
//! return NULL immediately. Otherwise find `name` in `database` through
//! `find_table`. A miss reports either `no such table` or `no such view`,
//! with an optional `database.` qualifier, then latches
//! `Parse.check_schema` (+0x12) before returning NULL. A hit leaves the
//! parse context untouched and returns the found `Table *`.
//!
//! The original's three callees are already ported and are called directly:
//! `sqlite_read_schema` @ 0x083817ec, `find_table` @ 0x08379024, and
//! `sqlite_error_msg` @ 0x083767a0. Deliberate deviation: C varargs become
//! the existing explicit `VaList` convention; a fixed local word array is
//! the original's r2/r3/stack varargs home area.

use super::error_msg::{sqlite_error_msg, Parse};
use super::find_table::find_table;
use super::read_schema::sqlite_read_schema;

const NO_SUCH_TABLE: &[u8] = b"no such table\0";
const NO_SUCH_VIEW: &[u8] = b"no such view\0";
const UNQUALIFIED_FORMAT: &[u8] = b"%s: %s\0";
const QUALIFIED_FORMAT: &[u8] = b"%s: %s.%s\0";

/// Builds the exact message formatter inputs from the original's
/// `cmp/mov/strne/add{eq,ne}` sequence. The trailing zero is unused for an
/// unqualified name, just as the formatter consumes only format arguments.
#[inline(always)]
fn missing_relation_error(
    is_view: u32,
    name: *const u8,
    database: *const u8,
) -> (*const u8, [u32; 3]) {
    let relation = if is_view == 0 { NO_SUCH_TABLE } else { NO_SUCH_VIEW };
    if database.is_null() {
        (
            UNQUALIFIED_FORMAT.as_ptr(),
            [relation.as_ptr() as usize as u32, name as usize as u32, 0],
        )
    } else {
        (
            QUALIFIED_FORMAT.as_ptr(),
            [
                relation.as_ptr() as usize as u32,
                database as usize as u32,
                name as usize as u32,
            ],
        )
    }
}

/// sqlite_locate_table — original: `FUN_0837d250` @ 0x0837d250 (120 bytes;
/// 9 unconditional `bl` call sites).
///
/// Locate `name` in `database`, reporting the correct table/view diagnostic
/// and marking the parse context for a schema check if no relation exists.
/// `is_view != 0` selects the view diagnostic.
///
/// # Safety
/// `parse`, `name`, and non-NULL `database` must be valid firmware objects
/// and NUL-terminated strings respectively; `parse->db` must be a valid
/// SQLite connection. The same requirements apply to the direct ports this
/// function calls.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn sqlite_locate_table(
    parse: *mut Parse,
    is_view: u32,
    name: *const u8,
    database: *const u8,
) -> *mut u8 {
    if sqlite_read_schema(parse) != 0 {
        return core::ptr::null_mut();
    }

    let table = find_table((*parse).db, name, database);
    if table.is_null() {
        let (format, args) = missing_relation_error(is_view, name, database);
        sqlite_error_msg(parse, format, args.as_ptr());
        (*parse).check_schema = 1;
    }
    table
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::sqlite::error_msg::{SQLITE_ERROR, SQLITE_OK};

    #[repr(C, align(8))]
    struct Connection {
        bytes: [u8; 0x84],
    }

    fn connection(n_db: i32) -> Connection {
        let mut connection = Connection { bytes: [0; 0x84] };
        unsafe {
            connection.bytes.as_mut_ptr().add(4).cast::<i32>().write(n_db);
        }
        connection
    }

    fn parse(db: *mut u8, rc: i32, n_err: i32) -> Parse {
        Parse {
            db,
            rc,
            z_err_msg: core::ptr::null_mut(),
            _gap_0c: [0xa5; 0x12 - 0x0c],
            check_schema: 0,
            _gap_13: [0xa5; 0x40 - 0x13],
            n_err,
        }
    }

    #[test]
    fn unqualified_missing_table_records_error_and_schema_check() {
        let mut connection = connection(0);
        let mut parse = parse(connection.bytes.as_mut_ptr(), SQLITE_OK, 4);
        unsafe {
            let table = sqlite_locate_table(
                &mut parse,
                0,
                b"tracks\0".as_ptr(),
                core::ptr::null(),
            );
            assert!(table.is_null());
        }
        assert_eq!(parse.rc, SQLITE_ERROR, "the first error becomes SQLITE_ERROR");
        assert_eq!(parse.n_err, 5, "the reporter increments nErr exactly once");
        assert_eq!(parse.check_schema, 1, "a lookup miss requests schema recheck");
        assert!(parse.z_err_msg.is_null(), "the default formatter models allocation failure");
    }

    #[test]
    fn qualified_missing_view_keeps_an_existing_error_code() {
        let mut connection = connection(0);
        let mut parse = parse(connection.bytes.as_mut_ptr(), 23, -1);
        unsafe {
            let view = sqlite_locate_table(
                &mut parse,
                7,
                b"recently_played\0".as_ptr(),
                b"main\0".as_ptr(),
            );
            assert!(view.is_null());
        }
        assert_eq!(parse.rc, 23, "sqlite_error_msg preserves the first result code");
        assert_eq!(parse.n_err, 0, "plain ARM addition wraps -1 to zero");
        assert_eq!(parse.check_schema, 1);
    }

    #[test]
    fn missing_relation_formats_match_table_view_and_qualification() {
        let name = b"items\0".as_ptr();
        let database = b"temp\0".as_ptr();
        let (format, args) = missing_relation_error(0, name, core::ptr::null());
        assert_eq!(format, UNQUALIFIED_FORMAT.as_ptr());
        assert_eq!(args, [NO_SUCH_TABLE.as_ptr() as usize as u32, name as usize as u32, 0]);

        let (format, args) = missing_relation_error(1, name, database);
        assert_eq!(format, QUALIFIED_FORMAT.as_ptr());
        assert_eq!(args, [
            NO_SUCH_VIEW.as_ptr() as usize as u32,
            database as usize as u32,
            name as usize as u32,
        ]);
    }
}
