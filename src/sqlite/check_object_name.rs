//! Guarding the `sqlite_` name prefix against user-created objects.
//!
//! - `sqlite_check_object_name` — original: `FUN_08372ec0` @
//!   `0x08372ec0` (**100 bytes**; extent verified from the raw words —
//!   the body ends with the twin `pop {r4,r5,r6,pc}` exits at
//!   `0x08372f1c..0x08372f24` and is followed by its two inline literal
//!   strings, `"sqlite_"` and `"object name reserved for internal
//!   use: %s"`, with the next separately linked function starting at
//!   `0x08372f58` on `push {r0-r11,lr}`). **4 direct `bl` call sites,
//!   all unconditional** (0x0836ef98, 0x0836fe98, 0x08373edc,
//!   0x08384688), verified by decoding every ARM B/BL word in
//!   osos.dec; Ghidra's "4 bl" count agrees, and the function itself
//!   issues exactly 2 `bl` calls (both unconditional). SQLite 3.5.9's
//!   `sqlite3CheckObjectName` (src/build.c).
//!
//! Algorithm: reject user object names that collide with SQLite's
//! internal `sqlite_` prefix — unless the schema is being read or
//! written by SQLite itself. Concretely, return 0 (name acceptable)
//! when any of these hold:
//!
//! 1. the connection is initialising its schema (`db->init.busy`,
//!    byte at +0x80 of the connection, non-zero);
//! 2. this is a nested (trigger/fkey) parse (`Parse.nested`, byte at
//!    +0x13, non-zero);
//! 3. the connection's write-schema flag is set (bit `0x800` of
//!    `db->flags`, word at +0x0c);
//! 4. the name does not begin with `sqlite_` (case-insensitive, first
//!    7 bytes, [`str_nicmp`] @ 0x08384fa0).
//!
//! Otherwise report "object name reserved for internal use: %s" with
//! the offending name through `sqlite3ErrorMsg` @ 0x083767a0 and
//! return 1. The original's predicated guard chain (`ldrbeq/cmpeq/
//! ldreq/tsteq` fall-through) evaluates the four conditions strictly
//! in this order, short-circuiting on the first hit; the port keeps
//! that order.
//!
//! Deliberate deviations:
//!
//! - Both callees are ported and are called directly, per the house
//!   rule: [`str_nicmp`] and [`sqlite_error_msg`]. The original is
//!   C-variadic (`sqlite3ErrorMsg(pParse, fmt, zName)` — r2 = name);
//!   the port follows the existing explicit-`VaList` convention with a
//!   fixed local word array as the r2/r3 varargs home (same pattern as
//!   `sqlite/locate_table.rs`).
//! - `Parse` and the connection are typed `#[repr(C)]` views rather
//!   than raw byte offsets, so the pointer field stays disjoint on a
//!   64-bit host. The original offsets are asserted on the 32-bit
//!   target.

use super::error_msg::{sqlite_error_msg, Parse as ErrorParse};
use super::stricmp::str_nicmp;

/// The reserved prefix every internal SQLite object name starts with
/// (original: the inline literal at 0x08372f24, compared for 7 bytes).
const RESERVED_PREFIX: &[u8; 8] = b"sqlite_\0";

/// The diagnostic reported for a reserved name (original: the inline
/// literal at 0x08372f2c; `%s` consumes the offending name).
const RESERVED_NAME_FORMAT: &[u8; 42] = b"object name reserved for internal use: %s\0";

/// The write-schema bit in `db->flags` (original: `tsteq r0, #0x800`).
/// While set (SQLite itself is rewriting the schema) any name goes.
const WRITE_SCHEMA_FLAG: u32 = 0x800;

/// The fields of SQLite's `Parse` this guard reads. Disjoint from the
/// [`crate::sqlite::error_msg::Parse`] view — the same underlying
/// struct, cast at the call site per house precedent
/// (`sqlite/auth_check.rs`).
#[repr(C)]
pub struct Parse {
    /// +0x000: the owning connection (`sqlite3 *`).
    pub db: *mut Connection,
    /// +0x004..+0x013: unmodeled.
    pub _gap_04: [u8; 0x13 - 0x04],
    /// +0x013: non-zero while parsing a nested (trigger/fkey) program —
    /// internal names are expected there (original:
    /// `ldrbeq r1,[r4,#19]`).
    pub nested: u8,
}

/// The fields of the connection (`sqlite3`) this guard reads.
#[repr(C)]
pub struct Connection {
    /// +0x000..+0x00c: unmodeled (`pVfs`, `nDb`, `aDb`).
    pub _gap_00: [u8; 0x0c],
    /// +0x00c: connection flags; bit [`WRITE_SCHEMA_FLAG`] permits
    /// reserved names (original: `ldreq r0,[r0,#12]; tsteq r0,#0x800`).
    pub flags: u32,
    /// +0x010..+0x080: unmodeled.
    pub _gap_10: [u8; 0x80 - 0x10],
    /// +0x080: `db->init.busy` — schema initialisation in progress
    /// (original: `ldrb r1,[r0,#128]`).
    pub init_busy: u8,
}

// The original's layout, asserted on the 32-bit target. On a 64-bit
// host the pointer field widens and `Parse.nested` shifts — harmless,
// because every access goes through the typed structs.
#[cfg(target_pointer_width = "32")]
const _: () = {
    assert!(core::mem::offset_of!(Parse, nested) == 0x13);
    assert!(core::mem::offset_of!(Connection, flags) == 0x0c);
    assert!(core::mem::offset_of!(Connection, init_busy) == 0x80);
};

/// sqlite_check_object_name — original: `FUN_08372ec0` @ `0x08372ec0`
/// (100 bytes; 4 unconditional direct `bl` call sites).
///
/// `sqlite3CheckObjectName`: return 1 (and record the "reserved name"
/// error on `parse`) when `name` starts with the internal `sqlite_`
/// prefix while no internal-schema exception applies; return 0
/// otherwise. See the module header for the guard order.
///
/// # Safety
///
/// `parse` must point to a real parse context with a valid `db` (the
/// original dereferences both unconditionally), and `name` must be
/// readable for at least 7 bytes or up to its NUL, whichever is first.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn sqlite_check_object_name(parse: *mut Parse, name: *const u8) -> i32 {
    let parse = &mut *parse;
    let db = &*parse.db;
    if db.init_busy != 0
        || parse.nested != 0
        || db.flags & WRITE_SCHEMA_FLAG != 0
        || str_nicmp(name, RESERVED_PREFIX.as_ptr(), 7) != 0
    {
        return 0;
    }
    // Original: r2 = zName is the sole variadic argument; the explicit
    // VaList word array is that spilled-register home.
    let args = [name as usize as u32];
    sqlite_error_msg(parse as *mut Parse as *mut ErrorParse, RESERVED_NAME_FORMAT.as_ptr(), args.as_ptr());
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A parse/connection fixture pair. The error_msg view reads
    /// `Parse.db/rc/z_err_msg/...` through the same base pointer, so
    /// the backing block must span that view's host layout (its pointer
    /// fields widen to 8 bytes, putting `n_err` at +76) and alignment;
    /// the zeroed words keep `rc = SQLITE_OK` and `z_err_msg = NULL`.
    struct Fixture {
        parse_block: [u64; 10],
        connection: Connection,
    }

    impl Fixture {
        fn new(init_busy: u8, nested: u8, flags: u32) -> Fixture {
            let mut fixture = Fixture {
                parse_block: [0; 10],
                connection: Connection {
                    _gap_00: [0; 0x0c],
                    flags,
                    _gap_10: [0; 0x80 - 0x10],
                    init_busy,
                },
            };
            let parse = fixture.parse();
            unsafe {
                (*parse).db = &mut fixture.connection;
                (*parse).nested = nested;
            }
            fixture
        }

        fn parse(&mut self) -> *mut Parse {
            self.parse_block.as_mut_ptr().cast()
        }

        fn n_err(&mut self) -> i32 {
            unsafe { (*(self.parse() as *mut ErrorParse)).n_err }
        }
    }

    #[test]
    fn reserved_name_reports_error_and_returns_one() {
        let mut fixture = Fixture::new(0, 0, 0);
        let rc = unsafe {
            sqlite_check_object_name(fixture.parse(), b"sqlite_master".as_ptr())
        };
        assert_eq!(rc, 1);
        assert_eq!(fixture.n_err(), 1, "the error is recorded on the parse context");
    }

    #[test]
    fn prefix_match_is_case_insensitive() {
        let mut fixture = Fixture::new(0, 0, 0);
        let rc = unsafe {
            sqlite_check_object_name(fixture.parse(), b"SQLITE_sequence".as_ptr())
        };
        assert_eq!(rc, 1);
    }

    #[test]
    fn ordinary_name_is_accepted() {
        let mut fixture = Fixture::new(0, 0, 0);
        let rc = unsafe { sqlite_check_object_name(fixture.parse(), b"my_table".as_ptr()) };
        assert_eq!(rc, 0);
        assert_eq!(fixture.n_err(), 0, "no error is recorded");
    }

    #[test]
    fn short_name_matching_prefix_stem_is_accepted() {
        // Only 7 bytes are compared; "sqlite" (6 bytes) diverges at the
        // NUL versus '_' and must pass.
        let mut fixture = Fixture::new(0, 0, 0);
        let rc = unsafe { sqlite_check_object_name(fixture.parse(), b"sqlite".as_ptr()) };
        assert_eq!(rc, 0);
        assert_eq!(fixture.n_err(), 0);
    }

    #[test]
    fn schema_init_permits_reserved_name() {
        let mut fixture = Fixture::new(1, 0, 0);
        let rc = unsafe {
            sqlite_check_object_name(fixture.parse(), b"sqlite_master".as_ptr())
        };
        assert_eq!(rc, 0);
        assert_eq!(fixture.n_err(), 0);
    }

    #[test]
    fn nested_parse_permits_reserved_name() {
        let mut fixture = Fixture::new(0, 1, 0);
        let rc = unsafe {
            sqlite_check_object_name(fixture.parse(), b"sqlite_master".as_ptr())
        };
        assert_eq!(rc, 0);
        assert_eq!(fixture.n_err(), 0);
    }

    #[test]
    fn write_schema_flag_permits_reserved_name() {
        let mut fixture = Fixture::new(0, 0, WRITE_SCHEMA_FLAG);
        let rc = unsafe {
            sqlite_check_object_name(fixture.parse(), b"sqlite_master".as_ptr())
        };
        assert_eq!(rc, 0);
        assert_eq!(fixture.n_err(), 0);
    }

    #[test]
    fn unrelated_flags_do_not_permit_reserved_name() {
        let mut fixture = Fixture::new(0, 0, !WRITE_SCHEMA_FLAG);
        let rc = unsafe {
            sqlite_check_object_name(fixture.parse(), b"sqlite_master".as_ptr())
        };
        assert_eq!(rc, 1, "only the 0x800 bit grants the exception");
    }
}
