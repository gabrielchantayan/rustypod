//! The parser's schema gate — every statement that needs a loaded
//! catalogue enters through here.
//!
//! - `sqlite_read_schema` — original: `FUN_083817ec` @ 0x083817ec (64
//!   bytes; 20 `bl` call sites, verified by decoding every B/BL word in
//!   osos.dec: all 20 are unconditional `bl`, no predicated forms, no
//!   tail `b`, and the address appears in no data word, so it is never
//!   dispatched through a table). SQLite 3.5.x's `sqlite3ReadSchema`
//!   (src/build.c), matched statement-for-statement against the
//!   upstream source.
//!
//! Algorithm: pull the connection (`db` at parse +0x00). If a schema
//! load is already running (`db->init.busy`, byte at db +0x80), do
//! nothing and report `SQLITE_OK` — the re-entrant call would be a
//! no-op anyway, because `sqlite3Init` opens with the same test.
//! Otherwise run `sqlite3Init(db, &pParse->zErrMsg)` @ 0x0837b394,
//! which loads every attached database's catalogue and writes any
//! diagnostic straight into the parse context's `zErrMsg` slot (+0x08).
//! A non-zero result is recorded on the parse context — `rc` (+0x04)
//! then `nErr` (+0x40), in that order — and returned. A successful load
//! leaves the parse context completely untouched.
//!
//! Note the failure path *overwrites* an already-latched `rc`, unlike
//! `sqlite::error_msg::sqlite_error_msg` where the first error wins:
//! the original's `strne r1, [r4, #4]` is unconditional on the error
//! branch, with no `cmp` of the old value. Callers exploit this — every
//! one of the 20 sites tests the return against zero and bails out
//! immediately, so a stale `rc` is never the interesting one.
//!
//! ```text
//! 083817ec  push  {r4, lr}
//! 083817f0  mov   r4, r0            ; parse
//! 083817f4  ldr   r0, [r0]          ; db = parse->db
//! 083817f8  mov   r1, #0            ; rc = SQLITE_OK
//! 083817fc  ldrb  r2, [r0, #0x80]   ; db->init.busy
//! 08381800  cmp   r2, #0
//! 08381804  bne   0x8381824
//! 08381808  add   r1, r4, #8        ; &parse->zErrMsg
//! 0838180c  bl    0x837b394         ; sqlite3Init(db, &zErrMsg)
//! 08381810  movs  r1, r0
//! 08381814  strne r1, [r4, #4]      ; parse->rc = rc
//! 08381818  ldrne r0, [r4, #0x40]
//! 0838181c  addne r0, r0, #1
//! 08381820  strne r0, [r4, #0x40]   ; parse->nErr++
//! 08381824  mov   r0, r1
//! 08381828  pop   {r4, pc}
//! ```
//!
//! Deviations:
//! - `sqlite3Init` @ 0x0837b394 (252 bytes) is not ported: it walks
//!   `db->aDb`, calls `sqlite3InitOne` @ 0x0837b5f0 per attached
//!   database, resets the internal schema @ 0x0838209c on failure and
//!   folds in `sqlite3CommitInternalChanges` (clearing
//!   `SQLITE_InternChanges`, bit 4 of `db->flags` at +0x0c) — the whole
//!   catalogue loader, a batch of its own. It is the
//!   [`SQLITE_SCHEMA_INIT`] dispatch boundary (house pattern, see
//!   `sqlite/error_msg.rs`). The default slot reports `SQLITE_OK`: the
//!   state the original reaches when every attached database already
//!   carries `DB_SchemaLoaded`, i.e. no work and no diagnostic.
//! - The `Parse` view is `sqlite::error_msg::Parse`, which already
//!   models exactly the four fields this gate touches (`db`, `rc`,
//!   `z_err_msg`, `n_err`); the `Db` view is
//!   `sqlite::auth_check::Db`, which already models `init.busy`. Typed
//!   `#[repr(C)]` structs rather than raw byte offsets keep the pointer
//!   fields disjoint on a 64-bit test host, and both modules assert the
//!   original offsets on the 32-bit target.

use crate::sqlite::auth_check::Db;
use crate::sqlite::error_msg::{Parse, SQLITE_OK};

/// The catalogue loader: `sqlite3Init(db, &pParse->zErrMsg)` @
/// 0x0837b394. Returns `SQLITE_OK` or the first failing database's
/// result code, and owns the `z_err_msg` slot it is handed.
pub type SchemaInitFn = unsafe extern "C" fn(db: *mut Db, pz_err_msg: *mut *mut u8) -> i32;

/// Default stub: report `SQLITE_OK` and touch nothing — the original's
/// outcome when every attached database's schema is already loaded (see
/// the module header).
pub(crate) unsafe extern "C" fn unported_schema_init(
    _db: *mut Db,
    _pz_err_msg: *mut *mut u8,
) -> i32 {
    SQLITE_OK
}

/// The active catalogue loader. Host tests install recording mocks; the
/// real port replaces the default when 0x0837b394 lands.
pub static mut SQLITE_SCHEMA_INIT: SchemaInitFn = unported_schema_init;

/// Reads the loader slot (volatile — the slot is meant to be swapped at
/// runtime, and a plain read lets LLVM const-fold the default away).
#[inline(always)]
pub(crate) fn schema_init_op() -> SchemaInitFn {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(SQLITE_SCHEMA_INIT)) }
}

/// sqlite_read_schema — original: `FUN_083817ec` @ 0x083817ec (64
/// bytes; 20 `bl` call sites).
///
/// `sqlite3ReadSchema`: make sure the connection's catalogue is loaded
/// before the caller compiles against it. Returns `SQLITE_OK` when the
/// schema is loaded (or a load is already in flight), otherwise the
/// loader's result code — which is also recorded on the parse context.
///
/// Register usage: r0 = parse, r0 = result.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn sqlite_read_schema(parse: *mut Parse) -> i32 {
    let parse = &mut *parse;
    let db = parse.db as *mut Db;
    if (*db).init_busy != 0 {
        return SQLITE_OK;
    }
    let rc = (schema_init_op())(db, &mut parse.z_err_msg);
    if rc != SQLITE_OK {
        parse.rc = rc;
        // Original: `ldrne/addne/strne [r4, #0x40]` — a plain ARM add,
        // it wraps.
        parse.n_err = parse.n_err.wrapping_add(1);
    }
    rc
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use parking_lot::{Mutex, MutexGuard};

    /// Serializes the tests: the loader slot is process-global.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    /// `(db, pz_err_msg)` of the last loader invocation.
    static mut RECORDED: Option<(*mut Db, *mut *mut u8)> = None;
    /// Result code the recording loader hands back.
    static mut NEXT_RC: i32 = SQLITE_OK;
    /// Message the recording loader writes through `pz_err_msg`.
    static mut NEXT_MESSAGE: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn recording_schema_init(db: *mut Db, pz_err_msg: *mut *mut u8) -> i32 {
        RECORDED = Some((db, pz_err_msg));
        *pz_err_msg = NEXT_MESSAGE;
        NEXT_RC
    }

    fn bench() -> MutexGuard<'static, ()> {
        let guard = TEST_LOCK.lock();
        unsafe {
            RECORDED = None;
            NEXT_RC = SQLITE_OK;
            NEXT_MESSAGE = core::ptr::null_mut();
        }
        guard
    }

    /// Swaps in the recording loader for `body`, then restores the
    /// documented default so a failed assertion cannot leak the mock
    /// into the next test.
    unsafe fn with_loader(rc: i32, message: *mut u8, body: impl FnOnce()) {
        NEXT_RC = rc;
        NEXT_MESSAGE = message;
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(SQLITE_SCHEMA_INIT),
            recording_schema_init,
        );
        body();
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(SQLITE_SCHEMA_INIT),
            unported_schema_init,
        );
    }

    /// A connection with `init.busy` set as given; every other byte is
    /// poison, so a stray read shows up.
    fn db(init_busy: u8) -> Db {
        Db {
            _gap_00: [0x5a; 0x80],
            init_busy,
            _gap_81: [0x5a; 0xe0 - 0x81],
            x_auth: None,
            p_auth_arg: core::ptr::null_mut(),
        }
    }

    fn parse(db: *mut Db, rc: i32, n_err: i32) -> Parse {
        Parse {
            db: db as *mut u8,
            rc,
            z_err_msg: core::ptr::null_mut(),
            _gap_0c: [0xa5; 0x12 - 0x0c],
            check_schema: 0xa5,
            _gap_13: [0xa5; 0x40 - 0x13],
            n_err,
        }
    }

    #[test]
    fn a_load_already_in_flight_is_a_no_op() {
        let _guard = bench();
        let mut connection = db(1);
        let mut parse = parse(&mut connection, 7, 3);
        unsafe {
            with_loader(21, core::ptr::null_mut(), || {
                assert_eq!(sqlite_read_schema(&mut parse), SQLITE_OK, "reports OK");
            });
            let recorded = core::ptr::read(core::ptr::addr_of!(RECORDED));
            assert_eq!(recorded, None, "the loader is not re-entered");
            assert_eq!(parse.rc, 7, "the parse context is untouched");
            assert_eq!(parse.n_err, 3);
        }
    }

    #[test]
    fn a_successful_load_leaves_the_parse_context_alone() {
        let _guard = bench();
        let mut connection = db(0);
        let mut parse = parse(&mut connection, 7, 3);
        let db_ptr = &mut connection as *mut Db;
        unsafe {
            with_loader(SQLITE_OK, core::ptr::null_mut(), || {
                assert_eq!(sqlite_read_schema(&mut parse), SQLITE_OK);
            });
            let recorded = core::ptr::read(core::ptr::addr_of!(RECORDED));
            assert_eq!(
                recorded,
                Some((db_ptr, core::ptr::addr_of_mut!(parse.z_err_msg))),
                "loader saw (db, &parse->zErrMsg)"
            );
            assert_eq!(parse.rc, 7, "rc not disturbed");
            assert_eq!(parse.n_err, 3, "counter not bumped");
        }
    }

    #[test]
    fn a_failed_load_records_the_code_and_bumps_the_counter() {
        let _guard = bench();
        let mut connection = db(0);
        let mut parse = parse(&mut connection, SQLITE_OK, 41);
        unsafe {
            with_loader(11, core::ptr::null_mut(), || {
                assert_eq!(sqlite_read_schema(&mut parse), 11, "the code is returned");
            });
            assert_eq!(parse.rc, 11, "recorded on the parse context");
            assert_eq!(parse.n_err, 42, "counter bumped");
        }
    }

    #[test]
    fn a_failed_load_overwrites_an_already_latched_code() {
        let _guard = bench();
        let mut connection = db(0);
        let mut parse = parse(&mut connection, 5, 1);
        unsafe {
            with_loader(1, core::ptr::null_mut(), || {
                sqlite_read_schema(&mut parse);
            });
            // Unlike sqlite_error_msg, there is no first-error-wins
            // test here: `strne r1, [r4, #4]` is unconditional on the
            // error branch.
            assert_eq!(parse.rc, 1, "the latest code wins");
            assert_eq!(parse.n_err, 2);
        }
    }

    #[test]
    fn the_loaders_diagnostic_lands_in_the_parse_context() {
        let _guard = bench();
        let mut connection = db(0);
        let mut canned = std::vec::Vec::from(*b"malformed database schema\0");
        let message = canned.as_mut_ptr();
        let mut parse = parse(&mut connection, SQLITE_OK, 0);
        unsafe {
            with_loader(11, message, || {
                sqlite_read_schema(&mut parse);
            });
            assert_eq!(parse.z_err_msg, message, "written through &zErrMsg");
        }
    }

    #[test]
    fn the_error_counter_wraps_like_the_original() {
        let _guard = bench();
        let mut connection = db(0);
        let mut parse = parse(&mut connection, SQLITE_OK, i32::MAX);
        unsafe {
            with_loader(1, core::ptr::null_mut(), || {
                sqlite_read_schema(&mut parse);
            });
            assert_eq!(parse.n_err, i32::MIN, "plain ARM add, no saturation");
        }
    }

    #[test]
    fn any_non_zero_busy_byte_skips_the_load() {
        let _guard = bench();
        unsafe {
            for busy in [1u8, 2, 0x80, 0xff] {
                let mut connection = db(busy);
                let mut parse = parse(&mut connection, SQLITE_OK, 0);
                with_loader(11, core::ptr::null_mut(), || {
                    assert_eq!(sqlite_read_schema(&mut parse), SQLITE_OK, "busy = {busy}");
                });
                assert_eq!(parse.n_err, 0, "busy = {busy}");
            }
        }
    }

    #[test]
    fn the_default_loader_reports_a_loaded_schema() {
        let _guard = bench();
        let mut connection = db(0);
        let mut parse = parse(&mut connection, 9, 4);
        unsafe {
            assert_eq!(sqlite_read_schema(&mut parse), SQLITE_OK);
            assert_eq!(parse.rc, 9, "no work, no diagnostic");
            assert_eq!(parse.n_err, 4);
            assert!(parse.z_err_msg.is_null());
        }
    }

    #[test]
    fn nothing_outside_the_three_written_fields_is_touched() {
        let _guard = bench();
        let mut connection = db(0);
        let mut parse = parse(&mut connection, SQLITE_OK, 0);
        unsafe {
            with_loader(11, core::ptr::null_mut(), || {
                sqlite_read_schema(&mut parse);
            });
            assert!(parse._gap_0c.iter().all(|b| *b == 0xa5), "parse gap before check_schema clobbered");
            assert_eq!(parse.check_schema, 0xa5, "check_schema clobbered");
            assert!(parse._gap_13.iter().all(|b| *b == 0xa5), "parse gap after check_schema clobbered");
            assert!(connection._gap_00.iter().all(|b| *b == 0x5a), "db head clobbered");
            assert_eq!(connection.init_busy, 0, "the busy flag is read, never written");
            assert!(connection._gap_81.iter().all(|b| *b == 0x5a), "db tail clobbered");
        }
    }
}
