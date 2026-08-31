//! The parser's authorization gate — the single point every SQL action
//! in osos passes through before the code generator emits for it.
//!
//! - `sqlite_auth_check` — original: `FUN_0836f91c` @ 0x0836f91c (156
//!   bytes; 28 `bl` call sites, verified by decoding every B/BL word in
//!   osos.dec: all 28 are unconditional `bl`, no predicated forms, no
//!   tail `b`). SQLite 3.5.9's `sqlite3AuthCheck` (src/auth.c), matched
//!   statement-for-statement against the upstream source.
//!
//! Algorithm: pull the connection (`db` at parse +0x00). Skip the check
//! entirely — return `SQLITE_OK` — when the schema is being initialised
//! (`db->init.busy`, byte at db +0x80), when the parser is declaring a
//! vtab (`pParse->declareVtab`, byte at parse +0x198), or when no
//! authorizer is installed (`db->xAuth`, word at db +0xe0). Otherwise
//! invoke the authorizer as
//! `xAuth(pAuthArg, code, zArg1, zArg2, zArg3, pParse->zAuthContext)`
//! (pAuthArg at db +0xe4, zAuthContext at parse +0x18c) and map its
//! verdict: `SQLITE_DENY` reports "not authorized" through
//! `sqlite3ErrorMsg` and latches `pParse->rc = SQLITE_AUTH`; any value
//! other than `SQLITE_OK`/`SQLITE_IGNORE`/`SQLITE_DENY` is an authorizer
//! protocol violation — `sqliteAuthBadReturnCode` @ 0x083918f4 is
//! invoked with `SQLITE_DENY` and `SQLITE_DENY` is returned. `SQLITE_OK`
//! and `SQLITE_IGNORE` pass through untouched.
//!
//! Field map pinned by the original's load/store sequence and
//! cross-checked against the SQLite 3.5.9 sources:
//!
//! ```text
//! db (sqlite3):            parse (Parse):
//!   +0x80 init.busy  (u8)    +0x00 db             (*mut Db)
//!   +0xe0 xAuth      (fn)    +0x04 rc             (i32)
//!   +0xe4 pAuthArg   (ptr)   +0x18c zAuthContext  (*const u8)
//!                            +0x198 declareVtab   (u8)
//! ```
//!
//! Verdict constants: `SQLITE_OK` = 0, `SQLITE_DENY` = 1,
//! `SQLITE_IGNORE` = 2, `SQLITE_AUTH` = 23 (0x17, the `mov r0, #23`
//! stored to parse +0x04 in the deny branch). Note `SQLITE_DENY` and
//! `SQLITE_ERROR` share the value 1 — the bad-return branch relies on
//! it, passing the already-latched `SQLITE_DENY` straight through as the
//! report's offending-code argument.
//!
//! Deviations:
//! - `sqlite3ErrorMsg` @ 0x083767a0 *is* ported
//!   (`sqlite::error_msg::sqlite_error_msg`) and is called directly, per
//!   the porting rules. The original passes no variadic arguments with
//!   "not authorized" (its r2/r3 are dead at the `bl`); the port hands
//!   over a NULL `VaList`, which the formatter never reads for a
//!   conversion-free format.
//! - `sqliteAuthBadReturnCode` @ 0x083918f4 (32 bytes; its only call
//!   site is this function's predicated `blne`) is not ported. It is
//!   the [`SQLITE_AUTH_BAD_RETURN_CODE`] dispatch boundary (house
//!   pattern, see `sqlite/error_msg.rs`). The default slot latches
//!   `parse->rc = SQLITE_ERROR` — the original's unconditional final
//!   store — and skips the report itself (see
//!   [`unported_auth_bad_return_code`]).
//! - `Parse`/`Db` are typed `#[repr(C)]` structs rather than raw byte
//!   offsets, so the pointer fields stay disjoint on a 64-bit test
//!   host. The original byte offsets are statically asserted on 32-bit
//!   targets (`_DB_*_OFFSET` / `_PARSE_*_OFFSET`).

use crate::sqlite::error_msg::{sqlite_error_msg, SQLITE_OK};

/// Authorizer verdict "allow the action" (original: `cmp r0, #0` —
/// re-exported from `sqlite::error_msg`).
pub const SQLITE_DENY: i32 = 1;
/// Authorizer verdict "skip the action silently" (original:
/// `cmpne r4, #2`).
pub const SQLITE_IGNORE: i32 = 2;
/// Statement result code "authorization denied" (original:
/// `mov r0, #23; str r0, [r5, #4]`).
pub const SQLITE_AUTH: i32 = 23;

/// The authorizer callback (`sqlite3.xAuth`): six arguments, the last
/// being the innermost trigger/view name the check runs under.
pub type XAuthFn = unsafe extern "C" fn(
    p_auth_arg: *mut u8,
    code: i32,
    z_arg1: *const u8,
    z_arg2: *const u8,
    z_arg3: *const u8,
    z_auth_context: *const u8,
) -> i32;

/// A database connection (`sqlite3`), only the fields this gate
/// touches. See the module header for the original byte offsets.
#[repr(C)]
pub struct Db {
    /// +0x00..+0x80: unmodeled.
    pub _gap_00: [u8; 0x80],
    /// +0x80: `db->init.busy` — schema initialisation in progress.
    pub init_busy: u8,
    /// +0x81..+0xe0: unmodeled.
    pub _gap_81: [u8; 0xe0 - 0x81],
    /// +0xe0: the installed authorizer, NULL when none.
    pub x_auth: Option<XAuthFn>,
    /// +0xe4: opaque first argument handed to `x_auth` (`pAuthArg`).
    pub p_auth_arg: *mut u8,
}

/// A parse context (`sqlite3Parse`), only the fields this gate touches.
/// Distinct from `sqlite::error_msg::Parse` (a shorter view over the
/// same object); the deny branch casts between the two.
#[repr(C)]
pub struct Parse {
    /// +0x00: the owning connection.
    pub db: *mut Db,
    /// +0x04: statement result code (SQLITE_*).
    pub rc: i32,
    /// +0x08..+0x18c: unmodeled.
    pub _gap_08: [u8; 0x18c - 0x08],
    /// +0x18c: `pParse->zAuthContext` — name of the innermost trigger
    /// or view being compiled, handed to the authorizer.
    pub z_auth_context: *const u8,
    /// +0x190..+0x198: unmodeled.
    pub _gap_190: [u8; 0x198 - 0x190],
    /// +0x198: `pParse->declareVtab` (the IN_DECLARE_VTAB test).
    pub declare_vtab: u8,
}

// The original's byte offsets, asserted on the 32-bit target. On a
// 64-bit host the pointer fields widen and these shift — harmless,
// because all access goes through the typed structs.
#[cfg(target_pointer_width = "32")]
const _DB_INIT_BUSY_OFFSET: [u8; 0x80] = [0; core::mem::offset_of!(Db, init_busy)];
#[cfg(target_pointer_width = "32")]
const _DB_X_AUTH_OFFSET: [u8; 0xe0] = [0; core::mem::offset_of!(Db, x_auth)];
#[cfg(target_pointer_width = "32")]
const _DB_P_AUTH_ARG_OFFSET: [u8; 0xe4] = [0; core::mem::offset_of!(Db, p_auth_arg)];
#[cfg(target_pointer_width = "32")]
const _PARSE_DB_OFFSET: [u8; 0x00] = [0; core::mem::offset_of!(Parse, db)];
#[cfg(target_pointer_width = "32")]
const _PARSE_RC_OFFSET: [u8; 0x04] = [0; core::mem::offset_of!(Parse, rc)];
#[cfg(target_pointer_width = "32")]
const _PARSE_Z_AUTH_CONTEXT_OFFSET: [u8; 0x18c] =
    [0; core::mem::offset_of!(Parse, z_auth_context)];
#[cfg(target_pointer_width = "32")]
const _PARSE_DECLARE_VTAB_OFFSET: [u8; 0x198] =
    [0; core::mem::offset_of!(Parse, declare_vtab)];

/// `sqliteAuthBadReturnCode(parse, rc)` @ 0x083918f4: report an
/// authorizer protocol violation and latch `parse->rc = SQLITE_ERROR`.
pub type AuthBadReturnCodeFn = unsafe extern "C" fn(parse: *mut Parse, rc: i32);

/// Default stub: latch `SQLITE_ERROR` — the original's unconditional
/// final store — and skip the report. The report's format pointer
/// (0x088fd968 in the original's literal pool) is one of the skewed
/// rodata pointers documented in `sqlite/mod.rs`: its datum lives at
/// image address +0xaed8, i.e. 0x08908840 — the upstream 3.5.9 string
/// "illegal return value (%d) from the authorization function - should
/// be SQLITE_OK, SQLITE_IGNORE, or SQLITE_DENY", confirming the
/// identity. Until 0x083918f4 is ported the stub preserves the
/// observable result-code state and nothing else (the original also
/// bumps `n_err` inside `sqlite3ErrorMsg`; the stub does not).
pub(crate) unsafe extern "C" fn unported_auth_bad_return_code(parse: *mut Parse, _rc: i32) {
    (*parse).rc = crate::sqlite::error_msg::SQLITE_ERROR;
}

/// The active bad-return reporter. Host tests install recording mocks;
/// the real port replaces the default when 0x083918f4 lands.
pub static mut SQLITE_AUTH_BAD_RETURN_CODE: AuthBadReturnCodeFn =
    unported_auth_bad_return_code;

/// Reads the reporter slot (volatile — the slot is meant to be swapped
/// at runtime, and a plain read lets LLVM const-fold the default away).
#[inline(always)]
pub(crate) fn auth_bad_return_code_op() -> AuthBadReturnCodeFn {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(SQLITE_AUTH_BAD_RETURN_CODE)) }
}

/// sqlite_auth_check — original: `FUN_0836f91c` @ 0x0836f91c (156
/// bytes; 28 `bl` call sites).
///
/// `sqlite3AuthCheck`: run the installed authorizer for one action.
/// Returns the authorizer's verdict (`SQLITE_OK` / `SQLITE_IGNORE` /
/// `SQLITE_DENY`); see the module header for the skip conditions and
/// the verdict mapping.
///
/// Register usage: r0 = parse, r1 = code, r2 = z_arg1, r3 = z_arg2,
/// [sp] = z_arg3 (the original forwards it to the authorizer together
/// with `z_auth_context` via `strd r2, [sp]`).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn sqlite_auth_check(
    parse: *mut Parse,
    code: i32,
    z_arg1: *const u8,
    z_arg2: *const u8,
    z_arg3: *const u8,
) -> i32 {
    let parse = &mut *parse;
    let db = &*parse.db;
    if db.init_busy != 0 || parse.declare_vtab != 0 {
        return SQLITE_OK;
    }
    let Some(x_auth) = db.x_auth else {
        return SQLITE_OK;
    };
    let rc = x_auth(
        db.p_auth_arg,
        code,
        z_arg1,
        z_arg2,
        z_arg3,
        parse.z_auth_context,
    );
    if rc == SQLITE_DENY {
        sqlite_error_msg(
            parse as *mut Parse as *mut crate::sqlite::error_msg::Parse,
            b"not authorized\0".as_ptr(),
            core::ptr::null(),
        );
        parse.rc = SQLITE_AUTH;
    } else if rc != SQLITE_OK && rc != SQLITE_IGNORE {
        (auth_bad_return_code_op())(parse, SQLITE_DENY);
        return SQLITE_DENY;
    }
    rc
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::sqlite::error_msg;
    use parking_lot::{Mutex, MutexGuard};

    /// Serializes the tests: the seams are process-global.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    /// Arguments of the last recording authorizer invocation.
    static mut RECORDED: Option<(
        *mut u8,
        i32,
        *const u8,
        *const u8,
        *const u8,
        *const u8,
    )> = None;
    /// Verdict the recording authorizer hands back.
    static mut NEXT_VERDICT: i32 = 0;
    /// (parse, rc) of the last bad-return reporter invocation.
    static mut BAD_RETURN: Option<(*mut Parse, i32)> = None;

    unsafe extern "C" fn recording_x_auth(
        p_auth_arg: *mut u8,
        code: i32,
        z_arg1: *const u8,
        z_arg2: *const u8,
        z_arg3: *const u8,
        z_auth_context: *const u8,
    ) -> i32 {
        RECORDED = Some((p_auth_arg, code, z_arg1, z_arg2, z_arg3, z_auth_context));
        NEXT_VERDICT
    }

    unsafe extern "C" fn recording_bad_return_code(parse: *mut Parse, rc: i32) {
        BAD_RETURN = Some((parse, rc));
    }

    /// A zeroed connection/parse pair with the gate fields set as
    /// given. Zeroed gaps keep the error_msg view's `z_err_msg` NULL,
    /// so the real `sqlite_error_msg` runs cleanly. `parse.db` is left
    /// NULL on purpose: wiring it to `db` inside here would dangle the
    /// moment the pair moves into the caller's frame — every test
    /// re-points it after destructuring.
    fn fixtures(init_busy: u8, declare_vtab: u8, x_auth: Option<XAuthFn>) -> (Db, Parse) {
        let db = Db {
            _gap_00: [0; 0x80],
            init_busy,
            _gap_81: [0; 0xe0 - 0x81],
            x_auth,
            p_auth_arg: core::ptr::null_mut(),
        };
        let parse = Parse {
            db: core::ptr::null_mut(),
            rc: 0,
            _gap_08: [0; 0x18c - 0x08],
            z_auth_context: core::ptr::null(),
            _gap_190: [0; 0x198 - 0x190],
            declare_vtab,
        };
        (db, parse)
    }

    fn lock() -> MutexGuard<'static, ()> {
        let guard = TEST_LOCK.lock();
        unsafe {
            RECORDED = None;
            NEXT_VERDICT = 0;
            BAD_RETURN = None;
        }
        guard
    }

    /// n_err as `sqlite::error_msg::Parse` sees it (+0x40), for
    /// asserting that the deny branch really ran the reporter.
    unsafe fn n_err(parse: *const Parse) -> i32 {
        (*(parse as *const error_msg::Parse)).n_err
    }

    #[test]
    fn init_busy_skips_authorizer() {
        let _guard = lock();
        let (mut db, mut parse) = fixtures(1, 0, Some(recording_x_auth));
        parse.db = &mut db;
        unsafe {
            NEXT_VERDICT = SQLITE_DENY;
            let rc = sqlite_auth_check(
                &mut parse,
                0x1f,
                b"fn\0".as_ptr(),
                core::ptr::null(),
                core::ptr::null(),
            );
            assert_eq!(rc, SQLITE_OK);
            assert!(RECORDED.is_none());
            assert_eq!(parse.rc, 0);
        }
    }

    #[test]
    fn declare_vtab_skips_authorizer() {
        let _guard = lock();
        let (mut db, mut parse) = fixtures(0, 1, Some(recording_x_auth));
        parse.db = &mut db;
        unsafe {
            NEXT_VERDICT = SQLITE_DENY;
            let rc = sqlite_auth_check(
                &mut parse,
                0x15,
                core::ptr::null(),
                core::ptr::null(),
                core::ptr::null(),
            );
            assert_eq!(rc, SQLITE_OK);
            assert!(RECORDED.is_none());
        }
    }

    #[test]
    fn missing_authorizer_returns_ok() {
        let _guard = lock();
        let (mut db, mut parse) = fixtures(0, 0, None);
        parse.db = &mut db;
        unsafe {
            let rc = sqlite_auth_check(
                &mut parse,
                0x15,
                core::ptr::null(),
                core::ptr::null(),
                core::ptr::null(),
            );
            assert_eq!(rc, SQLITE_OK);
            assert_eq!(parse.rc, 0);
        }
    }

    #[test]
    fn ok_verdict_passes_args_through() {
        let _guard = lock();
        let (mut db, mut parse) = fixtures(0, 0, Some(recording_x_auth));
        parse.db = &mut db;
        let auth_arg = 0x11223344usize as *mut u8;
        let context = b"trigger\0".as_ptr();
        db.p_auth_arg = auth_arg;
        parse.z_auth_context = context;
        unsafe {
            NEXT_VERDICT = SQLITE_OK;
            let arg1 = b"column\0".as_ptr();
            let arg2 = b"table\0".as_ptr();
            let rc = sqlite_auth_check(&mut parse, 0x1f, arg1, arg2, core::ptr::null());
            assert_eq!(rc, SQLITE_OK);
            let got = RECORDED.expect("authorizer must run");
            assert_eq!(got.0, auth_arg);
            assert_eq!(got.1, 0x1f);
            assert_eq!(got.2, arg1);
            assert_eq!(got.3, arg2);
            assert_eq!(got.4, core::ptr::null());
            assert_eq!(got.5, context);
            assert_eq!(parse.rc, 0);
            assert_eq!(n_err(&parse), 0);
        }
    }

    #[test]
    fn ignore_verdict_passes_through() {
        let _guard = lock();
        let (mut db, mut parse) = fixtures(0, 0, Some(recording_x_auth));
        parse.db = &mut db;
        unsafe {
            NEXT_VERDICT = SQLITE_IGNORE;
            let rc = sqlite_auth_check(
                &mut parse,
                0x15,
                core::ptr::null(),
                core::ptr::null(),
                core::ptr::null(),
            );
            assert_eq!(rc, SQLITE_IGNORE);
            assert_eq!(parse.rc, 0);
            assert_eq!(n_err(&parse), 0);
        }
    }

    #[test]
    fn deny_reports_not_authorized() {
        let _guard = lock();
        let (mut db, mut parse) = fixtures(0, 0, Some(recording_x_auth));
        parse.db = &mut db;
        unsafe {
            NEXT_VERDICT = SQLITE_DENY;
            let rc = sqlite_auth_check(
                &mut parse,
                0x15,
                core::ptr::null(),
                core::ptr::null(),
                core::ptr::null(),
            );
            assert_eq!(rc, SQLITE_DENY);
            // The reporter ran (n_err bumped) and SQLITE_AUTH latched.
            assert_eq!(n_err(&parse), 1);
            assert_eq!(parse.rc, SQLITE_AUTH);
        }
    }

    #[test]
    fn deny_overwrites_latched_rc() {
        let _guard = lock();
        let (mut db, mut parse) = fixtures(0, 0, Some(recording_x_auth));
        parse.db = &mut db;
        parse.rc = 5;
        unsafe {
            NEXT_VERDICT = SQLITE_DENY;
            let rc = sqlite_auth_check(
                &mut parse,
                0x15,
                core::ptr::null(),
                core::ptr::null(),
                core::ptr::null(),
            );
            assert_eq!(rc, SQLITE_DENY);
            // The original's `mov r0, #23; str` is unconditional.
            assert_eq!(parse.rc, SQLITE_AUTH);
        }
    }

    #[test]
    fn bad_verdict_latches_error_via_default_stub() {
        let _guard = lock();
        let (mut db, mut parse) = fixtures(0, 0, Some(recording_x_auth));
        parse.db = &mut db;
        unsafe {
            NEXT_VERDICT = 7;
            let rc = sqlite_auth_check(
                &mut parse,
                0x15,
                core::ptr::null(),
                core::ptr::null(),
                core::ptr::null(),
            );
            assert_eq!(rc, SQLITE_DENY);
            assert_eq!(parse.rc, error_msg::SQLITE_ERROR);
        }
    }

    #[test]
    fn negative_verdict_is_a_bad_return() {
        let _guard = lock();
        let (mut db, mut parse) = fixtures(0, 0, Some(recording_x_auth));
        parse.db = &mut db;
        unsafe {
            NEXT_VERDICT = -1;
            let rc = sqlite_auth_check(
                &mut parse,
                0x15,
                core::ptr::null(),
                core::ptr::null(),
                core::ptr::null(),
            );
            assert_eq!(rc, SQLITE_DENY);
            assert_eq!(parse.rc, error_msg::SQLITE_ERROR);
        }
    }

    #[test]
    fn bad_verdict_reaches_installed_reporter() {
        let _guard = lock();
        let (mut db, mut parse) = fixtures(0, 0, Some(recording_x_auth));
        parse.db = &mut db;
        unsafe {
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(SQLITE_AUTH_BAD_RETURN_CODE),
                recording_bad_return_code,
            );
            NEXT_VERDICT = 42;
            let parse_ptr = &mut parse as *mut Parse;
            let rc = sqlite_auth_check(
                parse_ptr,
                0x15,
                core::ptr::null(),
                core::ptr::null(),
                core::ptr::null(),
            );
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(SQLITE_AUTH_BAD_RETURN_CODE),
                unported_auth_bad_return_code,
            );
            assert_eq!(rc, SQLITE_DENY);
            // The reporter sees the already-latched SQLITE_DENY as its
            // offending-code argument (SQLITE_DENY == SQLITE_ERROR == 1).
            assert_eq!(BAD_RETURN, Some((parse_ptr, SQLITE_DENY)));
            // The recording mock does not latch rc itself.
            assert_eq!(parse.rc, 0);
        }
    }
}
