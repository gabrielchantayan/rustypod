//! Resolve an expression's effective SQLite collation descriptor.
//!
//! - `expr_coll_seq` — original: `FUN_08377bf0` @ `0x08377bf0` (148 bytes;
//!   6 `bl` call sites, binary-scanned — all unconditional).
//!
//! Raw `osos.dec` establishes the exact code extent as
//! `0x08377bf0..0x08377c84`: the return is `pop {r4,r5,r6,pc}` at
//! `0x08377c80`, immediately followed by the error-format string. The body
//! walks `Expr::left` through transparent `TK_CAST` (31) and `TK_UPLUS`
//! (86) nodes when they do not already carry a collation. The first remaining
//! node with a collation is checked through `sqlite3GetCollSeq`; a successful
//! check returns that original descriptor. A failed check reports the missing
//! name only when `Parse::n_err` was zero, then increments `n_err` once more.
//!
//! Deliberate deviation: `sqlite3GetCollSeq` @ `0x0837a17c` is not ported.
//! Its observed `(db, coll, coll->name, -1) -> coll-or-NULL` contract is kept
//! as a volatile dispatch seam; target builds call the exact retail address
//! and host tests install a recorder. `sqlite_error_msg` @ `0x083767a0` is
//! already ported and is called directly.

use core::ptr;

use super::error_msg::{sqlite_error_msg, Parse, VaList};
use super::expr_affinity::Expr;

const TK_CAST: u8 = 31;
const TK_UPLUS: u8 = b'V';
const NO_SUCH_COLLATION_SEQUENCE: &[u8] = b"no such collation sequence: %s\0";

/// The prefix of SQLite's `CollSeq`; this port only reads its NUL-terminated
/// name at +0x00.
#[repr(C)]
pub struct CollSeq {
    pub name: *const u8,
}

/// RetailOS load address of the unresolved `sqlite3GetCollSeq` helper.
pub const GET_COLL_SEQ_ADDRESS: usize = 0x0837_a17c;

/// Observed ABI of `sqlite3GetCollSeq(db, coll, coll->name, -1)`.
pub type GetCollSeq = unsafe extern "C" fn(
    db: *mut u8,
    coll: *mut CollSeq,
    name: *const u8,
    name_len: i32,
) -> *mut CollSeq;

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_get_coll_seq(
    db: *mut u8,
    coll: *mut CollSeq,
    name: *const u8,
    name_len: i32,
) -> *mut CollSeq {
    let get: GetCollSeq = core::mem::transmute(GET_COLL_SEQ_ADDRESS);
    get(db, coll, name, name_len)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_get_coll_seq(
    _db: *mut u8,
    _coll: *mut CollSeq,
    _name: *const u8,
    _name_len: i32,
) -> *mut CollSeq {
    panic!("expr_coll_seq requires retail helper @ 0x0837a17c")
}

/// Replaceable unported-helper dispatch.
#[derive(Clone, Copy)]
pub struct ExprCollSeqHooks {
    pub get_coll_seq: GetCollSeq,
}

#[cfg(target_os = "none")]
pub const DEFAULT_EXPR_COLL_SEQ_HOOKS: ExprCollSeqHooks = ExprCollSeqHooks {
    get_coll_seq: retail_get_coll_seq,
};

#[cfg(not(target_os = "none"))]
pub const DEFAULT_EXPR_COLL_SEQ_HOOKS: ExprCollSeqHooks = ExprCollSeqHooks {
    get_coll_seq: missing_get_coll_seq,
};

/// The target helper operation. A volatile load preserves the real target
/// call rather than allowing LLVM to fold the default dispatch away.
pub static mut EXPR_COLL_SEQ_HOOKS: ExprCollSeqHooks = DEFAULT_EXPR_COLL_SEQ_HOOKS;

#[inline(always)]
unsafe fn get_coll_seq_op() -> GetCollSeq {
    ptr::read_volatile(ptr::addr_of!(EXPR_COLL_SEQ_HOOKS.get_coll_seq))
}

/// `sqlite3ExprCollSeq`: resolve the collation of `expr` for `parse`.
///
/// # Safety
/// `parse` must be a valid [`Parse`]. Every non-NULL expression reached
/// through `left` must be a valid [`Expr`], and every non-NULL
/// `collating_sequence` must point to a valid [`CollSeq`] whose `name` is
/// suitable for the stock helper. On target, `0x0837a17c` must be callable.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn expr_coll_seq(parse: *mut Parse, mut expr: *mut Expr) -> *mut CollSeq {
    let mut coll = ptr::null_mut::<CollSeq>();

    while !expr.is_null() {
        coll = (*expr).collating_sequence.cast();
        if (*expr).op != TK_CAST && (*expr).op != TK_UPLUS {
            break;
        }
        if !coll.is_null() {
            break;
        }
        expr = (*expr).left;
    }

    if coll.is_null() {
        return ptr::null_mut();
    }

    let name = (*coll).name;
    if !(get_coll_seq_op())((*parse).db, coll, name, -1).is_null() {
        return coll;
    }

    if (*parse).n_err == 0 {
        let args = [name as usize as u32];
        sqlite_error_msg(parse, NO_SUCH_COLLATION_SEQUENCE.as_ptr(), args.as_ptr() as VaList);
    }
    (*parse).n_err = (*parse).n_err.wrapping_add(1);
    ptr::null_mut()
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::Mutex;
    use std::vec;
    use std::vec::Vec;

    static HOOK_LOCK: Mutex<()> = Mutex::new(());
    static mut GET_RESULT: *mut CollSeq = ptr::null_mut();
    static mut GET_CALLS: Vec<(*mut u8, *mut CollSeq, *const u8, i32)> = Vec::new();

    unsafe extern "C" fn recording_get_coll_seq(
        db: *mut u8,
        coll: *mut CollSeq,
        name: *const u8,
        name_len: i32,
    ) -> *mut CollSeq {
        (*ptr::addr_of_mut!(GET_CALLS)).push((db, coll, name, name_len));
        *ptr::addr_of!(GET_RESULT)
    }

    struct HookGuard;
    impl Drop for HookGuard {
        fn drop(&mut self) {
            unsafe { EXPR_COLL_SEQ_HOOKS = DEFAULT_EXPR_COLL_SEQ_HOOKS; }
        }
    }

    fn install_recorder(result: *mut CollSeq) -> HookGuard {
        unsafe {
            GET_RESULT = result;
            (*ptr::addr_of_mut!(GET_CALLS)).clear();
            EXPR_COLL_SEQ_HOOKS = ExprCollSeqHooks { get_coll_seq: recording_get_coll_seq };
        }
        HookGuard
    }

    fn parse(db: *mut u8, n_err: i32) -> Parse {
        Parse {
            db,
            rc: 0,
            z_err_msg: ptr::null_mut(),
            _gap_0c: [0; 0x12 - 0x0c],
            check_schema: 0,
            _gap_13: [0; 0x40 - 0x13],
            n_err,
        }
    }

    fn expr(op: u8, coll: *mut CollSeq, left: *mut Expr) -> Expr {
        unsafe {
            let mut expr: Expr = core::mem::zeroed();
            expr.op = op;
            expr.collating_sequence = coll.cast();
            expr.left = left;
            expr
        }
    }

    #[test]
    fn null_expression_does_not_call_lookup() {
        let _lock = HOOK_LOCK.lock();
        let _hooks = install_recorder(ptr::null_mut());
        let mut parse = parse(0x1000usize as *mut u8, 0);

        assert!(unsafe { expr_coll_seq(&mut parse, ptr::null_mut()) }.is_null());
        unsafe { assert!(GET_CALLS.is_empty()); }
        assert_eq!(parse.n_err, 0);
    }

    #[test]
    fn transparent_nodes_walk_left_and_return_original_collation() {
        let _lock = HOOK_LOCK.lock();
        let name = b"NOCASE\0";
        let mut coll = CollSeq { name: name.as_ptr() };
        let mut leaf = expr(0x55, &mut coll, ptr::null_mut());
        let mut cast = expr(TK_CAST, ptr::null_mut(), &mut leaf);
        let mut unary_plus = expr(TK_UPLUS, ptr::null_mut(), &mut cast);
        let mut parse = parse(0xfeedusize as *mut u8, 4);
        let _hooks = install_recorder(&mut coll);

        let found = unsafe { expr_coll_seq(&mut parse, &mut unary_plus) };
        assert_eq!(found.cast::<u8>(), (&mut coll as *mut CollSeq).cast::<u8>());
        unsafe {
            assert_eq!(GET_CALLS, vec![(parse.db, &mut coll as *mut CollSeq, name.as_ptr(), -1)]);
        }
        assert_eq!(parse.n_err, 4);
    }

    #[test]
    fn ordinary_uncollated_node_does_not_walk_left() {
        let _lock = HOOK_LOCK.lock();
        let name = b"BINARY\0";
        let mut coll = CollSeq { name: name.as_ptr() };
        let mut leaf = expr(0x55, &mut coll, ptr::null_mut());
        let mut root = expr(0x44, ptr::null_mut(), &mut leaf);
        let mut parse = parse(ptr::null_mut(), 0);
        let _hooks = install_recorder(&mut coll);

        assert!(unsafe { expr_coll_seq(&mut parse, &mut root) }.is_null());
        unsafe { assert!(GET_CALLS.is_empty()); }
    }

    #[test]
    fn failed_lookup_with_existing_error_only_increments_once() {
        let _lock = HOOK_LOCK.lock();
        let name = b"missing\0";
        let mut coll = CollSeq { name: name.as_ptr() };
        let mut root = expr(0x55, &mut coll, ptr::null_mut());
        let mut parse = parse(0x2000usize as *mut u8, 7);
        let _hooks = install_recorder(ptr::null_mut());

        assert!(unsafe { expr_coll_seq(&mut parse, &mut root) }.is_null());
        assert_eq!(parse.n_err, 8);
        unsafe { assert_eq!(GET_CALLS, vec![(parse.db, &mut coll as *mut CollSeq, name.as_ptr(), -1)]); }
    }

    #[test]
    fn first_failed_lookup_reports_then_increments_error_twice() {
        let _lock = HOOK_LOCK.lock();
        let name = b"missing\0";
        let mut coll = CollSeq { name: name.as_ptr() };
        let mut root = expr(0x55, &mut coll, ptr::null_mut());
        let mut parse = parse(0x3000usize as *mut u8, 0);
        let _hooks = install_recorder(ptr::null_mut());

        assert!(unsafe { expr_coll_seq(&mut parse, &mut root) }.is_null());
        assert_eq!(parse.n_err, 2, "sqlite_error_msg increments before the wrapper's tail");
        assert_eq!(parse.rc, crate::sqlite::error_msg::SQLITE_ERROR);
        assert!(parse.z_err_msg.is_null(), "the default formatter models allocation failure");
        unsafe { assert_eq!(GET_CALLS, vec![(parse.db, &mut coll as *mut CollSeq, name.as_ptr(), -1)]); }
    }
    }
