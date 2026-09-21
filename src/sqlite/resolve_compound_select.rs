//! Resolving the three expressions of a compound SELECT.
//!
//! - `sqlite_resolve_compound_select_expr` — original: `FUN_08367fb8` @
//!   0x08367fb8 (104 executable bytes, 0x08367fb8..0x08368020; the next
//!   independent function prologue is at 0x08368038). Raw ARM has three
//!   unconditional direct `bl` instructions and no predicated calls.
//!
//! Algorithm: ignore a NULL expression; turn the parser's TK_JOIN_KW
//! placeholder (0x17) into TK_ID (0x58); otherwise resolve names, reject a
//! non-constant expression, and report `invalid name: \"%T\"` using the
//! token stored at expression offset 0x1c. It returns the resolver/checker
//! result, or one after reporting the diagnostic.
//!
//! Deliberate deviation: `sqlite_resolve_expr_names` @ 0x083787a8 and
//! `sqlite_expr_is_constant` @ 0x083784bc remain stock target calls. Both
//! need stack-dependent walker callbacks with no callable Rust identity;
//! host tests dispatch them through `RESOLVE_COMPOUND_SELECT_OPS`.

use super::error_msg::{sqlite_error_msg, Parse, VaList};

const TK_JOIN_KW: u8 = 0x17;
const TK_ID: u8 = 0x58;
const TOKEN_OFFSET: usize = 0x1c;
const INVALID_NAME: &[u8] = b"invalid name: \"%T\"\0";

type ResolveExprNamesFn = unsafe extern "C" fn(*mut *mut Parse, *mut u8) -> i32;
type ExprIsConstantFn = unsafe extern "C" fn(*mut u8) -> i32;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn resolve_expr_names(context: *mut *mut Parse, expr: *mut u8) -> i32 {
    let resolve: ResolveExprNamesFn = core::mem::transmute(0x0837_87a8usize);
    resolve(context, expr)
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn expr_is_constant(expr: *mut u8) -> i32 {
    let is_constant: ExprIsConstantFn = core::mem::transmute(0x0837_84bcusize);
    is_constant(expr)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_resolve_expr_names(_context: *mut *mut Parse, _expr: *mut u8) -> i32 { 0 }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_expr_is_constant(_expr: *mut u8) -> i32 { 0 }

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
struct ResolveCompoundSelectOps {
    resolve_expr_names: ResolveExprNamesFn,
    expr_is_constant: ExprIsConstantFn,
}

#[cfg(not(target_os = "none"))]
const DEFAULT_RESOLVE_COMPOUND_SELECT_OPS: ResolveCompoundSelectOps = ResolveCompoundSelectOps {
    resolve_expr_names: missing_resolve_expr_names,
    expr_is_constant: missing_expr_is_constant,
};

#[cfg(not(target_os = "none"))]
static mut RESOLVE_COMPOUND_SELECT_OPS: ResolveCompoundSelectOps = DEFAULT_RESOLVE_COMPOUND_SELECT_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn resolve_expr_names(context: *mut *mut Parse, expr: *mut u8) -> i32 {
    (core::ptr::read_volatile(core::ptr::addr_of!(RESOLVE_COMPOUND_SELECT_OPS)).resolve_expr_names)(context, expr)
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn expr_is_constant(expr: *mut u8) -> i32 {
    (core::ptr::read_volatile(core::ptr::addr_of!(RESOLVE_COMPOUND_SELECT_OPS)).expr_is_constant)(expr)
}

/// `sqlite3ResolveOrderGroupBy` expression arm — original: `FUN_08367fb8` @
/// 0x08367fb8 (104 executable bytes; 3 unconditional direct `bl` calls).
///
/// Resolves a compound SELECT expression. A parser placeholder is rewritten
/// in place; every other non-NULL expression must resolve and be constant,
/// or the parser receives the original `invalid name: \"%T\"` diagnostic.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn sqlite_resolve_compound_select_expr(
    context: *mut *mut Parse,
    expr: *mut u8,
) -> i32 {
    if expr.is_null() {
        return 0;
    }
    if expr.read() == TK_JOIN_KW {
        expr.write(TK_ID);
        return 0;
    }
    let result = resolve_expr_names(context, expr);
    if result != 0 {
        return result;
    }
    let result = expr_is_constant(expr);
    if result != 0 {
        return result;
    }
    sqlite_error_msg(*context, INVALID_NAME.as_ptr(), expr.add(TOKEN_OFFSET).cast::<u32>() as VaList);
    1
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut RESOLVE_RESULT: i32 = 0;
    static mut CONSTANT_RESULT: i32 = 0;
    static mut RESOLVE_CALLS: usize = 0;
    static mut CONSTANT_CALLS: usize = 0;

    unsafe extern "C" fn resolve(_context: *mut *mut Parse, _expr: *mut u8) -> i32 {
        RESOLVE_CALLS += 1;
        RESOLVE_RESULT
    }
    unsafe extern "C" fn constant(_expr: *mut u8) -> i32 {
        CONSTANT_CALLS += 1;
        CONSTANT_RESULT
    }

    struct Bench { _guard: MutexGuard<'static, ()> }
    impl Drop for Bench {
        fn drop(&mut self) {
            unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!(RESOLVE_COMPOUND_SELECT_OPS), DEFAULT_RESOLVE_COMPOUND_SELECT_OPS); }
        }
    }
    fn bench(resolve_result: i32, constant_result: i32) -> Bench {
        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            RESOLVE_RESULT = resolve_result;
            CONSTANT_RESULT = constant_result;
            RESOLVE_CALLS = 0;
            CONSTANT_CALLS = 0;
            core::ptr::write_volatile(core::ptr::addr_of_mut!(RESOLVE_COMPOUND_SELECT_OPS), ResolveCompoundSelectOps { resolve_expr_names: resolve, expr_is_constant: constant });
        }
        Bench { _guard: guard }
    }

    #[repr(align(4))]
    struct ExprBytes([u8; 0x44]);
    fn parse() -> Parse {
        Parse { db: core::ptr::null_mut(), rc: 0, z_err_msg: core::ptr::null_mut(), _gap_0c: [0; 6], check_schema: 0, _gap_13: [0; 45], n_err: 0 }
    }

    #[test]
    fn null_and_join_keyword_skip_the_callees() {
        let _bench = bench(0, 0);
        let mut parse = parse();
        let mut context: *mut Parse = &mut parse;
        unsafe { assert_eq!(sqlite_resolve_compound_select_expr(&mut context as *mut *mut Parse, core::ptr::null_mut()), 0); }
        let mut expr = ExprBytes([0; 0x44]);
        expr.0[0] = TK_JOIN_KW;
        unsafe { assert_eq!(sqlite_resolve_compound_select_expr(&mut context as *mut *mut Parse, expr.0.as_mut_ptr()), 0); }
        assert_eq!(expr.0[0], TK_ID);
        unsafe { assert_eq!((RESOLVE_CALLS, CONSTANT_CALLS), (0, 0)); }
    }

    #[test]
    fn resolver_and_constant_failures_propagate_without_reporting() {
        let mut expr = ExprBytes([0; 0x44]);
        let mut parse = parse();
        let mut context: *mut Parse = &mut parse;
        let _bench = bench(7, 0);
        unsafe { assert_eq!(sqlite_resolve_compound_select_expr(&mut context as *mut *mut Parse, expr.0.as_mut_ptr()), 7); }
        assert_eq!(parse.n_err, 0);
        unsafe { assert_eq!((RESOLVE_CALLS, CONSTANT_CALLS), (1, 0)); }
        drop(_bench);
        let _bench = bench(0, 9);
        unsafe { assert_eq!(sqlite_resolve_compound_select_expr(&mut context as *mut *mut Parse, expr.0.as_mut_ptr()), 9); }
        assert_eq!(parse.n_err, 0);
        unsafe { assert_eq!((RESOLVE_CALLS, CONSTANT_CALLS), (1, 1)); }
    }

    #[test]
    fn resolved_constant_reports_the_token_error() {
        let _bench = bench(0, 0);
        let mut expr = ExprBytes([0; 0x44]);
        let mut parse = parse();
        let mut context: *mut Parse = &mut parse;
        unsafe { assert_eq!(sqlite_resolve_compound_select_expr(&mut context as *mut *mut Parse, expr.0.as_mut_ptr()), 1); }
        assert_eq!((parse.n_err, parse.rc), (1, 1));
        unsafe { assert_eq!((RESOLVE_CALLS, CONSTANT_CALLS), (1, 1)); }
    }
}
