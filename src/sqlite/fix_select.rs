//! SQLite select-statement reference validation.
//!
//! - `sqlite_fix_select` — original: `FUN_08379694` @ `0x08379694` (124
//!   bytes, `0x08379694..0x08379710`; the independently linked
//!   `sqlite3FixSrcList` prologue begins at `0x08379710`). Decoding every
//!   aligned ARM `B`/`BL` immediate in `osos.dec` finds four direct inbound
//!   `bl` calls, all unconditional: `0x0837483c`
//!   (`sqlite3FixTriggerStep`), `0x08379384` (inside `FUN_083792f4`),
//!   `0x083795b0` (`sqlite3FixExpr`), and `0x08379788`
//!   (`sqlite3FixSrcList`).
//!   There are no predicated call forms or tail `b` transfers. Ghidra's
//!   124-byte size and 4-`bl` report match the raw words exactly. This is
//!   SQLite 3.5.x's `sqlite3FixSelect`.
//!
//! Algorithm: an absent select succeeds. For each select in the compound
//! chain, validate its result expression list (`pEList`, +0x00) through
//! `sqlite3FixExprList` @ `0x08379600`, its table source (`pSrc`, +0x0c)
//! through `sqlite3FixSrcList` @ `0x08379710`, then its `WHERE` (+0x10)
//! and `HAVING` (+0x18) expressions through the ported `sqlite_fix_expr`.
//! A nonzero child result stops immediately with one; otherwise `pPrior`
//! (+0x20) becomes the next loop iteration. Returning zero means the whole
//! compound select is valid.
//!
//! Deliberate host-only deviation: the two still-stock callees are absolute
//! calls to `0x08379600` and `0x08379710` on the target. Host tests replace
//! those boundaries through `FIX_SELECT_OPS`; its default no-ops reproduce
//! their NULL-input result but cannot model a non-NULL unported subtree.
//! The `WHERE`/`HAVING` fixer is the in-tree `sqlite_fix_expr`, called
//! directly; host tests pass NULL for both (its NULL input returns zero)
//! because its own failure states live behind its private ops boundary.

use super::fix_expr::sqlite_fix_expr;

/// Raw layout of the SQLite 3.5.x `Select` fields this fixer touches.
/// Word offsets are load-address facts; the gaps keep the target's 4-byte
/// spacing independent of host pointer width.
#[repr(C)]
pub struct Select {
    /// `pEList` — result expression list, validated via `sqlite3FixExprList`.
    pub p_elist: *mut u8,
    pub _gap_04: [u8; 0x08],
    /// `pSrc` — table source list, validated via `sqlite3FixSrcList`.
    pub p_src: *mut u8,
    /// `pWhere` — validated via `sqlite_fix_expr`.
    pub p_where: *mut u8,
    pub _gap_14: [u8; 0x04],
    /// `pHaving` — validated via `sqlite_fix_expr`.
    pub p_having: *mut u8,
    pub _gap_1c: [u8; 0x04],
    /// `pPrior` — next select in the compound chain.
    pub p_prior: *mut Select,
}

/// ABI of `sqlite3FixExprList` @ 0x08379600.
type FixExprListFn = unsafe extern "C" fn(fixer: *mut u8, list: *mut u8) -> u32;
/// ABI of `sqlite3FixSrcList` @ 0x08379710.
type FixSrcListFn = unsafe extern "C" fn(fixer: *mut u8, src: *mut u8) -> u32;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn fix_expr_list(fixer: *mut u8, list: *mut u8) -> u32 {
    let fix: FixExprListFn = core::mem::transmute(0x0837_9600usize);
    fix(fixer, list)
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn fix_src_list(fixer: *mut u8, src: *mut u8) -> u32 {
    let fix: FixSrcListFn = core::mem::transmute(0x0837_9710usize);
    fix(fixer, src)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_fix_expr_list(_fixer: *mut u8, _list: *mut u8) -> u32 {
    0
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_fix_src_list(_fixer: *mut u8, _src: *mut u8) -> u32 {
    0
}

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
struct FixSelectOps {
    fix_expr_list: FixExprListFn,
    fix_src_list: FixSrcListFn,
}

#[cfg(not(target_os = "none"))]
const DEFAULT_FIX_SELECT_OPS: FixSelectOps = FixSelectOps {
    fix_expr_list: missing_fix_expr_list,
    fix_src_list: missing_fix_src_list,
};

#[cfg(not(target_os = "none"))]
static mut FIX_SELECT_OPS: FixSelectOps = DEFAULT_FIX_SELECT_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn fix_expr_list(fixer: *mut u8, list: *mut u8) -> u32 {
    (core::ptr::read_volatile(core::ptr::addr_of!(FIX_SELECT_OPS)).fix_expr_list)(fixer, list)
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn fix_src_list(fixer: *mut u8, src: *mut u8) -> u32 {
    (core::ptr::read_volatile(core::ptr::addr_of!(FIX_SELECT_OPS)).fix_src_list)(fixer, src)
}

/// `sqlite3FixSelect` — original: `FUN_08379694` @ `0x08379694` (124 bytes;
/// 4 unconditional direct `bl` call sites).
///
/// Validates the expression list, table sources, and `WHERE`/`HAVING`
/// clauses of every select in the compound chain headed by `select` for the
/// supplied SQLite database-fixer context. It returns one at the first
/// invalid nested reference and zero when the whole chain is valid.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.sqlite_fix_select")]
#[inline(never)]
pub unsafe extern "C" fn sqlite_fix_select(fixer: *mut u8, mut select: *mut Select) -> u32 {
    while !select.is_null() {
        if fix_expr_list(fixer, (*select).p_elist) != 0 {
            return 1;
        }
        if fix_src_list(fixer, (*select).p_src) != 0 {
            return 1;
        }
        if sqlite_fix_expr(fixer, (*select).p_where.cast()) != 0 {
            return 1;
        }
        if sqlite_fix_expr(fixer, (*select).p_having.cast()) != 0 {
            return 1;
        }
        select = (*select).p_prior;
    }
    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: Vec<(&'static str, usize)> = Vec::new();
    static mut LIST_FAILURE: usize = 0;
    static mut SRC_FAILURE: usize = 0;

    fn lock() -> MutexGuard<'static, ()> {
        OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner())
    }

    unsafe fn restore_defaults() {
        core::ptr::write_volatile(core::ptr::addr_of_mut!(FIX_SELECT_OPS), DEFAULT_FIX_SELECT_OPS);
        (*core::ptr::addr_of_mut!(CALLS)).clear();
        core::ptr::write(core::ptr::addr_of_mut!(LIST_FAILURE), 0);
        core::ptr::write(core::ptr::addr_of_mut!(SRC_FAILURE), 0);
    }

    unsafe fn calls() -> Vec<(&'static str, usize)> {
        (*core::ptr::addr_of!(CALLS)).clone()
    }

    unsafe extern "C" fn recording_fix_expr_list(_fixer: *mut u8, list: *mut u8) -> u32 {
        (*core::ptr::addr_of_mut!(CALLS)).push(("list", list as usize));
        (list as usize == core::ptr::read(core::ptr::addr_of!(LIST_FAILURE))) as u32
    }

    unsafe extern "C" fn recording_fix_src_list(_fixer: *mut u8, src: *mut u8) -> u32 {
        (*core::ptr::addr_of_mut!(CALLS)).push(("src", src as usize));
        (src as usize == core::ptr::read(core::ptr::addr_of!(SRC_FAILURE))) as u32
    }

    unsafe fn install_recorders() {
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(FIX_SELECT_OPS),
            FixSelectOps {
                fix_expr_list: recording_fix_expr_list,
                fix_src_list: recording_fix_src_list,
            },
        );
    }

    fn select(elist: usize, src: usize, prior: *mut Select) -> Select {
        Select {
            p_elist: elist as *mut u8,
            _gap_04: [0; 0x08],
            p_src: src as *mut u8,
            p_where: core::ptr::null_mut(),
            _gap_14: [0; 0x04],
            p_having: core::ptr::null_mut(),
            _gap_1c: [0; 0x04],
            p_prior: prior,
        }
    }

    #[test]
    fn null_select_calls_nothing_and_succeeds() {
        let _guard = lock();
        unsafe {
            restore_defaults();
            install_recorders();
            assert_eq!(sqlite_fix_select(0x1111usize as *mut u8, core::ptr::null_mut()), 0);
            assert!(calls().is_empty());
            restore_defaults();
        }
    }

    #[test]
    fn walks_prior_chain_in_order() {
        let _guard = lock();
        unsafe {
            restore_defaults();
            install_recorders();
            let mut tail = select(0x2002, 0x3002, core::ptr::null_mut());
            let mut head = select(0x2001, 0x3001, &mut tail);

            assert_eq!(sqlite_fix_select(0x1111usize as *mut u8, &mut head), 0);
            assert_eq!(
                calls(),
                [("list", 0x2001), ("src", 0x3001), ("list", 0x2002), ("src", 0x3002)],
            );
            restore_defaults();
        }
    }

    #[test]
    fn expr_list_failure_short_circuits_chain() {
        let _guard = lock();
        unsafe {
            restore_defaults();
            install_recorders();
            let mut tail = select(0x2002, 0x3002, core::ptr::null_mut());
            let mut head = select(0x2001, 0x3001, &mut tail);
            core::ptr::write(core::ptr::addr_of_mut!(LIST_FAILURE), 0x2001);

            assert_eq!(sqlite_fix_select(0x1111usize as *mut u8, &mut head), 1);
            assert_eq!(calls(), [("list", 0x2001)]);
            restore_defaults();
        }
    }

    #[test]
    fn src_list_failure_skips_remaining_selects() {
        let _guard = lock();
        unsafe {
            restore_defaults();
            install_recorders();
            let mut tail = select(0x2002, 0x3002, core::ptr::null_mut());
            let mut head = select(0x2001, 0x3001, &mut tail);
            core::ptr::write(core::ptr::addr_of_mut!(SRC_FAILURE), 0x3001);

            assert_eq!(sqlite_fix_select(0x1111usize as *mut u8, &mut head), 1);
            assert_eq!(calls(), [("list", 0x2001), ("src", 0x3001)]);
            restore_defaults();
        }
    }

    #[test]
    fn failure_in_tail_select_still_returns_one() {
        let _guard = lock();
        unsafe {
            restore_defaults();
            install_recorders();
            let mut tail = select(0x2002, 0x3002, core::ptr::null_mut());
            let mut head = select(0x2001, 0x3001, &mut tail);
            core::ptr::write(core::ptr::addr_of_mut!(LIST_FAILURE), 0x2002);

            assert_eq!(sqlite_fix_select(0x1111usize as *mut u8, &mut head), 1);
            assert_eq!(
                calls(),
                [("list", 0x2001), ("src", 0x3001), ("list", 0x2002)],
            );
            restore_defaults();
        }
    }
}
