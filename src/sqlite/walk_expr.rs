//! `sqlite_expr_walk` — original: `FUN_0839866c` @ `0x0839866c` (140
//! bytes, `0x0839866c..0x083986f8`; the separately linked sibling begins at
//! `0x083986f8`).
//!
//! Raw ARM decoding finds **13 direct `bl` call sites**: 12 unconditional and
//! one `blne` at `0x08383394`. The lone predicated call is gated by that
//! caller's condition; this walker itself has a NULL root guard but no callback
//! guard.
//!
//! This is SQLite's internal expression-tree visitor. It invokes `visit` with
//! `(context, expr)`. A zero result descends pre-order through `p_left`, then
//! `p_right`, then the expression list at `p_list`. A nonzero result at most
//! one prunes that node's descendants and continues successfully; a result
//! greater than one aborts, as does an abort reported by a descendant. A NULL
//! expression succeeds without calling `visit`.
//!
//! Deliberate deviation: the final list traversal is the distinct unported
//! `FUN_08398614` @ `0x08398614`. Target builds call its verified firmware
//! entry; host builds expose a volatile replacement slot. `names.yaml` has no
//! ported entry for that address, so no existing port is re-stubbed. The raw
//! function touches `p_list` only; it deliberately does not inspect the
//! separate `p_select` field.

use core::ptr;

use super::expr_height::Expr;

/// Callback run before descending from one SQLite expression node.
///
/// Zero requests descent, nonzero values through one prune the node, and a
/// value greater than one aborts the whole traversal.
pub type ExprVisit = unsafe extern "C" fn(context: *mut u8, expr: *mut Expr) -> i32;

/// ABI of `FUN_08398614`, the still-unported expression-list walker.
pub type ExprListWalk = unsafe extern "C" fn(
    list: *mut u8,
    visit: ExprVisit,
    context: *mut u8,
) -> i32;

/// Firmware load address of the expression-list walker.
pub const EXPR_LIST_WALK_ADDRESS: usize = 0x0839_8614;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_expr_list_walk(
    list: *mut u8,
    visit: ExprVisit,
    context: *mut u8,
) -> i32 {
    let walk: ExprListWalk = core::mem::transmute(EXPR_LIST_WALK_ADDRESS);
    walk(list, visit, context)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_expr_list_walk(
    _list: *mut u8,
    _visit: ExprVisit,
    _context: *mut u8,
) -> i32 {
    panic!("sqlite_expr_walk requires the expression-list walker 0x08398614")
}

/// Dispatch slot for the unported `FUN_08398614` expression-list walker.
/// Target builds retain the stock entry; host tests install a recording model.
#[cfg(target_os = "none")]
pub static mut SQLITE_EXPR_LIST_WALK: ExprListWalk = firmware_expr_list_walk;

/// Host default for [`SQLITE_EXPR_LIST_WALK`]; tests must explicitly provide
/// the list walk whenever a successful visitor reaches `Expr::p_list`.
#[cfg(not(target_os = "none"))]
pub static mut SQLITE_EXPR_LIST_WALK: ExprListWalk = missing_expr_list_walk;

/// `sqlite_expr_walk` — original: `FUN_0839866c` @ `0x0839866c` (140 bytes;
/// 13 direct `bl` callers, 12 unconditional and one predicated). See the
/// module header for the recovered algorithm.
///
/// Returns zero after a complete walk or a visitor prune; returns one after a
/// visitor or descendant abort.
///
/// # Safety
///
/// `visit` must be callable. Every non-NULL expression reached must be a
/// readable [`Expr`]; the unported list walker defines the additional validity
/// requirements of `p_list` when and only when the visitor accepts the node
/// and both operand walks complete.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn sqlite_expr_walk(
    expr: *mut Expr,
    visit: ExprVisit,
    context: *mut u8,
) -> i32 {
    if expr.is_null() {
        return 0;
    }

    let status = visit(context, expr);
    if status != 0 {
        return if status > 1 { 1 } else { 0 };
    }

    let left = ptr::read_volatile(ptr::addr_of!((*expr).p_left)).cast::<Expr>();
    if sqlite_expr_walk(left, visit, context) != 0 {
        return 1;
    }

    let right = ptr::read_volatile(ptr::addr_of!((*expr).p_right)).cast::<Expr>();
    if sqlite_expr_walk(right, visit, context) != 0 {
        return 1;
    }

    let list = ptr::read_volatile(ptr::addr_of!((*expr).p_list));
    let walk_list = ptr::read_volatile(ptr::addr_of!(SQLITE_EXPR_LIST_WALK));
    if walk_list(list, visit, context) != 0 {
        return 1;
    }

    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut VISITS: [u8; 8] = [0; 8];
    static mut VISIT_COUNT: usize = 0;
    static mut LIST_POINTER: *mut u8 = ptr::null_mut();
    static mut LIST_VISIT: Option<ExprVisit> = None;
    static mut LIST_CONTEXT: *mut u8 = ptr::null_mut();
    static mut LIST_RESULT: i32 = 0;

    struct Reset;

    impl Drop for Reset {
        fn drop(&mut self) {
            unsafe {
                VISITS = [0; 8];
                VISIT_COUNT = 0;
                LIST_POINTER = ptr::null_mut();
                LIST_VISIT = None;
                LIST_CONTEXT = ptr::null_mut();
                LIST_RESULT = 0;
                SQLITE_EXPR_LIST_WALK = missing_expr_list_walk;
            }
        }
    }

    fn expr(id: u8, status: i8, left: *mut Expr, right: *mut Expr, list: *mut u8) -> Expr {
        let mut value = Expr {
            _gap_00: [0; 0x08],
            p_left: left.cast(),
            p_right: right.cast(),
            p_list: list,
            _gap_14: [0; 0x38 - 0x14],
            p_select: ptr::null_mut(),
            _gap_3c: [0; 0x40 - 0x3c],
            n_height: 0,
        };
        value._gap_00[0] = id;
        value._gap_00[1] = status as u8;
        value
    }

    unsafe extern "C" fn record_visit(_context: *mut u8, node: *mut Expr) -> i32 {
        VISITS[VISIT_COUNT] = (*node)._gap_00[0];
        VISIT_COUNT += 1;
        (*node)._gap_00[1] as i8 as i32
    }

    unsafe extern "C" fn record_list_walk(
        list: *mut u8,
        visit: ExprVisit,
        context: *mut u8,
    ) -> i32 {
        LIST_POINTER = list;
        LIST_VISIT = Some(visit);
        LIST_CONTEXT = context;
        LIST_RESULT
    }

    fn install_list_walk(result: i32) {
        unsafe {
            SQLITE_EXPR_LIST_WALK = record_list_walk;
            LIST_RESULT = result;
        }
    }

    #[test]
    fn null_root_never_calls_visitor_or_list_walker() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _reset = Reset;
        install_list_walk(1);

        let result = unsafe { sqlite_expr_walk(ptr::null_mut(), record_visit, 0x4d as *mut u8) };

        assert_eq!(result, 0);
        unsafe {
            assert_eq!(VISIT_COUNT, 0);
            assert!(LIST_POINTER.is_null());
        }
    }

    #[test]
    fn nonzero_status_prunes_and_only_greater_than_one_aborts() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _reset = Reset;
        install_list_walk(0);
        let mut child = expr(2, 0, ptr::null_mut(), ptr::null_mut(), ptr::null_mut());
        let mut pruned = expr(1, 1, ptr::addr_of_mut!(child), ptr::null_mut(), 0x1 as *mut u8);

        assert_eq!(unsafe { sqlite_expr_walk(ptr::addr_of_mut!(pruned), record_visit, ptr::null_mut()) }, 0);
        unsafe {
            assert_eq!(&VISITS[..VISIT_COUNT], &[1]);
            assert!(LIST_POINTER.is_null(), "a pruned node does not visit its list");
        }

        let mut negative = expr(3, -1, ptr::addr_of_mut!(child), ptr::null_mut(), 0x2 as *mut u8);
        assert_eq!(unsafe { sqlite_expr_walk(ptr::addr_of_mut!(negative), record_visit, ptr::null_mut()) }, 0);
        unsafe { assert_eq!(&VISITS[..VISIT_COUNT], &[1, 3]); }

        let mut aborting = expr(4, 2, ptr::addr_of_mut!(child), ptr::null_mut(), 0x3 as *mut u8);
        assert_eq!(unsafe { sqlite_expr_walk(ptr::addr_of_mut!(aborting), record_visit, ptr::null_mut()) }, 1);
        unsafe {
            assert_eq!(&VISITS[..VISIT_COUNT], &[1, 3, 4]);
            assert!(LIST_POINTER.is_null());
        }
    }

    #[test]
    fn descendant_abort_short_circuits_right_operand_and_list() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _reset = Reset;
        install_list_walk(0);
        let mut left = expr(2, 2, ptr::null_mut(), ptr::null_mut(), ptr::null_mut());
        let mut right = expr(3, 0, ptr::null_mut(), ptr::null_mut(), ptr::null_mut());
        let mut root = expr(1, 0, ptr::addr_of_mut!(left), ptr::addr_of_mut!(right), 0x9 as *mut u8);

        assert_eq!(unsafe { sqlite_expr_walk(ptr::addr_of_mut!(root), record_visit, ptr::null_mut()) }, 1);
        unsafe {
            assert_eq!(&VISITS[..VISIT_COUNT], &[1, 2]);
            assert!(LIST_POINTER.is_null());
        }
    }

    #[test]
    fn accepted_node_visits_operands_then_forwards_list_callback_and_context() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _reset = Reset;
        install_list_walk(1);
        let context = 0x5a as *mut u8;
        let list = 0x61 as *mut u8;
        let mut left = expr(2, 1, ptr::null_mut(), ptr::null_mut(), ptr::null_mut());
        let mut right = expr(3, -1, ptr::null_mut(), ptr::null_mut(), ptr::null_mut());
        let mut root = expr(1, 0, ptr::addr_of_mut!(left), ptr::addr_of_mut!(right), list);

        assert_eq!(unsafe { sqlite_expr_walk(ptr::addr_of_mut!(root), record_visit, context) }, 1);
        unsafe {
            assert_eq!(&VISITS[..VISIT_COUNT], &[1, 2, 3]);
            assert_eq!(LIST_POINTER, list);
            assert_eq!(LIST_VISIT.unwrap() as usize, record_visit as ExprVisit as usize);
            assert_eq!(LIST_CONTEXT, context);
        }
    }
}
