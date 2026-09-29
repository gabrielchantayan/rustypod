//! Resolve a compound SELECT result column's effective SQLite collation.
//!
//! - `select_coll_seq` — original: `FUN_082da7fc` @ `0x082da7fc` (76 bytes,
//!   `0x082da7fc..0x082da848`; the following `push {lr}` starts the next
//!   function). Raw ARM words contain one plain outbound `bl` (the recursive
//!   call) and no predicated `bl`; two plain inbound `bl` call sites were
//!   independently found at `0x082da668` and `0x082da820`.
//!
//! SQLite 3.5.9's `sqlite3SelectCollSeq`: first recurse through `pPrior` so
//! the leftmost SELECT in a compound query wins. If it has no collation, take
//! item `column` from this SELECT's result list and tail-call
//! `sqlite3ExprCollSeq` for that expression.
//!
//! Deliberate deviation: the stock tail branch becomes a direct Rust call.
//! Typed target-layout views keep the target's 12-byte `ExprListItem` stride;
//! host fixtures use the corresponding naturally widened Rust layout.

use super::error_msg::Parse;
use super::expr_affinity::Expr;
use super::expr_coll_seq::{expr_coll_seq, CollSeq};

#[repr(C)]
pub struct ExprListItem {
    pub expression: *mut Expr,
    _gap_04: [u8; 0x0c - 0x04],
}

#[repr(C)]
pub struct ExprList {
    _count: i32,
    _capacity: i32,
    _cursor: i32,
    pub items: *mut ExprListItem,
}

#[repr(C)]
pub struct Select {
    pub expressions: *mut ExprList,
    _gap_04: [u8; 0x20 - 0x04],
    pub prior: *mut Select,
}

#[cfg(target_pointer_width = "32")]
const _: () = {
    assert!(core::mem::offset_of!(ExprList, items) == 0x0c);
    assert!(core::mem::offset_of!(ExprListItem, expression) == 0x00);
    assert!(core::mem::size_of::<ExprListItem>() == 0x0c);
    assert!(core::mem::offset_of!(Select, prior) == 0x20);
};

/// `sqlite3SelectCollSeq`: resolve `column`'s result collation, favoring the
/// leftmost SELECT in a compound chain.
///
/// # Safety
/// `parse` and `select` must satisfy `expr_coll_seq`'s requirements. Every
/// traversed select must have a readable result list containing `column`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn select_coll_seq(
    parse: *mut Parse,
    select: *mut Select,
    column: i32,
) -> *mut CollSeq {
    if !(*select).prior.is_null() {
        let collation = select_coll_seq(parse, (*select).prior, column);
        if !collation.is_null() {
            return collation;
        }
    }

    let expression = (*(*select).expressions).items.add(column as usize).read().expression;
    expr_coll_seq(parse, expression)
}

#[cfg(test)]
mod tests {
    use core::ptr;

    use super::*;
    use crate::testing::SQLITE_EXPR_COLL_SEQ_TEST_LOCK;
    use super::super::expr_coll_seq::{ExprCollSeqHooks, DEFAULT_EXPR_COLL_SEQ_HOOKS, EXPR_COLL_SEQ_HOOKS};

    unsafe extern "C" fn accept_collation(
        _db: *mut u8,
        collation: *mut CollSeq,
        _name: *const u8,
        _name_len: i32,
    ) -> *mut CollSeq {
        collation
    }

    struct HookGuard;
    impl Drop for HookGuard {
        fn drop(&mut self) {
            unsafe { EXPR_COLL_SEQ_HOOKS = DEFAULT_EXPR_COLL_SEQ_HOOKS; }
        }
    }

    fn install_acceptor() -> HookGuard {
        unsafe { EXPR_COLL_SEQ_HOOKS = ExprCollSeqHooks { get_coll_seq: accept_collation }; }
        HookGuard
    }


    unsafe fn select(expressions: *mut ExprList, prior: *mut Select) -> Select {
        Select { expressions, _gap_04: [0; 0x20 - 0x04], prior }
    }

    unsafe fn list(items: *mut ExprListItem) -> ExprList {
        ExprList { _count: 0, _capacity: 0, _cursor: 0, items }
    }

    unsafe fn expression(collation: *mut CollSeq) -> Expr {
        let mut expression: Expr = core::mem::zeroed();
        expression.collating_sequence = collation.cast();
        expression
    }

    #[test]
    fn returns_current_select_column_collation() {
        let _lock = SQLITE_EXPR_COLL_SEQ_TEST_LOCK.lock();
        let _hooks = install_acceptor();
        unsafe {
            let mut collation: CollSeq = core::mem::zeroed();
            let mut expression = expression(&mut collation);
            let mut items = [ExprListItem { expression: &mut expression, _gap_04: [0; 8] }];
            let mut expressions = list(items.as_mut_ptr());
            let mut current = select(&mut expressions, ptr::null_mut());

            let mut parse: Parse = core::mem::zeroed();
            assert_eq!(select_coll_seq(&mut parse, &mut current, 0) as usize, &mut collation as *mut CollSeq as usize);
        }
    }

    #[test]
    fn leftmost_compound_collation_wins() {
        let _lock = SQLITE_EXPR_COLL_SEQ_TEST_LOCK.lock();
        let _hooks = install_acceptor();
        unsafe {
            let mut left_collation: CollSeq = core::mem::zeroed();
            let mut right_collation: CollSeq = core::mem::zeroed();
            let mut left_expression = expression(&mut left_collation);
            let mut right_expression = expression(&mut right_collation);
            let mut left_items = [ExprListItem { expression: &mut left_expression, _gap_04: [0; 8] }];
            let mut right_items = [ExprListItem { expression: &mut right_expression, _gap_04: [0; 8] }];
            let mut left_expressions = list(left_items.as_mut_ptr());
            let mut right_expressions = list(right_items.as_mut_ptr());
            let mut left = select(&mut left_expressions, ptr::null_mut());
            let mut right = select(&mut right_expressions, &mut left);

            let mut parse: Parse = core::mem::zeroed();
            assert_eq!(select_coll_seq(&mut parse, &mut right, 0) as usize, &mut left_collation as *mut CollSeq as usize);
        }
    }

    #[test]
    fn falls_back_when_prior_has_no_collation() {
        let _lock = SQLITE_EXPR_COLL_SEQ_TEST_LOCK.lock();
        let _hooks = install_acceptor();
        unsafe {
            let mut collation: CollSeq = core::mem::zeroed();
            let mut left_expression = expression(ptr::null_mut());
            let mut right_expression = expression(&mut collation);
            let mut left_items = [ExprListItem { expression: &mut left_expression, _gap_04: [0; 8] }];
            let mut right_items = [ExprListItem { expression: &mut right_expression, _gap_04: [0; 8] }];
            let mut left_expressions = list(left_items.as_mut_ptr());
            let mut right_expressions = list(right_items.as_mut_ptr());
            let mut left = select(&mut left_expressions, ptr::null_mut());
            let mut right = select(&mut right_expressions, &mut left);

            let mut parse: Parse = core::mem::zeroed();
            assert_eq!(select_coll_seq(&mut parse, &mut right, 0) as usize, &mut collation as *mut CollSeq as usize);
        }
    }
}
