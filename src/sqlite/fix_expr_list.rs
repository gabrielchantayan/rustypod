//! SQLite expression-list reference validation.
//!
//! - `sqlite_fix_expr_list` — original: `FUN_08379600` @ `0x08379600` (84
//!   bytes, `0x08379600..0x08379654`; the independent `sqlite3FixInit`
//!   prologue begins at `0x08379654`). Decoding every aligned ARM `B`/`BL`
//!   immediate in `osos.dec` finds three direct inbound `bl` calls, all
//!   unconditional: `0x083793ac`, `0x083795c4`, and `0x083796ac`. There are
//!   no predicated `bl` calls or tail branches to this entry. This is SQLite
//!   3.5.x's `sqlite3FixExprList`.
//!
//! Algorithm: a NULL list succeeds. Otherwise walk its signed `nExpr` count
//! at +0x00 and 12-byte `ExprList_item` array at +0x0c, passing each item's
//! expression at +0x00 to `sqlite3FixExpr`. Stop at the first nonzero child
//! result and return one; otherwise return zero. The raw u32 reads deliberately
//! preserve target offsets on 64-bit hosts rather than using host pointer layout.

/// ABI of `sqlite3FixExpr` @ 0x08379598.
type FixExprFn = unsafe extern "C" fn(fixer: *mut u8, expr: *mut u8) -> u32;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn fix_expr(fixer: *mut u8, expr: *mut u8) -> u32 {
    super::fix_expr::sqlite_fix_expr(fixer, expr.cast())
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_fix_expr(_fixer: *mut u8, _expr: *mut u8) -> u32 {
    0
}

#[cfg(not(target_os = "none"))]
static mut FIX_EXPR: FixExprFn = missing_fix_expr;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn fix_expr(fixer: *mut u8, expr: *mut u8) -> u32 {
    core::ptr::read_volatile(core::ptr::addr_of!(FIX_EXPR))(fixer, expr)
}

/// `sqlite3FixExprList` — original: `FUN_08379600` @ `0x08379600` (84 bytes;
/// 3 unconditional direct `bl` call sites).
///
/// Validates every expression in a SQLite expression list for the supplied
/// database-fixer context. A NULL list or every valid child returns zero; the
/// first invalid child returns one.
///
/// # Safety
///
/// A non-null `list` must be aligned for the target-width `ExprList` layout:
/// signed `nExpr` at +0x00 and a u32 `a` pointer at +0x0c. Each aligned
/// 12-byte item begins with a u32 `Expr *`.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.sqlite_fix_expr_list")]
#[inline(never)]
pub unsafe extern "C" fn sqlite_fix_expr_list(fixer: *mut u8, list: *mut u8) -> u32 {
    if list.is_null() {
        return 0;
    }

    let count = core::ptr::read(list.cast::<i32>());
    let mut item = core::ptr::read(list.add(0x0c).cast::<u32>()) as usize as *mut u8;
    let mut index = 0;
    while index < count {
        let expr = core::ptr::read(item.cast::<u32>()) as usize as *mut u8;
        if fix_expr(fixer, expr) != 0 {
            return 1;
        }
        item = item.add(12);
        index += 1;
    }
    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::{LazyLock, Mutex};
    use std::vec::Vec;

    const FIXTURE_LEN: usize = 0x1000;
    const LIST_OFFSET: usize = 0x100;
    const ITEMS_OFFSET: usize = 0x200;
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::SQLITE_FIX_EXPR_LIST, FIXTURE_LEN).map(|pointer| pointer as usize)
    });
    static LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: Vec<u32> = Vec::new();
    static mut FAILURE: u32 = 0;

    unsafe extern "C" fn recording_fix_expr(_fixer: *mut u8, expr: *mut u8) -> u32 {
        let expr = expr as usize as u32;
        (*core::ptr::addr_of_mut!(CALLS)).push(expr);
        (expr == core::ptr::read(core::ptr::addr_of!(FAILURE))) as u32
    }

    unsafe fn reset() {
        core::ptr::write_volatile(core::ptr::addr_of_mut!(FIX_EXPR), missing_fix_expr);
        (*core::ptr::addr_of_mut!(CALLS)).clear();
        core::ptr::write(core::ptr::addr_of_mut!(FAILURE), 0);
    }

    unsafe fn install_recorder() {
        core::ptr::write_volatile(core::ptr::addr_of_mut!(FIX_EXPR), recording_fix_expr);
    }

    unsafe fn write_list(base: *mut u8, count: i32, expressions: &[u32]) -> *mut u8 {
        base.write_bytes(0, FIXTURE_LEN);
        let list = base.add(LIST_OFFSET);
        core::ptr::write(list.cast::<i32>(), count);
        core::ptr::write(list.add(0x0c).cast::<u32>(), base.add(ITEMS_OFFSET) as usize as u32);
        for (index, expression) in expressions.iter().enumerate() {
            core::ptr::write(base.add(ITEMS_OFFSET + index * 12).cast::<u32>(), *expression);
        }
        list
    }

    #[test]
    fn null_and_nonpositive_lists_do_not_call_the_child_fixer() {
        let _guard = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some(base) = *SLAB else {
            assert!(note_missing_u32_fixture("sqlite/fix_expr_list"));
            return;
        };
        unsafe {
            reset();
            install_recorder();
            assert_eq!(sqlite_fix_expr_list(core::ptr::null_mut(), core::ptr::null_mut()), 0);
            assert_eq!(sqlite_fix_expr_list(core::ptr::null_mut(), write_list(base as *mut u8, 0, &[])), 0);
            assert_eq!(sqlite_fix_expr_list(core::ptr::null_mut(), write_list(base as *mut u8, -1, &[])), 0);
            assert!((*core::ptr::addr_of!(CALLS)).is_empty());
            reset();
        }
    }

    #[test]
    fn walks_twelve_byte_items_and_stops_at_first_failure() {
        let _guard = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some(base) = *SLAB else {
            assert!(note_missing_u32_fixture("sqlite/fix_expr_list"));
            return;
        };
        unsafe {
            reset();
            install_recorder();
            let expressions = [0x1234_0001, 0x1234_0002, 0x1234_0003];
            core::ptr::write(core::ptr::addr_of_mut!(FAILURE), expressions[1]);
            assert_eq!(sqlite_fix_expr_list(0x1111usize as *mut u8, write_list(base as *mut u8, 3, &expressions)), 1);
            assert_eq!(*core::ptr::addr_of!(CALLS), expressions[..2]);
            reset();
        }
    }
}
