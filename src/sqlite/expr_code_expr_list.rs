//! Compile an SQLite expression list into consecutive VDBE registers.
//!
//! `expr_code_expr_list` — original: `FUN_08376c94` @ **0x08376c94**
//! (156 bytes; **5** direct inbound `bl` call sites, all unconditional:
//! 0x082e885c, 0x08368908, 0x083771c0, 0x083836dc, and 0x083961a0).
//! Raw words end at `pop {...,pc}` @ 0x08376d2c; the separately linked next
//! function begins at 0x08376d30.
//!
//! SQLite 3.5.9's `sqlite3ExprCodeExprList` (expr.c): return zero for a NULL
//! list; otherwise call `expr_code` for every 12-byte `ExprList_item`, with
//! targets `target + i`, and return `nExpr`. When `do_hard_copy` is nonzero,
//! the firmware inlines `sqlite3ExprHardCopy`: it changes the newest VDBE op
//! from opcode 8 (`OP_SCopy`) to opcode 19 (`OP_Copy`) only when that op's
//! source register lies in `[target, target + nExpr)`.
//!
//! Deliberate deviation: no deviation. The upstream assertions are absent in
//! the retail NDEBUG image; in particular, non-NULL lists require a valid
//! `Parse.pVdbe` when `do_hard_copy` is set.

use super::expr_code::{expr_code, P_VDBE_OFFSET};
use super::vdbe::vdbe_get_op;

const EXPR_LIST_ITEMS_OFFSET: usize = 0x0c;
const EXPR_LIST_ITEM_SIZE: usize = 0x0c;
const OP_S_COPY: u8 = 8;
const OP_COPY: u8 = 19;

/// `sqlite3ExprCodeExprList` — original: `FUN_08376c94` @ 0x08376c94
/// (156 bytes; 5 direct unconditional `bl` call sites).
///
/// # Safety
///
/// A non-null `list` must name the target-width `ExprList` layout: signed
/// `nExpr` at +0 and the 32-bit `a` pointer at +0x0c. Each item is 12 bytes
/// and begins with a 32-bit `Expr *`. `parse` must meet [`expr_code`]'s
/// requirements; `do_hard_copy != 0` additionally requires its `pVdbe` field
/// to be valid, matching the unguarded retail call to `vdbe_get_op`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn expr_code_expr_list(
    parse: *mut u8,
    list: *mut u8,
    target: i32,
    do_hard_copy: i32,
) -> i32 {
    if list.is_null() {
        return 0;
    }

    let count = list.cast::<i32>().read();
    let mut item = (list.add(EXPR_LIST_ITEMS_OFFSET).cast::<u32>().read() as usize) as *mut u8;
    let mut index = 0i32;
    while index < count {
        let expr = (item.cast::<u32>().read() as usize) as *mut u8;
        expr_code(parse, expr, target.wrapping_add(index));

        if do_hard_copy != 0 {
            let vdbe = (parse.add(P_VDBE_OFFSET) as *const *mut super::vdbe::Vdbe).read();
            let op = vdbe_get_op(vdbe, (*vdbe).n_op.wrapping_sub(1));
            if !op.is_null()
                && (*op).opcode == OP_S_COPY
                && (*op).p1 >= target
                && (*op).p1 < target.wrapping_add(count)
            {
                (*op).opcode = OP_COPY;
            }
        }

        index = index.wrapping_add(1);
        item = item.add(EXPR_LIST_ITEM_SIZE);
    }
    count
}


#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::sqlite::expr_code::{ExprCodeOps, DEFAULT_EXPR_CODE_OPS, EXPR_CODE_OPS, EXPR_CODE_OPS_LOCK};
    use crate::sqlite::vdbe::{Vdbe, VdbeOp};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::{LazyLock, MutexGuard};
    use std::vec::Vec;

    use std::vec;
    const SLAB_LEN: usize = 0x1000;
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::SQLITE_EXPR_CODE_EXPR_LIST, SLAB_LEN).map(|pointer| pointer as usize)
    });
    static mut CALLS: Vec<(usize, i32)> = Vec::new();

    unsafe extern "C" fn record_expr(_parse: *mut u8, expr: *mut u8, target: i32) -> i32 {
        (*addr_of_mut!(CALLS)).push((expr as usize, target));
        target
    }

    struct Fixture {
        _guard: MutexGuard<'static, ()>,
        list: *mut u8,
    }

    impl Fixture {
        fn new(count: i32) -> Option<Self> {
            let guard = EXPR_CODE_OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
            let base = (*SLAB)? as *mut u8;
            unsafe {
                base.write_bytes(0, SLAB_LEN);
                base.cast::<i32>().write(count);
                base.add(EXPR_LIST_ITEMS_OFFSET).cast::<u32>().write(base.add(0x40) as usize as u32);
                (*addr_of_mut!(CALLS)).clear();
                core::ptr::write_volatile(addr_of_mut!(EXPR_CODE_OPS), ExprCodeOps { expr_code_target: record_expr });
            }
            Some(Self { _guard: guard, list: base })
        }
        unsafe fn set_expr(&self, index: usize, expr: usize) {
            self.list.add(0x40 + index * EXPR_LIST_ITEM_SIZE).cast::<u32>().write(expr as u32);
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            unsafe { core::ptr::write_volatile(addr_of_mut!(EXPR_CODE_OPS), DEFAULT_EXPR_CODE_OPS) };
        }
    }

    fn parse_with(vdbe: *mut Vdbe) -> [u8; 0x20] {
        let mut parse = [0u8; 0x20];
        unsafe { (parse.as_mut_ptr().add(P_VDBE_OFFSET) as *mut *mut Vdbe).write(vdbe) };
        parse
    }

    #[test]
    fn null_list_returns_zero_without_expression_dispatch() {
        let guard = EXPR_CODE_OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            (*addr_of_mut!(CALLS)).clear();
            assert_eq!(expr_code_expr_list(core::ptr::null_mut(), core::ptr::null_mut(), 7, 0), 0);
            assert!(addr_of!(CALLS).read().is_empty());
        }
        drop(guard);
    }

    #[test]
    fn evaluates_each_item_in_consecutive_wrapping_registers() {
        let Some(fixture) = Fixture::new(3) else {
            assert!(note_missing_u32_fixture("sqlite/expr_code_expr_list"));
            return;
        };
        unsafe {
            fixture.set_expr(0, 0x1000);
            fixture.set_expr(1, 0x2000);
            fixture.set_expr(2, 0x3000);
            let mut parse = parse_with(core::ptr::null_mut());
            assert_eq!(expr_code_expr_list(parse.as_mut_ptr(), fixture.list, i32::MAX, 0), 3);
            assert_eq!((*addr_of!(CALLS)).clone(), vec![(0x1000, i32::MAX), (0x2000, i32::MIN), (0x3000, i32::MIN + 1)]);
        }
    }

    #[test]
    fn hard_copy_only_converts_the_newest_in_range_shallow_copy() {
        let Some(fixture) = Fixture::new(2) else {
            assert!(note_missing_u32_fixture("sqlite/expr_code_expr_list"));
            return;
        };
        unsafe {
            fixture.set_expr(0, 0x1000);
            fixture.set_expr(1, 0x2000);
            let mut op = VdbeOp { opcode: OP_S_COPY, p4type: 0, opflags: 0, p5: 0, p1: 8, p2: 0, p3: 0, p4: core::ptr::null_mut() };
            let mut vdbe: Vdbe = core::mem::zeroed();
            vdbe.n_op = 1;
            vdbe.a_op = &mut op;
            let mut parse = parse_with(&mut vdbe);
            assert_eq!(expr_code_expr_list(parse.as_mut_ptr(), fixture.list, 7, 1), 2);
            assert_eq!(op.opcode, OP_COPY);
            assert_eq!((*addr_of!(CALLS)).clone(), vec![(0x1000, 7), (0x2000, 8)]);

            op.opcode = OP_S_COPY;
            op.p1 = 9;
            (*addr_of_mut!(CALLS)).clear();
            assert_eq!(expr_code_expr_list(parse.as_mut_ptr(), fixture.list, 7, 1), 2);
            assert_eq!(op.opcode, OP_S_COPY, "exclusive upper bound preserves an out-of-range source");
        }
    }
}
