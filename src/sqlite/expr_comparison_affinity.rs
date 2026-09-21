//! SQLite comparison-expression affinity recovery.

use super::expr_affinity::{expr_affinity, Expr};
use super::expr_compare_affinity::expr_compare_affinity;

const AFFINITY_NONE: u8 = b'b';

/// `expr_comparison_affinity` — original: `FUN_082c4718` @ `0x082c4718`
/// (84 bytes, `0x082c4718..0x082c476b`; the next independent `push` starts
/// at `0x082c476c`). Raw ARM decoding finds two plain outbound `bl` calls
/// (`expr_affinity` @ `0x083768e0`, `expr_compare_affinity` @ `0x083735b8`)
/// and zero predicated `bl`; it has three direct inbound plain `bl` call
/// sites. SQLite 3.5.9's comparison-affinity helper: get the left operand's
/// affinity, compare it with the right operand, or with the first SELECT
/// result when there is no right operand; when neither exists, preserve the
/// left affinity or use SQLITE_AFF_NONE. Deliberate deviations: none.
///
/// # Safety
/// `expression` must name a valid target-layout SQLite expression. A NULL
/// right operand requires either a NULL select or a valid select result list
/// with a first expression.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn expr_comparison_affinity(expression: *mut Expr) -> u8 {
    let left_affinity = expr_affinity((*expression).left);
    let mut right = (*expression).right;

    if right.is_null() {
        let select = (*expression).select;
        if select.is_null() {
            return if left_affinity == 0 { AFFINITY_NONE } else { left_affinity };
        }
        right = (*(*select).expressions).items.read().expr;
    }

    expr_compare_affinity(right, left_affinity)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::sqlite::expr_affinity::{ExprList, ExprListItem, Select};

    unsafe fn expr(affinity: u8) -> Expr {
        let mut expression: Expr = core::mem::zeroed();
        expression.affinity = affinity;
        expression
    }

    #[test]
    fn compares_left_and_right_operand_affinities() {
        unsafe {
            let mut left = expr(b'a');
            let mut right = expr(b'd');
            let mut comparison = expr(0);
            comparison.left = &mut left;
            comparison.right = &mut right;
            assert_eq!(expr_comparison_affinity(&mut comparison), b'c');
        }
    }

    #[test]
    fn uses_first_select_result_when_right_operand_is_absent() {
        unsafe {
            let mut left = expr(0);
            let mut result = expr(b'e');
            let mut item = ExprListItem { expr: &mut result };
            let mut results = ExprList { count: 1, capacity: 1, cursor: 0, items: &mut item };
            let mut select = Select { expressions: &mut results };
            let mut comparison = expr(0);
            comparison.left = &mut left;
            comparison.select = &mut select;
            assert_eq!(expr_comparison_affinity(&mut comparison), b'e');
        }
    }

    #[test]
    fn returns_left_or_none_without_a_right_or_select_operand() {
        unsafe {
            let mut left = expr(b'a');
            let mut comparison = expr(0);
            comparison.left = &mut left;
            assert_eq!(expr_comparison_affinity(&mut comparison), b'a');

            left.affinity = 0;
            assert_eq!(expr_comparison_affinity(&mut comparison), b'b');
        }
    }
}
