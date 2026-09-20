//! SQLite expression-affinity comparison.

use super::expr_affinity::{expr_affinity, Expr};

const AFFINITY_NONE: u8 = b'b';
const AFFINITY_NUMERIC: u8 = b'c';

/// `expr_compare_affinity` — original: `FUN_083735b8` @ `0x083735b8` (68
/// bytes, `0x083735b8..0x083735fb`; the next independent entry is
/// `0x083735fc`). Raw ARM decoding finds one plain outbound `bl`
/// (`expr_affinity` @ `0x083768e0`) and zero predicated `bl`; it has three
/// direct inbound `bl` call sites. SQLite 3.5.9's `sqlite3CompareAffinity`:
/// return the sole nonzero affinity when either side has none, the shared
/// affinity when equal, numeric when either nonzero affinity is numeric or
/// stronger, and none for text/blob disagreement. Deliberate deviation: none.
///
/// # Safety
/// `left` must name a valid SQLite expression accepted by `expr_affinity`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn expr_compare_affinity(left: *mut Expr, right_affinity: u8) -> u8 {
    let left_affinity = expr_affinity(left);

    if left_affinity == 0 || right_affinity == 0 {
        if left_affinity != 0 || right_affinity != 0 {
            left_affinity.wrapping_add(right_affinity)
        } else {
            AFFINITY_NONE
        }
    } else if left_affinity >= AFFINITY_NUMERIC || right_affinity >= AFFINITY_NUMERIC {
        AFFINITY_NUMERIC
    } else {
        AFFINITY_NONE
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    unsafe fn expr(affinity: u8) -> Expr {
        let mut expr: Expr = core::mem::zeroed();
        expr.affinity = affinity;
        expr
    }

    unsafe fn compare(left_affinity: u8, right_affinity: u8) -> u8 {
        let mut left = expr(left_affinity);
        expr_compare_affinity(core::ptr::addr_of_mut!(left), right_affinity)
    }

    #[test]
    fn returns_none_for_absent_or_disagreeing_non_numeric_affinities() {
        unsafe {
            assert_eq!(compare(0, 0), b'b');
            assert_eq!(compare(b'a', 0), b'a');
            assert_eq!(compare(0, b'e'), b'e');
            assert_eq!(compare(b'a', b'b'), b'b');
        }
    }

    #[test]
    fn preserves_equal_affinity_and_promotes_numeric_pairs() {
        unsafe {
            assert_eq!(compare(b'a', b'a'), b'b');
            assert_eq!(compare(b'b', b'b'), b'b');
            assert_eq!(compare(b'e', b'e'), b'c');
            assert_eq!(compare(b'a', b'd'), b'c');
            assert_eq!(compare(b'b', b'c'), b'c');
        }
    }
}
