//! The span merge — how a token-less expression node remembers which
//! slice of the source text its whole subtree came from.
//!
//! - `expr_span` — original: `FUN_0837894c` @ 0x0837894c (96 bytes;
//!   5 `bl` call sites, binary-scanned: one in
//!   [`expr_new`](super::expr_new) @ 0x08376894, the other four in the
//!   0x0839a grammar-action block). SQLite 3.5.x's `sqlite3ExprSpan`.
//!
//! Algorithm: given the node and the spans of its two operands, make
//! the node's span cover both children. A NULL node, or a NULL `z` in
//! either child span, is a no-op (the predicated `cmp`/`ldrne`/`bxeq`
//! chain — the node's span keeps whatever the caller left there; for
//! `expr_new` that is the allocator's zeroes). If either child span is
//! heap-owned (`dyn`, bit 0 of the packed `n:31|dyn:1` word at +0x04),
//! the merged span cannot safely point into text the children will
//! free, so only `span.z` (+0x1c) is NULLed and the packed word at
//! +0x20 is left alone. Otherwise `span.z` becomes the left child's
//! `z` and the packed word becomes
//! `(right.z - left.z + right.n) << 1` OR'd with the node's previous
//! `dyn` bit — the one flag the merge preserves from the old span.
//!
//! ```text
//! 0837894c:  cmp  r0,#0               ; node NULL?
//!            ldrne r3,[r2,#0]         ; right->z ...
//!            ldrne r3,[r1,#0]         ; ... then left->z (kept in r3)
//! 08378960:  bxeq lr                  ; any NULL: leave the node alone
//! 08378964:  tst  [r1,#4],#1          ; left span dyn?
//!            tsteq [r2,#4],#1         ; right span dyn?
//! 08378974:  strne #0,[r0,#0x1c]      ; dyn: span.z = NULL, n_dyn kept
//! 08378980:  str  r3,[r0,#0x1c]       ; span.z = left->z
//!            r1 = right->z - left->z + (right->n_dyn >> 1)
//! 08378998:  r2 = [r0,#0x20] & 1      ; keep the node's own dyn bit
//! 083789a4:  str  r2 | (r1 << 1),[r0,#0x20]
//! ```
//!
//! `Expr`/`Token` fields used (pinned by the original's
//! `ldr/str [rX, #off]` sequence; the full layout is documented in
//! `sqlite/expr_new.rs`):
//!
//! ```text
//! Expr:  +0x1c span (Token)
//! Token: +0x00 z, +0x04 packed `n:31 | dyn:1` (dyn in bit 0)
//! ```
//!
//! Deviations:
//! - The structs are [`expr_new`](super::expr_new)'s own typed
//!   `#[repr(C)]` `Expr`/`Token` — the caller hands the node and the
//!   two `&child->span` addresses straight through, so no new layout
//!   is introduced here (the 32-bit offset asserts live in
//!   `expr_new.rs`).
//! - Ghidra's decompile invents a fourth parameter (`param_4`, reused
//!   as a scratch slot); the original reads r0..r2 only — AAPCS r3 is
//!   dead on entry. The port is three-argument, matching all five
//!   call sites.
//! - The port is the shipped default of
//!   [`expr_new`](super::expr_new)'s `SQLITE_EXPR_SPAN_MERGE` slot,
//!   replacing the documented no-op stub (retained there for host
//!   tests): a token-less node with two spanned operands now gets the
//!   merged span instead of keeping the allocator's zeroes.

use super::expr_new::{Expr, Token};

/// expr_span — original: `FUN_0837894c` @ 0x0837894c (96 bytes; 5 `bl`
/// call sites).
///
/// `sqlite3ExprSpan`: set `expr`'s span to cover both child spans. A
/// NULL node or a NULL `z` in either child span is a no-op. If either
/// child span is heap-owned (`dyn` bit set), only `span.z` is NULLed
/// and the packed word is kept; otherwise `span.z` becomes the left
/// child's `z` and the packed word becomes the covering length
/// (`right.z - left.z + right.n`, in the `n:31` field) with the node's
/// own previous `dyn` bit preserved. Register usage: r0 = expr,
/// r1 = left_span, r2 = right_span. This port is wired as the default
/// of [`super::expr_new`]'s `SQLITE_EXPR_SPAN_MERGE` slot.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn expr_span(
    expr: *mut Expr,
    left_span: *const Token,
    right_span: *const Token,
) {
    if expr.is_null() || (*right_span).z.is_null() || (*left_span).z.is_null() {
        return;
    }
    if (*left_span).n_dyn & 1 != 0 || (*right_span).n_dyn & 1 != 0 {
        (*expr).span.z = core::ptr::null();
        return;
    }
    (*expr).span.z = (*left_span).z;
    let n = ((*right_span).z as usize)
        .wrapping_sub((*left_span).z as usize) as u32;
    let n = n.wrapping_add((*right_span).n_dyn >> 1);
    (*expr).span.n_dyn = ((*expr).span.n_dyn & 1) | (n << 1);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    /// A scratch node big enough for the widened host `Expr`; only the
    /// `span` field is ever touched, so a plain byte arena does.
    #[repr(align(16))]
    struct NodeBuf([u8; 128]);

    fn node(buf: &mut NodeBuf) -> *mut Expr {
        buf.0.as_mut_ptr() as *mut Expr
    }

    static TEXT: &[u8; 16] = b"SELECT a+b FROM ";

    #[test]
    fn a_null_expr_is_a_no_op() {
        let left = Token { z: TEXT.as_ptr(), n_dyn: 3 << 1 };
        let right = Token { z: unsafe { TEXT.as_ptr().add(4) }, n_dyn: 4 << 1 };
        unsafe { expr_span(core::ptr::null_mut(), &left, &right) };
    }

    #[test]
    fn a_null_child_z_leaves_the_span_untouched() {
        let sentinel = Token { z: 0x11111111 as *const u8, n_dyn: 0x22222222 };
        let spanned = Token { z: TEXT.as_ptr(), n_dyn: 3 << 1 };
        let null_z = Token { z: core::ptr::null(), n_dyn: 4 << 1 };

        // NULL right->z (checked first by the original's ldr chain).
        let mut buf = NodeBuf([0; 128]);
        let expr = node(&mut buf);
        unsafe {
            (*expr).span = sentinel;
            expr_span(expr, &spanned, &null_z);
            assert_eq!((*expr).span.z, sentinel.z);
            assert_eq!((*expr).span.n_dyn, sentinel.n_dyn);
        }

        // NULL left->z.
        let mut buf2 = NodeBuf([0; 128]);
        let expr2 = node(&mut buf2);
        unsafe {
            (*expr2).span = sentinel;
            expr_span(expr2, &null_z, &spanned);
            assert_eq!((*expr2).span.z, sentinel.z);
            assert_eq!((*expr2).span.n_dyn, sentinel.n_dyn);
        }
    }

    #[test]
    fn a_dyn_child_nulls_only_the_span_z() {
        let plain = Token { z: TEXT.as_ptr(), n_dyn: 3 << 1 };
        let owned = Token { z: unsafe { TEXT.as_ptr().add(4) }, n_dyn: (4 << 1) | 1 };

        // Left child heap-owned: checked first (`tst [r1,#4],#1`).
        let mut buf = NodeBuf([0; 128]);
        let expr = node(&mut buf);
        unsafe {
            (*expr).span = Token { z: 0x11111111 as *const u8, n_dyn: 0x22222222 };
            expr_span(expr, &owned, &plain);
            assert!((*expr).span.z.is_null(), "dyn left: only the z is cleared");
            assert_eq!((*expr).span.n_dyn, 0x22222222, "the packed word is left alone");
        }

        // Right child heap-owned.
        let mut buf2 = NodeBuf([0; 128]);
        let expr2 = node(&mut buf2);
        unsafe {
            (*expr2).span = Token { z: 0x33333333 as *const u8, n_dyn: 0x44444444 };
            expr_span(expr2, &plain, &owned);
            assert!((*expr2).span.z.is_null(), "dyn right: only the z is cleared");
            assert_eq!((*expr2).span.n_dyn, 0x44444444);
        }
    }

    #[test]
    fn the_merge_covers_both_child_spans() {
        // Left covers TEXT[1..4] (n = 3), right covers TEXT[6..9] (n = 3):
        // the parent span starts at TEXT[1] and runs to TEXT[9], n = 8.
        let left = Token { z: unsafe { TEXT.as_ptr().add(1) }, n_dyn: 3 << 1 };
        let right = Token { z: unsafe { TEXT.as_ptr().add(6) }, n_dyn: 3 << 1 };
        let mut buf = NodeBuf([0; 128]);
        let expr = node(&mut buf);
        unsafe {
            (*expr).span = Token { z: core::ptr::null(), n_dyn: 0 };
            expr_span(expr, &left, &right);
            assert_eq!((*expr).span.z, TEXT.as_ptr().add(1), "the span starts at the left child's text");
            assert_eq!((*expr).span.n_dyn, 8 << 1, "right.z + right.n - left.z = 6 + 3 - 1 = 8, dyn clear");
        }
    }

    #[test]
    fn the_nodes_own_dyn_bit_survives_the_merge() {
        let left = Token { z: TEXT.as_ptr(), n_dyn: 3 << 1 };
        let right = Token { z: unsafe { TEXT.as_ptr().add(4) }, n_dyn: 4 << 1 };
        let mut buf = NodeBuf([0; 128]);
        let expr = node(&mut buf);
        unsafe {
            (*expr).span = Token { z: core::ptr::null(), n_dyn: 1 };
            expr_span(expr, &left, &right);
            assert_eq!((*expr).span.z, TEXT.as_ptr());
            assert_eq!(
                (*expr).span.n_dyn,
                (8 << 1) | 1,
                "right.z + right.n - left.z = 4 + 4 = 8, the old dyn bit is OR'd back in"
            );
        }
    }
}
