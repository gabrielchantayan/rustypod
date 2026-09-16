//! expr_function — original: `FUN_08377f10` @ 0x08377f10 (96 bytes;
//! 4 `bl` call sites).
//!
//! `sqlite3ExprFunction`: build a `TK_FUNCTION` expression node for a
//! function-call grammar action. The database handle is re-loaded from
//! `parse +0x00` before the allocation (`ldr r0,[r0]`); 0x44 bytes are
//! requested from `db_malloc_zero` @ 0x08374998. On allocation failure
//! the argument list is released through `expr_list_delete` @
//! 0x08378670 and NULL is returned. Otherwise the node gets opcode
//! 0x94 (`TK_FUNCTION` in this build), the argument list is linked at
//! +0x10, and the name token's two words (`z`, packed `n`/`dyn`) are
//! copied into both the token (+0x14/+0x18) and the span
//! (+0x1c/+0x20) — the original's `ldmia r6,{r0,r1}` followed by two
//! store pairs, so the token is copied verbatim, ownership bit and
//! all. The cached height is then recomputed through the ported
//! [`expr_set_height`] and the node returned.
//!
//! All four callers are unconditional `bl`s inside the parser's
//! grammar-action block (0x0839aa10, 0x0839aa54, 0x0839aa6c,
//! 0x0839ab30); a whole-image scan shows no predicated BL or tail-B
//! forms. The three direct callees were already ported, so no dispatch
//! seam was added — the Rust port calls them directly, matching the
//! original's direct `bl`s.
//!
//! Raw listing:
//!
//! ```text
//! 08377f10:  stmdb sp!,{r4,r5,r6,lr}
//! 08377f14:  mov r5,r1            ; list
//! 08377f18:  ldr r0,[r0,#0x0]     ; db = parse->db
//! 08377f1c:  mov r1,#0x44
//! 08377f20:  mov r6,r2            ; token
//! 08377f24:  bl 0x08374998        ; db_malloc_zero
//! 08377f28:  movs r4,r0
//! 08377f2c:  bne 0x08377f40
//! 08377f30:  mov r0,r5
//! 08377f34:  bl 0x08378670        ; expr_list_delete
//! 08377f38:  mov r0,#0x0
//! 08377f3c:  ldmia sp!,{r4,r5,r6,pc}
//! 08377f40:  mov r0,#0x94
//! 08377f44:  strb r0,[r4,#0x0]    ; op = TK_FUNCTION
//! 08377f48:  str r5,[r4,#0x10]    ; p_list = list
//! 08377f4c:  ldmia r6,{r0,r1}     ; token.z, token.n_dyn
//! 08377f50:  str r0,[r4,#0x14]
//! 08377f54:  str r1,[r4,#0x18]    ; token = *token
//! 08377f58:  str r0,[r4,#0x1c]
//! 08377f5c:  mov r0,r4
//! 08377f60:  str r1,[r4,#0x20]    ; span = *token
//! 08377f64:  bl 0x083788fc        ; expr_set_height
//! 08377f68:  mov r0,r4
//! 08377f6c:  ldmia sp!,{r4,r5,r6,pc}
//! ```
//!
//! Layout note: `p_list` must land where [`expr_set_height`] reads it,
//! so on a 64-bit test host the pointer fields widen exactly like
//! `sqlite/expr_height.rs`'s `Expr` (`p_left` +0x08, `p_right` +0x10,
//! `p_list` +0x18) and the widened token/span pairs fill its
//! +0x14..+0x38 gap. Only the 32-bit offsets are asserted — they are
//! the original's.

use super::expr_height::expr_set_height;
use super::expr_list_delete::expr_list_delete;
use super::expr_new::{Token, EXPR_SIZE};
use super::mem::db_malloc_zero;

/// This build's `TK_FUNCTION` opcode byte (original: `mov r0,#0x94`).
pub const TK_FUNCTION: u8 = 0x94;

/// An expression node (`sqlite3Expr`), only the fields this
/// constructor touches. See the module header's layout note for the
/// 64-bit widening; `sqlite/expr_height.rs` documents the full node.
#[repr(C)]
pub struct Expr {
    /// +0x00: opcode (`TK_*`); the original stores `op`'s low byte.
    pub op: u8,
    /// +0x01..+0x08: affinity, flags, `i_table` — unmodeled.
    pub _gap_01: [u8; 0x08 - 0x01],
    /// +0x08: left operand — unmodeled (`expr_height::Expr`).
    pub _gap_left: *mut u8,
    /// +0x0c: right operand — unmodeled.
    pub _gap_right: *mut u8,
    /// +0x10: argument list (`ExprList *`, may be NULL).
    pub p_list: *mut u8,
    /// +0x14: the function-name token.
    pub token: Token,
    /// +0x1c: the source span (a verbatim copy of the token here).
    pub span: Token,
    /// +0x24..+0x44: `p_select` +0x38 and `n_height` +0x40 — unmodeled
    /// here (see `sqlite/expr_height.rs`). 32-bit target layout.
    #[cfg(target_pointer_width = "32")]
    pub _gap_24: [u8; 0x44 - 0x24],
    /// The rest of the node on a 64-bit host — covers
    /// `expr_height::Expr`'s widened `p_select` (+0x48) and
    /// `n_height` (+0x54).
    #[cfg(target_pointer_width = "64")]
    pub _gap_40: [u8; 0x58 - 0x40],
}

// The original's byte offsets, asserted on the 32-bit target. On a
// 64-bit host the pointer fields widen and these shift — harmless,
// because all access goes through the typed structs.
#[cfg(target_pointer_width = "32")]
const _EXPR_OP_OFFSET: [u8; 0x00] = [0; core::mem::offset_of!(Expr, op)];
#[cfg(target_pointer_width = "32")]
const _EXPR_P_LIST_OFFSET: [u8; 0x10] = [0; core::mem::offset_of!(Expr, p_list)];
#[cfg(target_pointer_width = "32")]
const _EXPR_TOKEN_OFFSET: [u8; 0x14] = [0; core::mem::offset_of!(Expr, token)];
#[cfg(target_pointer_width = "32")]
const _EXPR_SPAN_OFFSET: [u8; 0x1c] = [0; core::mem::offset_of!(Expr, span)];
#[cfg(target_pointer_width = "32")]
const _EXPR_SIZE_CHECK: [u8; 0x44] = [0; core::mem::size_of::<Expr>()];

/// expr_function — original: `FUN_08377f10` @ 0x08377f10 (96 bytes;
/// 4 `bl` call sites).
///
/// `sqlite3ExprFunction`: build a `TK_FUNCTION` node. `db` is loaded
/// from `parse +0x00`; `parse` itself is dereferenced without a NULL
/// guard. On allocation failure the argument list is released through
/// the ported [`expr_list_delete`] and NULL is returned. Otherwise the
/// node is initialized (opcode [`TK_FUNCTION`], argument list, token
/// and span) and its cached height is recomputed through the ported
/// [`expr_set_height`].
///
/// Register usage: r0 = parse, r1 = list, r2 = token.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn expr_function(
    parse: *mut u8,
    list: *mut u8,
    token: *const Token,
) -> *mut u8 {
    let db = *(parse as *mut *mut u8);
    let node = db_malloc_zero(db, EXPR_SIZE) as *mut Expr;
    if node.is_null() {
        expr_list_delete(list);
        return core::ptr::null_mut();
    }
    (*node).op = TK_FUNCTION;
    (*node).p_list = list;
    (*node).token = *token;
    (*node).span = *token;
    expr_set_height(node as *mut super::expr_height::Expr);
    node as *mut u8
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::super::expr_height;
    use super::super::mem::tests::{install_recorder, realloc_log, Connection};
    use super::super::mem::{DB_MEM_OPS, DEFAULT_DB_MEM_OPS};
    use super::*;

    /// A `Parse` stand-in: only the `db` word at +0x00 matters.
    #[repr(C)]
    struct Parse {
        db: *mut u8,
    }

    fn parse_for(db: &mut Connection) -> Parse {
        Parse { db: db.ptr() }
    }

    /// Host arena size: on a 64-bit host the widened `expr_height::Expr`
    /// puts `n_height` past the original's 0x44-byte request, so the
    /// arena must cover the widened struct.
    const ARENA_SIZE: usize = 0x60;

    /// A fresh arena for the recording malloc, aligned for the widened
    /// host struct. The first 0x44 bytes are poisoned so the
    /// allocator's zero-fill stays observable; the widened tail is
    /// pre-zeroed — a NULL `p_select` and a zeroed `n_height`, the
    /// widening-transparent meaning of the original's zeroed block.
    #[repr(align(16))]
    struct Arena([u8; ARENA_SIZE]);

    fn arena() -> Arena {
        assert!(ARENA_SIZE >= core::mem::size_of::<expr_height::Expr>());
        assert!(ARENA_SIZE >= core::mem::size_of::<Expr>());
        let mut a = Arena([0xa5u8; ARENA_SIZE]);
        for b in &mut a.0[EXPR_SIZE as usize..] {
            *b = 0;
        }
        a
    }

    /// Puts the allocator's documented always-fails stubs back (the
    /// recording malloc is only ever installed under `OPS_LOCK`).
    unsafe fn restore_mem_defaults() {
        core::ptr::write_volatile(core::ptr::addr_of_mut!(DB_MEM_OPS), DEFAULT_DB_MEM_OPS);
    }

    #[test]
    fn the_node_gets_the_list_and_the_token_becomes_both_token_and_span() {
        let mut buf = arena();
        let _ops = install_recorder(buf.0.as_mut_ptr());
        let mut db = Connection::healthy();
        let mut parse = parse_for(&mut db);
        let text = b"length";
        let token = Token { z: text.as_ptr(), n_dyn: 6 << 1 };
        // A real one-item argument list: the height fold walks it, so
        // the node must end up one above the child's cached height.
        let mut arg = expr_height::Expr {
            _gap_00: [0; 0x08],
            p_left: core::ptr::null_mut(),
            p_right: core::ptr::null_mut(),
            p_list: core::ptr::null_mut(),
            _gap_14: [0; 0x38 - 0x14],
            p_select: core::ptr::null_mut(),
            _gap_3c: [0; 0x40 - 0x3c],
            n_height: 5,
        };
        let mut items = [super::super::expr_list_height::ExprListItem {
            p_expr: &mut arg as *mut expr_height::Expr as *mut u8,
            _gap_04: [0; 0x0c - 0x04],
        }];
        let mut list = super::super::expr_list_height::ExprList {
            n_expr: 1,
            _gap_04: [0; 0x0c - 0x04],
            items: items.as_mut_ptr(),
        };
        let list_ptr = &mut list as *mut super::super::expr_list_height::ExprList as *mut u8;

        let raw = unsafe {
            expr_function(
                (&mut parse as *mut Parse).cast(),
                list_ptr,
                &token as *const Token,
            )
        };

        assert_eq!(raw, buf.0.as_mut_ptr(), "the allocator's block is the node");
        assert_eq!(realloc_log(), std::vec![(0, EXPR_SIZE)]);
        let node = unsafe { &*(raw as *const Expr) };
        assert_eq!(node.op, TK_FUNCTION);
        assert_eq!(node.p_list, list_ptr);
        assert_eq!(node.token.z, text.as_ptr());
        assert_eq!(node.token.n_dyn, 6 << 1);
        assert_eq!(node.span.z, text.as_ptr(), "span = token, verbatim");
        assert_eq!(node.span.n_dyn, 6 << 1);
        assert_eq!(
            unsafe { (*(raw as *const expr_height::Expr)).n_height },
            6,
            "the fold sees the linked list: max(5) + 1"
        );
        assert_eq!(db.failed_flag(), 0);
        unsafe { restore_mem_defaults() };
    }

    #[test]
    fn the_ownership_bit_is_copied_verbatim() {
        let mut buf = arena();
        let _ops = install_recorder(buf.0.as_mut_ptr());
        let mut db = Connection::healthy();
        let mut parse = parse_for(&mut db);
        let text = b"max";
        let token = Token { z: text.as_ptr(), n_dyn: (3 << 1) | 1 };

        let raw = unsafe {
            expr_function((&mut parse as *mut Parse).cast(), core::ptr::null_mut(), &token)
        };

        let node = unsafe { &*(raw as *const Expr) };
        assert_eq!(node.token.n_dyn, (3 << 1) | 1, "ldmia/str copies both words as-is");
        assert_eq!(node.span.n_dyn, (3 << 1) | 1);
        unsafe { restore_mem_defaults() };
    }

    #[test]
    fn the_cached_height_is_recomputed_from_the_children() {
        let mut buf = arena();
        let _ops = install_recorder(buf.0.as_mut_ptr());
        let mut db = Connection::healthy();
        let mut parse = parse_for(&mut db);
        let token = Token { z: core::ptr::null(), n_dyn: 0 };

        let raw = unsafe {
            expr_function((&mut parse as *mut Parse).cast(), core::ptr::null_mut(), &token)
        };

        // No operands, no list, no select: the fold's maximum stays 0
        // and the node's own height becomes 1.
        assert_eq!(unsafe { (*(raw as *const expr_height::Expr)).n_height }, 1);
        unsafe { restore_mem_defaults() };
    }

    #[test]
    fn oom_releases_the_list_and_returns_null() {
        let _ops = install_recorder(core::ptr::null_mut());
        let mut db = Connection::healthy();
        let mut parse = parse_for(&mut db);
        let token = Token { z: b"f".as_ptr(), n_dyn: 1 << 1 };

        // A NULL argument list: the destructor's `movs/ldmiaeq` early
        // return makes the release a no-op, so the observable contract
        // is the NULL return after the failed 0x44-byte request.
        let raw = unsafe {
            expr_function((&mut parse as *mut Parse).cast(), core::ptr::null_mut(), &token)
        };

        assert!(raw.is_null());
        assert_eq!(realloc_log(), std::vec![(0, EXPR_SIZE)]);
        assert_eq!(db.failed_flag(), 1, "the failed allocation latches the sticky flag");
        unsafe { restore_mem_defaults() };
    }
}
