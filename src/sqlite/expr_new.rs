//! The expression constructor — how grammar actions turn an opcode and
//! two subtrees into a linked, span-annotated `Expr` node.
//!
//! - `expr_new` — original: `FUN_08376808` @ 0x08376808 (216 bytes;
//!   6 `bl` call sites, binary-scanned). SQLite 3.5.x's `sqlite3Expr`.
//!
//! Algorithm: allocate a zeroed 0x44-byte `Expr` on the connection
//! through `sqlite3DbMallocZero` @ 0x08374998 (ported as
//! [`db_malloc_zero`](super::mem::db_malloc_zero), called directly). On
//! failure, release both operands through the expression destructor
//! @ 0x08377e00 (ported as [`expr_delete`](super::expr_delete::expr_delete),
//! reached through the [`SQLITE_EXPR_DELETE`] slot) and return NULL —
//! SQLite's OOM unwinding: the sticky
//! `db->mallocFailed` byte is already set by the allocator, so every
//! later allocation on the connection short-circuits. On success, store
//! the opcode's low byte at +0x00, seed `iAgg` at +0x30 to -1 and link
//! the operands at +0x08/+0x0c. With a token, copy its two words into
//! BOTH the token (+0x14/+0x18) and the span (+0x1c/+0x20). Without
//! one, but with both operands, merge the child spans through the
//! helper @ 0x0837894c and propagate `EP_CombBound` — the right child's
//! flags/iTable first (only inside the both-operands branch), then the
//! left child's (whenever `left` is non-NULL), so a doubly-flagged join
//! keeps the LEFT child's iTable. Finish by recomputing the cached tree
//! height through `sqlite3ExprSetHeight` @ 0x083788fc (ported as
//! [`expr_set_height`](super::expr_height::expr_set_height), called
//! directly):
//!
//! ```text
//! 08376808:  stmdb sp!,{r4,r5,r6,r7,r8,lr}
//!            r8 = op, r7 = token (5th arg), r5 = left, r6 = right
//! 08376820:  bl   0x08374998          ; db_malloc_zero(db, 0x44)
//! 08376828:  bne  0x08376844
//!            ; OOM: expr_delete(left); expr_delete(right); return 0
//! 08376830:  bl   0x08377e00
//! 08376838:  bl   0x08377e00
//! 08376844:  strb r8,[r4,#0x0]        ; node->op = op (low byte)
//!            str  -1,[r4,#0x30]       ; node->iAgg = -1 (mvn r0,#0)
//!            str  left/right at +0x08/+0x0c
//! 08376854:  cmp  r7,#0x0
//! 08376860:  ldmia r7,{r1,r2}         ; token path: span = token = *token
//!            str  r1/r2 at +0x14/+0x18 AND +0x1c/+0x20
//! 08376878:  ; no token: if left && right ->
//! 08376894:  bl   0x0837894c          ; span merge (node, &left->span, &right->span)
//!            tst right->flags,#0x100  ; EP_CombBound from the right...
//!            tst left->flags,#0x100   ; ... then from the left
//! 083768d4:  bl   0x083788fc          ; expr_set_height(node)
//! ```
//!
//! `Expr` and `Token` fields used (all pinned by this function's and
//! the span-merge helper's `ldr/str [rX, #off]` sequences and
//! cross-checked against the SQLite 3.5.x sources; the node is the
//! 0x44-byte allocation — see `sqlite/expr_height.rs` for the height
//! fields):
//!
//! ```text
//! Expr:  +0x00 op (u8), +0x01 affinity, +0x02 flags (u16, EP_*),
//!        +0x04 i_table (i32), +0x08 p_left, +0x0c p_right,
//!        +0x10 p_list, +0x14 token (Token), +0x1c span (Token),
//!        +0x30 i_agg (i32), +0x38 p_select, +0x40 n_height
//! Token: +0x00 z (*const u8), +0x04 packed `n:31 | dyn:1`
//!        (dyn in bit 0: `tst rX,#1`; length recovered by `lsr #1`)
//! ```
//!
//! Deviations:
//! - The expression destructor @ 0x08377e00 (88 bytes; 34 `bl` call
//!   sites) is ported as
//!   [`expr_delete`](super::expr_delete::expr_delete) and is the
//!   shipped default of the [`SQLITE_EXPR_DELETE`] dispatch boundary
//!   (house pattern — see `sqlite/error_msg.rs`). Its own list/select
//!   teardown stays behind `sqlite/expr_delete.rs`'s no-op-default
//!   slots. The documented no-op stub [`missing_expr_delete`] is
//!   retained for host tests (an OOM then *leaks* the two operands
//!   instead of releasing them — the NULL return the caller sees is
//!   unchanged); with the shipped default the OOM path really releases
//!   both operands, like the original.
//! - The span-merge helper @ 0x0837894c (96 bytes; 5 `bl` call sites,
//!   the other four in the 0x0839a block) is ported as
//!   [`expr_span`](super::expr_span::expr_span) and is the shipped
//!   default of the [`SQLITE_EXPR_SPAN_MERGE`] dispatch boundary. The
//!   documented no-op stub [`missing_span_merge`] is retained for host
//!   tests (with it installed the node's span keeps the zeroes
//!   `db_malloc_zero` wrote — identical to the original's early return
//!   whenever either child's `span.z` is NULL); with the shipped
//!   default the node gets the merged span, like the original.
//! - `Expr`/`Token` are typed `#[repr(C)]` structs rather than raw byte
//!   offsets, so the pointer fields stay disjoint on a 64-bit test
//!   host. The original byte offsets are statically asserted on 32-bit
//!   targets (`_EXPR_*_OFFSET` / `_TOKEN_*_OFFSET`). The `token`
//!   argument crosses the ABI as `*const u8` (the
//!   [`ExprNewFn`](super::parse_expr::ExprNewFn) signature the
//!   parse_expr adaptor forwards) and is cast to `*const Token`
//!   inside. On a 64-bit host the constructor's `i_agg`
//!   word keeps a `cfg`-split home in `expr_height::Expr`'s widened
//!   gap (the node is handed straight to [`expr_set_height`]; at the
//!   original's +0x30 it would land under the widened `p_select`) —
//!   see the [`Expr`] layout note.

use super::expr_height::expr_set_height;
use super::mem::db_malloc_zero;

/// Size of the original's allocation (original: `mov r1,#0x44`).
pub const EXPR_SIZE: i32 = 0x44;

/// The `EP_CombBound` property flag: the expression was combined from
/// terms bound to one table cursor (`i_table`); propagated from the
/// children to the parent (original: `tst rX,#0x100` on the +0x02
/// flags halfword).
pub const EP_COMB_BOUND: u16 = 0x100;

/// A parser token (`sqlite3Token`): text pointer plus a packed
/// length/ownership word. See the module header for the bit layout.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Token {
    /// +0x00: token text — not NUL-terminated, not necessarily owned.
    pub z: *const u8,
    /// +0x04: length in bits 1..=31, ownership (`dyn`) flag in bit 0.
    pub n_dyn: u32,
}

/// An expression node (`sqlite3Expr`), only the fields this constructor
/// touches. The full layout is documented in the module header; the
/// height fields (+0x38/+0x40) live behind the gap and are modeled by
/// `sqlite/expr_height.rs`'s own `Expr`.
///
/// Layout note: the constructor hands the node straight to
/// [`expr_set_height`], so on a 64-bit test host this struct must agree
/// with `expr_height::Expr`'s *widened* layout — `p_left`/`p_right` at
/// +0x08/+0x10 on both, and nothing this constructor writes may land
/// under its widened `p_list` (+0x18), `p_select` (+0x48) or
/// `n_height` (+0x54). The widened `token`/`span` pairs fit its gap
/// exactly; `i_agg`, a plain 4-byte word at +0x30 on the target, is
/// the one field that cannot keep its original byte offset (on the
/// host +0x30 sits inside the widened `span`), so its placement is
/// `cfg`-split: target offset +0x30 on 32-bit, the gap word right
/// after `span` on 64-bit. Only the 32-bit offsets are asserted —
/// they are the original's.
#[repr(C)]
pub struct Expr {
    /// +0x00: opcode (`TK_*`); the original stores `op`'s low byte.
    pub op: u8,
    /// +0x01: affinity — unmodeled.
    pub _gap_01: u8,
    /// +0x02: `EP_*` property flags; bit 0x100 is [`EP_COMB_BOUND`].
    pub flags: u16,
    /// +0x04: the table cursor an `EP_CombBound` term is bound to.
    pub i_table: i32,
    /// +0x08: left operand (`Expr *`, may be NULL).
    pub p_left: *mut u8,
    /// +0x0c: right operand (`Expr *`, may be NULL).
    pub p_right: *mut u8,
    /// +0x10..+0x14: `p_list` — unmodeled.
    pub _gap_10: [u8; 0x14 - 0x10],
    /// +0x14: the token this node was built from (zero when built from
    /// subtrees alone).
    pub token: Token,
    /// +0x1c: the source span covering the whole subtree.
    pub span: Token,
    /// +0x24..+0x30: unmodeled (32-bit target layout).
    #[cfg(target_pointer_width = "32")]
    pub _gap_24: [u8; 0x30 - 0x24],
    /// +0x30: aggregate index, seeded to -1 ("not an aggregate") by the
    /// constructor. See the struct's layout note for the 64-bit home.
    #[cfg(target_pointer_width = "32")]
    pub i_agg: i32,
    /// +0x34..+0x44: `p_select` +0x38 and `n_height` +0x40 — unmodeled
    /// here (see `sqlite/expr_height.rs`). 32-bit target layout.
    #[cfg(target_pointer_width = "32")]
    pub _gap_34: [u8; 0x44 - 0x34],
    /// 64-bit host home of the aggregate index (see the layout note):
    /// the gap word right after the widened `span`, clear of
    /// `expr_height::Expr`'s widened `p_select`/`n_height`.
    #[cfg(target_pointer_width = "64")]
    pub i_agg: i32,
    /// The rest of the node on a 64-bit host — covers
    /// `expr_height::Expr`'s widened `p_select` and `n_height`.
    #[cfg(target_pointer_width = "64")]
    pub _gap_44: [u8; 88 - 68],
}

// The original's byte offsets, asserted on the 32-bit target. On a
// 64-bit host the pointer fields widen and these shift — harmless,
// because all access goes through the typed structs.
#[cfg(target_pointer_width = "32")]
const _EXPR_OP_OFFSET: [u8; 0x00] = [0; core::mem::offset_of!(Expr, op)];
#[cfg(target_pointer_width = "32")]
const _EXPR_FLAGS_OFFSET: [u8; 0x02] = [0; core::mem::offset_of!(Expr, flags)];
#[cfg(target_pointer_width = "32")]
const _EXPR_I_TABLE_OFFSET: [u8; 0x04] = [0; core::mem::offset_of!(Expr, i_table)];
#[cfg(target_pointer_width = "32")]
const _EXPR_P_LEFT_OFFSET: [u8; 0x08] = [0; core::mem::offset_of!(Expr, p_left)];
#[cfg(target_pointer_width = "32")]
const _EXPR_P_RIGHT_OFFSET: [u8; 0x0c] = [0; core::mem::offset_of!(Expr, p_right)];
#[cfg(target_pointer_width = "32")]
const _EXPR_TOKEN_OFFSET: [u8; 0x14] = [0; core::mem::offset_of!(Expr, token)];
#[cfg(target_pointer_width = "32")]
const _EXPR_SPAN_OFFSET: [u8; 0x1c] = [0; core::mem::offset_of!(Expr, span)];
#[cfg(target_pointer_width = "32")]
const _EXPR_I_AGG_OFFSET: [u8; 0x30] = [0; core::mem::offset_of!(Expr, i_agg)];
#[cfg(target_pointer_width = "32")]
const _EXPR_SIZE_CHECK: [u8; 0x44] = [0; core::mem::size_of::<Expr>()];
#[cfg(target_pointer_width = "32")]
const _TOKEN_Z_OFFSET: [u8; 0x00] = [0; core::mem::offset_of!(Token, z)];
#[cfg(target_pointer_width = "32")]
const _TOKEN_N_DYN_OFFSET: [u8; 0x04] = [0; core::mem::offset_of!(Token, n_dyn)];

/// The expression destructor: `sqlite3ExprDelete(expr)` @ 0x08377e00.
/// Recursively releases a subtree; NULL is a no-op (the original's
/// `movs/ldmiaeq` early return).
pub type ExprDeleteFn = unsafe extern "C" fn(expr: *mut u8);

/// Default stub retained for host tests: no destructor wired, so the
/// operand release is skipped — an OOM leaks the subtrees instead of
/// freeing them; the NULL the caller sees is unchanged (see the module
/// header). The shipped default is the real port,
/// [`super::expr_delete::expr_delete`].
pub(crate) unsafe extern "C" fn missing_expr_delete(_expr: *mut u8) {}

/// The active destructor. The default is the real port,
/// [`super::expr_delete::expr_delete`]; host tests still install
/// recording mocks through the slot ([`missing_expr_delete`] is
/// retained for them).
pub static mut SQLITE_EXPR_DELETE: ExprDeleteFn = super::expr_delete::expr_delete;

/// The span-merge helper @ 0x0837894c: given the new node and the two
/// child spans (`&left->span`, `&right->span` — the `Token` at +0x1c of
/// each child), set the node's span to cover both children, or NULL it
/// when a child span is heap-owned (`dyn`), or leave it alone when a
/// child's `span.z` is NULL.
pub type ExprSpanMergeFn =
    unsafe extern "C" fn(expr: *mut Expr, left_span: *const Token, right_span: *const Token);

/// Default stub retained for host tests: no merge wired, so the node's
/// span keeps the zeroes the allocator wrote — exactly what the
/// original leaves behind when either child's `span.z` is NULL (see the
/// module header). The shipped default is the real port,
/// [`super::expr_span::expr_span`].
pub(crate) unsafe extern "C" fn missing_span_merge(
    _expr: *mut Expr,
    _left_span: *const Token,
    _right_span: *const Token,
) {
}

/// The active span merge. The default is the real port,
/// [`super::expr_span::expr_span`]; host tests still install recording
/// mocks through the slot ([`missing_span_merge`] is retained for
/// them).
pub static mut SQLITE_EXPR_SPAN_MERGE: ExprSpanMergeFn = super::expr_span::expr_span;

/// Reads a dispatch slot (volatile — the slots are meant to be swapped
/// at runtime, and a plain read lets LLVM const-fold the default away).
#[inline(always)]
pub(crate) fn expr_delete_op() -> ExprDeleteFn {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(SQLITE_EXPR_DELETE)) }
}

/// Reads the span-merge slot (volatile — see [`expr_delete_op`]).
#[inline(always)]
pub(crate) fn expr_span_merge_op() -> ExprSpanMergeFn {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(SQLITE_EXPR_SPAN_MERGE)) }
}

/// expr_new — original: `FUN_08376808` @ 0x08376808 (216 bytes; 6 `bl`
/// call sites).
///
/// `sqlite3Expr`: build one expression node. `op` is stored as a byte
/// (the original receives a full register and `strb`s its low half),
/// `i_agg` is seeded to -1 and the operands are linked unconditionally.
/// A non-NULL `token` becomes both the node's token and its span; with
/// no token and both operands present, the child spans are merged
/// (through the [`SQLITE_EXPR_SPAN_MERGE`] slot) and `EP_CombBound`
/// (flags bit 0x100, plus `i_table`) propagates from the right operand
/// first, then — whenever `left` is non-NULL, even if `right` is NULL —
/// from the left operand, so the left one wins a doubly-flagged join.
/// The cached height is recomputed through the ported
/// [`expr_set_height`]. On allocation failure both operands are
/// released through the [`SQLITE_EXPR_DELETE`] slot and NULL is
/// returned.
///
/// Register usage: r0 = db, r1 = op, r2 = left, r3 = right,
/// `[sp]` = token (the AAPCS 5th argument). This is the function the
/// `parse_expr` adaptor tail-calls; it is wired as the default of that
/// module's `SQLITE_EXPR_NEW` slot.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn expr_new(
    db: *mut u8,
    op: i32,
    left: *mut u8,
    right: *mut u8,
    token: *const u8,
) -> *mut u8 {
    let node = db_malloc_zero(db, EXPR_SIZE) as *mut Expr;
    if node.is_null() {
        (expr_delete_op())(left);
        (expr_delete_op())(right);
        return core::ptr::null_mut();
    }
    (*node).op = op as u8;
    (*node).i_agg = -1;
    (*node).p_left = left;
    (*node).p_right = right;
    if !token.is_null() {
        let token = &*(token as *const Token);
        (*node).token = *token;
        (*node).span = *token;
    } else if !left.is_null() {
        if !right.is_null() {
            (expr_span_merge_op())(
                node,
                core::ptr::addr_of!((*(left as *const Expr)).span),
                core::ptr::addr_of!((*(right as *const Expr)).span),
            );
            if (*(right as *const Expr)).flags & EP_COMB_BOUND != 0 {
                (*node).flags |= EP_COMB_BOUND;
                (*node).i_table = (*(right as *const Expr)).i_table;
            }
        }
        if (*(left as *const Expr)).flags & EP_COMB_BOUND != 0 {
            (*node).flags |= EP_COMB_BOUND;
            (*node).i_table = (*(left as *const Expr)).i_table;
        }
    }
    expr_set_height(node as *mut super::expr_height::Expr);
    node as *mut u8
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::super::expr_height;
    use super::super::mem::tests::{install_recorder, Connection};
    use super::super::mem::{DB_MEM_OPS, DEFAULT_DB_MEM_OPS};
    use super::*;
    use std::sync::Mutex;
    use std::vec::Vec;

    /// Serializes access to the delete/span-merge slots across tests.
    static SLOT_LOCK: Mutex<()> = Mutex::new(());

    /// Every operand the recording destructor was asked to release.
    static mut DELETED: Vec<usize> = Vec::new();

    /// (node, left_span, right_span) of every span-merge invocation.
    static mut MERGED: Vec<(usize, usize, usize)> = Vec::new();

    unsafe extern "C" fn recording_expr_delete(expr: *mut u8) {
        (*core::ptr::addr_of_mut!(DELETED)).push(expr as usize);
    }

    unsafe extern "C" fn recording_span_merge(
        expr: *mut Expr,
        left_span: *const Token,
        right_span: *const Token,
    ) {
        (*core::ptr::addr_of_mut!(MERGED)).push((expr as usize, left_span as usize, right_span as usize));
    }

    fn deleted() -> Vec<usize> {
        unsafe { (*core::ptr::addr_of!(DELETED)).clone() }
    }

    fn merged() -> Vec<(usize, usize, usize)> {
        unsafe { (*core::ptr::addr_of!(MERGED)).clone() }
    }

    /// The documented defaults: the real destructor port on the delete
    /// slot, the real span-merge port on the span-merge slot.
    unsafe fn restore_slot_defaults() {
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(SQLITE_EXPR_DELETE),
            super::super::expr_delete::expr_delete,
        );
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(SQLITE_EXPR_SPAN_MERGE),
            super::super::expr_span::expr_span,
        );
    }

    /// Puts the allocator's documented always-fails stubs back (the
    /// recording malloc is only ever installed under `OPS_LOCK`).
    unsafe fn restore_mem_defaults() {
        core::ptr::write_volatile(core::ptr::addr_of_mut!(DB_MEM_OPS), DEFAULT_DB_MEM_OPS);
    }

    /// Installs the given slots, runs `body`, then restores the slot
    /// defaults so a failed assertion cannot leak mocks into the next
    /// test.
    unsafe fn with_slots(delete: ExprDeleteFn, merge: ExprSpanMergeFn, body: impl FnOnce()) {
        (*core::ptr::addr_of_mut!(DELETED)).clear();
        (*core::ptr::addr_of_mut!(MERGED)).clear();
        core::ptr::write_volatile(core::ptr::addr_of_mut!(SQLITE_EXPR_DELETE), delete);
        core::ptr::write_volatile(core::ptr::addr_of_mut!(SQLITE_EXPR_SPAN_MERGE), merge);
        body();
        restore_slot_defaults();
    }

    /// `with_slots`, returning the closure's result.
    unsafe fn with_slots_result<R>(delete: ExprDeleteFn, merge: ExprSpanMergeFn, body: impl FnOnce() -> R) -> R {
        let mut result: Option<R> = None;
        with_slots(delete, merge, || {
            result = Some(body());
        });
        result.unwrap()
    }

    /// A child node as `expr_height`'s `Expr` (the struct whose typed
    /// `n_height` the real height fold reads). The `_gap_00` bytes are
    /// laid out by hand: op at +0x00, flags at +0x02, i_table at +0x04.
    fn child(op: u8, flags: u16, i_table: i32, height: i32) -> expr_height::Expr {
        let mut head = [0u8; 0x08];
        head[0] = op;
        head[2..4].copy_from_slice(&flags.to_ne_bytes());
        head[4..8].copy_from_slice(&i_table.to_ne_bytes());
        expr_height::Expr {
            _gap_00: head,
            p_left: core::ptr::null_mut(),
            p_right: core::ptr::null_mut(),
            p_list: core::ptr::null_mut(),
            _gap_14: [0; 0x38 - 0x14],
            p_select: core::ptr::null_mut(),
            _gap_3c: [0; 0x40 - 0x3c],
            n_height: height,
        }
    }

    /// Host arena size: on a 64-bit host the widened `expr_height::Expr`
    /// puts `p_select`/`n_height` past the original's 0x44-byte request,
    /// so the arena must cover the widened struct.
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
        let mut a = Arena([0xa5u8; ARENA_SIZE]);
        for b in &mut a.0[EXPR_SIZE as usize..] {
            *b = 0;
        }
        a
    }

    fn node_of(raw: *mut u8) -> *const Expr {
        raw as *const Expr
    }

    fn height_of(raw: *mut u8) -> i32 {
        unsafe { (*(raw as *const expr_height::Expr)).n_height }
    }

    #[test]
    fn a_token_becomes_both_the_token_and_the_span() {
        let mut buf = arena();
        let _ops = install_recorder(buf.0.as_mut_ptr());
        let _guard = SLOT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut db = Connection::healthy();
        let text = [b'a', b'b', b'c'];
        let token = Token { z: text.as_ptr(), n_dyn: 3 << 1 };
        let mut left = child(0x61, EP_COMB_BOUND, 7, 3);
        let mut right = child(0x62, EP_COMB_BOUND, 9, 5);

        let raw = unsafe {
            with_slots_result(recording_expr_delete, recording_span_merge, || {
                expr_new(
                    db.ptr(),
                    0x70,
                    &mut left as *mut expr_height::Expr as *mut u8,
                    &mut right as *mut expr_height::Expr as *mut u8,
                    &token as *const Token as *const u8,
                )
            })
        };

        assert_eq!(raw, buf.0.as_mut_ptr(), "the allocator's block is the node");
        let node = unsafe { &*node_of(raw) };
        assert_eq!(node.op, 0x70);
        assert_eq!(node.i_agg, -1, "mvn r0,#0: the aggregate index is seeded to -1");
        assert_eq!(node.p_left, &mut left as *mut expr_height::Expr as *mut u8);
        assert_eq!(node.p_right, &mut right as *mut expr_height::Expr as *mut u8);
        assert_eq!(node.token.z, text.as_ptr());
        assert_eq!(node.token.n_dyn, 3 << 1);
        assert_eq!(node.span.z, text.as_ptr(), "span = token on the token path");
        assert_eq!(node.span.n_dyn, 3 << 1);
        assert_eq!(node.flags, 0, "no EP_CombBound propagation when a token is given");
        assert_eq!(node.i_table, 0);
        assert!(merged().is_empty(), "the span merge is not consulted on the token path");
        assert!(deleted().is_empty(), "nothing is released on success");
        unsafe { restore_mem_defaults() };
    }

    #[test]
    fn the_op_is_stored_as_a_single_byte() {
        let mut buf = arena();
        let _ops = install_recorder(buf.0.as_mut_ptr());
        let _guard = SLOT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut db = Connection::healthy();

        let raw = unsafe {
            with_slots_result(missing_expr_delete, missing_span_merge, || {
                expr_new(db.ptr(), 0x170, core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null())
            })
        };

        assert_eq!(unsafe { (*node_of(raw)).op }, 0x70, "strb: only the low byte lands");
        unsafe { restore_mem_defaults() };
    }

    #[test]
    fn the_span_merge_runs_and_comb_bound_propagates_without_a_token() {
        let mut buf = arena();
        let _ops = install_recorder(buf.0.as_mut_ptr());
        let _guard = SLOT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut db = Connection::healthy();
        let text = *b"SELECT a+b";
        let mut left = child(0x61, 0, 0, 3);
        let mut right = child(0x62, EP_COMB_BOUND, 7, 5);
        // Child spans: left covers text[0..3], right text[4..8].
        unsafe {
            (*(node_of(&mut left as *mut expr_height::Expr as *mut u8) as *mut Expr)).span =
                Token { z: text.as_ptr(), n_dyn: 3 << 1 };
            (*(node_of(&mut right as *mut expr_height::Expr as *mut u8) as *mut Expr)).span =
                Token { z: text.as_ptr().add(4), n_dyn: 4 << 1 };
        }
        let left_span = unsafe { core::ptr::addr_of!((*(node_of(&mut left as *mut expr_height::Expr as *mut u8))).span) };
        let right_span = unsafe { core::ptr::addr_of!((*(node_of(&mut right as *mut expr_height::Expr as *mut u8))).span) };

        let raw = unsafe {
            with_slots_result(recording_expr_delete, recording_span_merge, || {
                expr_new(
                    db.ptr(),
                    0x6b,
                    &mut left as *mut expr_height::Expr as *mut u8,
                    &mut right as *mut expr_height::Expr as *mut u8,
                    core::ptr::null(),
                )
            })
        };

        assert_eq!(
            merged(),
            std::vec![(raw as usize, left_span as usize, right_span as usize)],
            "the merge is handed the node and the two child spans (+0x1c)"
        );
        let node = unsafe { &*node_of(raw) };
        assert_eq!(node.flags, EP_COMB_BOUND, "the right child's flag is inherited");
        assert_eq!(node.i_table, 7, "... with its table cursor");
        unsafe { restore_mem_defaults() };
    }

    #[test]
    fn the_left_child_wins_a_doubly_flagged_join_and_a_null_right_still_sees_left() {
        let mut buf = arena();
        let _ops = install_recorder(buf.0.as_mut_ptr());
        let _guard = SLOT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut db = Connection::healthy();
        let mut left = child(0x61, EP_COMB_BOUND, 5, 3);
        let mut right = child(0x62, EP_COMB_BOUND, 7, 5);

        let raw = unsafe {
            with_slots_result(missing_expr_delete, missing_span_merge, || {
                expr_new(
                    db.ptr(),
                    0x6b,
                    &mut left as *mut expr_height::Expr as *mut u8,
                    &mut right as *mut expr_height::Expr as *mut u8,
                    core::ptr::null(),
                )
            })
        };
        let node = unsafe { &*node_of(raw) };
        assert_eq!(node.flags, EP_COMB_BOUND);
        assert_eq!(node.i_table, 5, "right propagates first, then left overwrites");

        // A NULL right operand skips the merge and the right-flag check,
        // but the left child's EP_CombBound still propagates.
        let mut buf2 = arena();
        unsafe { core::ptr::write(core::ptr::addr_of_mut!(super::super::mem::tests::REALLOC_RESULT), buf2.0.as_mut_ptr()) };
        let mut left2 = child(0x61, EP_COMB_BOUND, 11, 2);
        let raw2 = unsafe {
            with_slots_result(missing_expr_delete, recording_span_merge, || {
                expr_new(
                    db.ptr(),
                    0x6b,
                    &mut left2 as *mut expr_height::Expr as *mut u8,
                    core::ptr::null_mut(),
                    core::ptr::null(),
                )
            })
        };
        assert!(merged().is_empty(), "no right operand: the merge is skipped");
        let node2 = unsafe { &*node_of(raw2) };
        assert_eq!(node2.flags, EP_COMB_BOUND);
        assert_eq!(node2.i_table, 11);
        unsafe { restore_mem_defaults() };
    }

    #[test]
    fn a_null_left_skips_the_whole_merge_and_flag_block() {
        let mut buf = arena();
        let _ops = install_recorder(buf.0.as_mut_ptr());
        let _guard = SLOT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut db = Connection::healthy();
        let mut right = child(0x62, EP_COMB_BOUND, 7, 5);

        let raw = unsafe {
            with_slots_result(missing_expr_delete, recording_span_merge, || {
                expr_new(
                    db.ptr(),
                    0x6b,
                    core::ptr::null_mut(),
                    &mut right as *mut expr_height::Expr as *mut u8,
                    core::ptr::null(),
                )
            })
        };

        assert!(merged().is_empty(), "no left operand: no merge");
        let node = unsafe { &*node_of(raw) };
        assert_eq!(node.flags, 0, "the right flag propagates only inside the both-operands branch");
        assert_eq!(node.i_table, 0);
        assert_eq!(node.p_right, &mut right as *mut expr_height::Expr as *mut u8);
        unsafe { restore_mem_defaults() };
    }

    #[test]
    fn the_shipped_merge_covers_both_child_spans() {
        let mut buf = arena();
        let _ops = install_recorder(buf.0.as_mut_ptr());
        let _guard = SLOT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut db = Connection::healthy();
        let text = *b"SELECT a+b";
        let mut left = child(0x61, 0, 0, 1);
        let mut right = child(0x62, 0, 0, 1);
        unsafe {
            (*(node_of(&mut left as *mut expr_height::Expr as *mut u8) as *mut Expr)).span =
                Token { z: text.as_ptr(), n_dyn: 3 << 1 };
            (*(node_of(&mut right as *mut expr_height::Expr as *mut u8) as *mut Expr)).span =
                Token { z: text.as_ptr().add(4), n_dyn: 4 << 1 };
        }

        let raw = unsafe {
            with_slots_result(missing_expr_delete, super::super::expr_span::expr_span, || {
                expr_new(
                    db.ptr(),
                    0x6b,
                    &mut left as *mut expr_height::Expr as *mut u8,
                    &mut right as *mut expr_height::Expr as *mut u8,
                    core::ptr::null(),
                )
            })
        };

        let node = unsafe { &*node_of(raw) };
        assert_eq!(node.span.z, text.as_ptr(), "the span starts at the left child's text");
        assert_eq!(node.span.n_dyn, 8 << 1, "right.z + right.n - left.z = 4 + 4 = 8, dyn clear");
        unsafe { restore_mem_defaults() };
    }

    #[test]
    fn the_retained_stub_leaves_the_zeroed_span() {
        let mut buf = arena();
        let _ops = install_recorder(buf.0.as_mut_ptr());
        let _guard = SLOT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut db = Connection::healthy();
        let text = *b"abcdef";
        let mut left = child(0x61, 0, 0, 1);
        let mut right = child(0x62, 0, 0, 1);
        unsafe {
            (*(node_of(&mut left as *mut expr_height::Expr as *mut u8) as *mut Expr)).span =
                Token { z: text.as_ptr(), n_dyn: 3 << 1 };
            (*(node_of(&mut right as *mut expr_height::Expr as *mut u8) as *mut Expr)).span =
                Token { z: text.as_ptr().add(3), n_dyn: 3 << 1 };
        }

        let raw = unsafe {
            with_slots_result(missing_expr_delete, missing_span_merge, || {
                expr_new(
                    db.ptr(),
                    0x6b,
                    &mut left as *mut expr_height::Expr as *mut u8,
                    &mut right as *mut expr_height::Expr as *mut u8,
                    core::ptr::null(),
                )
            })
        };

        let node = unsafe { &*node_of(raw) };
        assert!(node.span.z.is_null(), "the no-op stub keeps the allocator's zeroes");
        assert_eq!(node.span.n_dyn, 0);
        unsafe { restore_mem_defaults() };
    }

    #[test]
    fn oom_releases_both_operands_in_order_and_returns_null() {
        let _ops = install_recorder(core::ptr::null_mut());
        let _guard = SLOT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut db = Connection::healthy();

        let raw = unsafe {
            with_slots_result(recording_expr_delete, recording_span_merge, || {
                expr_new(db.ptr(), 0x70, 0x11111111 as *mut u8, 0x22222222 as *mut u8, core::ptr::null())
            })
        };

        assert!(raw.is_null());
        assert_eq!(deleted(), std::vec![0x11111111, 0x22222222], "left first, then right");
        assert_eq!(db.failed_flag(), 1, "the allocator recorded the failure");
        assert!(merged().is_empty());
        unsafe { restore_mem_defaults() };
    }

    #[test]
    fn the_height_is_recomputed_from_the_children() {
        // The height folds live in expr_height's own dispatch slots; its
        // test lock serializes against that module's slot-swapping
        // tests so the shipped defaults (the real ports) are in effect.
        let _height = expr_height::tests::SLOT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut buf = arena();
        let _ops = install_recorder(buf.0.as_mut_ptr());
        let _guard = SLOT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut db = Connection::healthy();
        let mut left = child(0x61, 0, 0, 3);
        let mut right = child(0x62, 0, 0, 7);

        let raw = unsafe {
            with_slots_result(missing_expr_delete, missing_span_merge, || {
                expr_new(
                    db.ptr(),
                    0x6b,
                    &mut left as *mut expr_height::Expr as *mut u8,
                    &mut right as *mut expr_height::Expr as *mut u8,
                    core::ptr::null(),
                )
            })
        };
        assert_eq!(height_of(raw), 8, "expr_set_height with the shipped folds: max(3, 7) + 1");

        // A leaf node is one level tall.
        let mut buf2 = arena();
        unsafe { core::ptr::write(core::ptr::addr_of_mut!(super::super::mem::tests::REALLOC_RESULT), buf2.0.as_mut_ptr()) };
        let raw2 = unsafe {
            with_slots_result(missing_expr_delete, missing_span_merge, || {
                expr_new(db.ptr(), 0x6b, core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null())
            })
        };
        assert_eq!(height_of(raw2), 1);
        unsafe { restore_mem_defaults() };
    }
}
