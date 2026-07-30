//! The expression destructor — how a finished parse tree gives its
//! memory back.
//!
//! - `expr_delete` — original: `FUN_08377e00` @ 0x08377e00 (88 bytes;
//!   34 `bl` call sites, binary-scanned). SQLite 3.5.x's
//!   `sqlite3ExprDelete`, the single-argument build variant (no `db`
//!   parameter — the frees go straight to the global tracked
//!   allocator).
//!
//! Algorithm: NULL is a no-op (`movs r4,r0` / `ldmiaeq sp!,{r4,pc}`).
//! Otherwise, in fixed field order: if the span's packed word at +0x20
//! has its ownership (`dyn`) bit set, free the span text at +0x1c
//! through `sqlite3_free` @ 0x083906f4 (ported as
//! [`tracked_free`](crate::heap::tracked::tracked_free), called
//! directly); the same dyn-test/free pair for the token (+0x18 packed
//! word, +0x14 text). Then recurse into the operands — p_left at +0x08
//! first, p_right at +0x0c second, both direct self-calls — tear the
//! argument list at +0x10 down through `sqlite3ExprListDelete` @
//! 0x08378670 (ported as
//! [`expr_list_delete`](super::expr_list_delete::expr_list_delete),
//! reached through the [`SQLITE_EXPR_LIST_DELETE`] slot) and the
//! sub-select at +0x38 through `sqlite3SelectDelete`
//! @ 0x08383c88, and finish with a tail branch into `sqlite3_free` on
//! the node itself. Post-order: every child is fully released before
//! its parent's own block goes back.
//!
//! ```text
//! 08377e00:  stmdb sp!,{r4,lr}
//!            movs r4,r0 ; ldmiaeq sp!,{r4,pc}    ; NULL no-op
//! 08377e0c:  ldr r0,[r4,#0x20] ; tst r0,#1       ; span dyn?
//!            ldrne r0,[r4,#0x1c] ; blne 0x083906f4
//! 08377e1c:  ldr r0,[r4,#0x18] ; tst r0,#1       ; token dyn?
//!            ldrne r0,[r4,#0x14] ; blne 0x083906f4
//! 08377e2c:  ldr r0,[r4,#0x8]  ; bl 0x08377e00   ; left operand
//! 08377e34:  ldr r0,[r4,#0xc]  ; bl 0x08377e00   ; right operand
//! 08377e3c:  ldr r0,[r4,#0x10] ; bl 0x08378670   ; ExprList delete
//! 08377e44:  ldr r0,[r4,#0x38] ; bl 0x08383c88   ; Select delete
//! 08377e4c:  mov r0,r4 ; ldmia sp!,{r4,lr} ; b 0x083906f4
//! ```
//!
//! `Expr` fields used (pinned by the original's `ldr [r4, #off]`
//! sequence; the node is the 0x44-byte allocation of
//! [`expr_new`](super::expr_new), whose module header carries the full
//! layout; `Token` packs `n:31 | dyn:1`, dyn in bit 0 — the
//! `tst rX,#1` above):
//!
//! ```text
//! Expr:  +0x08 p_left, +0x0c p_right, +0x10 p_list,
//!        +0x14 token (Token), +0x1c span (Token), +0x38 p_select
//! ```
//!
//! Deviations:
//! - The argument-list destructor @ 0x08378670 (80 bytes; 22 `bl` call
//!   sites — walks the items array at stride 0xc, releasing each item's
//!   `p_expr` back through 0x08377e00 and its name through
//!   `sqlite3_free`, then the array and the header) is ported as
//!   [`expr_list_delete`](super::expr_list_delete::expr_list_delete)
//!   and is the shipped default of the [`SQLITE_EXPR_LIST_DELETE`]
//!   dispatch boundary (house pattern — see `sqlite/error_msg.rs`). The
//!   documented no-op stub [`missing_expr_list_delete`] is retained for
//!   host tests (with it installed the list teardown is skipped; the
//!   node's strings, operands and own block are still released exactly
//!   as the original releases them). The sub-select destructor
//!   `sqlite3SelectDelete` @ 0x08383c88 (32 bytes; a clear helper
//!   @ 0x082c36c4 then the block free) is not ported — it drags in the
//!   Select chain — so it stays the [`SQLITE_SELECT_DELETE`] dispatch
//!   boundary with a documented no-op default.
//! - `Expr` is a typed `#[repr(C)]` struct rather than raw byte
//!   offsets, reusing [`expr_new`](super::expr_new)'s `Token`, so the
//!   pointer fields stay disjoint on a 64-bit test host. The original
//!   byte offsets are statically asserted on 32-bit targets
//!   (`_EXPR_*_OFFSET`). On a 64-bit host the widened `token`/`span`
//!   pair pushes `p_select` off its +0x38 home; it keeps a `cfg`-split
//!   home at +0x48 instead, matching `expr_height::Expr`'s widened
//!   layout (and clear of `expr_new::Expr`'s widened `i_agg` word at
//!   +0x40) so a node built by the constructor and folded by the
//!   height pass can be handed here unchanged.
//! - The port is the shipped default of
//!   [`expr_new`](super::expr_new)'s `SQLITE_EXPR_DELETE` slot: the
//!   constructor's OOM path now really releases both operands instead
//!   of leaking them through the old no-op stub.

use super::expr_new::Token;
use crate::heap::tracked::tracked_free;

/// An expression node (`sqlite3Expr`), only the fields this destructor
/// touches. The full layout is documented in the module header and in
/// `sqlite/expr_new.rs`; the height fields (+0x38's neighbour +0x40)
/// are modeled by `sqlite/expr_height.rs`'s own `Expr`.
///
/// Layout note: on a 64-bit test host the pointer fields widen, so
/// `p_left`/`p_right`/`p_list` sit at +0x08/+0x10/+0x18 and the
/// `token`/`span` pair at +0x20/+0x30, exactly where
/// `expr_new::Expr`'s widened layout puts them. `p_select`, +0x38 on
/// the target, cannot keep that offset (on the host +0x38 is the
/// widened `span`'s `n_dyn` word), so its placement is `cfg`-split:
/// target offset +0x38 on 32-bit, +0x48 on 64-bit — the same home
/// `expr_height::Expr`'s widened `p_select` uses. Only the 32-bit
/// offsets are asserted — they are the original's.
#[repr(C)]
pub struct Expr {
    /// +0x00..+0x08: the op byte, affinity, flags, i_table — unmodeled.
    pub _gap_00: [u8; 0x08],
    /// +0x08: left operand (`Expr *`, may be NULL).
    pub p_left: *mut u8,
    /// +0x0c: right operand (`Expr *`, may be NULL).
    pub p_right: *mut u8,
    /// +0x10: argument / IN-expression list (`ExprList *`, may be NULL).
    pub p_list: *mut u8,
    /// +0x14: the token this node was built from.
    pub token: Token,
    /// +0x1c: the source span covering the whole subtree.
    pub span: Token,
    /// +0x24..+0x38: unmodeled (32-bit target layout).
    #[cfg(target_pointer_width = "32")]
    pub _gap_24: [u8; 0x38 - 0x24],
    /// +0x38: sub-select (`Select *`, may be NULL). 32-bit target home.
    #[cfg(target_pointer_width = "32")]
    pub p_select: *mut u8,
    /// +0x3c..+0x44: `n_height` +0x40 — unmodeled here (see
    /// `sqlite/expr_height.rs`). 32-bit target layout.
    #[cfg(target_pointer_width = "32")]
    pub _gap_3c: [u8; 0x44 - 0x3c],
    /// +0x40..+0x48 on a 64-bit host: covers `expr_new::Expr`'s widened
    /// `i_agg` word — unmodeled here.
    #[cfg(target_pointer_width = "64")]
    pub _gap_40: [u8; 0x48 - 0x40],
    /// 64-bit host home of the sub-select pointer (see the struct's
    /// layout note), matching `expr_height::Expr`'s widened layout.
    #[cfg(target_pointer_width = "64")]
    pub p_select: *mut u8,
}

// The original's byte offsets, asserted on the 32-bit target. On a
// 64-bit host the pointer fields widen and these shift — harmless,
// because all access goes through the typed structs.
#[cfg(target_pointer_width = "32")]
const _EXPR_P_LEFT_OFFSET: [u8; 0x08] = [0; core::mem::offset_of!(Expr, p_left)];
#[cfg(target_pointer_width = "32")]
const _EXPR_P_RIGHT_OFFSET: [u8; 0x0c] = [0; core::mem::offset_of!(Expr, p_right)];
#[cfg(target_pointer_width = "32")]
const _EXPR_P_LIST_OFFSET: [u8; 0x10] = [0; core::mem::offset_of!(Expr, p_list)];
#[cfg(target_pointer_width = "32")]
const _EXPR_TOKEN_OFFSET: [u8; 0x14] = [0; core::mem::offset_of!(Expr, token)];
#[cfg(target_pointer_width = "32")]
const _EXPR_SPAN_OFFSET: [u8; 0x1c] = [0; core::mem::offset_of!(Expr, span)];
#[cfg(target_pointer_width = "32")]
const _EXPR_P_SELECT_OFFSET: [u8; 0x38] = [0; core::mem::offset_of!(Expr, p_select)];
#[cfg(target_pointer_width = "32")]
const _EXPR_SIZE_CHECK: [u8; 0x44] = [0; core::mem::size_of::<Expr>()];

/// The argument-list destructor: `sqlite3ExprListDelete(list)` @
/// 0x08378670. Recursively releases an `ExprList`; NULL is a no-op (the
/// original's `movs/ldmiaeq` early return).
pub type ExprListDeleteFn = unsafe extern "C" fn(list: *mut u8);

/// Default stub retained for host tests: no list destructor wired, so
/// the list teardown is skipped — the node, its strings and its
/// operands are still released (see the module header). The shipped
/// default is the real port,
/// [`super::expr_list_delete::expr_list_delete`].
pub(crate) unsafe extern "C" fn missing_expr_list_delete(_list: *mut u8) {}

/// The active list destructor. The default is the real port,
/// [`super::expr_list_delete::expr_list_delete`]; host tests still
/// install recording mocks through the slot ([`missing_expr_list_delete`]
/// is retained for them).
pub static mut SQLITE_EXPR_LIST_DELETE: ExprListDeleteFn =
    super::expr_list_delete::expr_list_delete;

/// The sub-select destructor: `sqlite3SelectDelete(select)` @
/// 0x08383c88. Releases a `Select`; NULL is a no-op (the original's
/// `movs/ldmiaeq` early return).
pub type SelectDeleteFn = unsafe extern "C" fn(select: *mut u8);

/// Default stub: no select destructor wired, so the sub-select teardown
/// is skipped (see the module header).
pub(crate) unsafe extern "C" fn missing_select_delete(_select: *mut u8) {}

/// The active select destructor. Host tests install recording mocks;
/// the real port replaces the default when 0x08383c88 lands.
pub static mut SQLITE_SELECT_DELETE: SelectDeleteFn = missing_select_delete;

/// Reads the list-destructor slot (volatile — the slots are meant to be
/// swapped at runtime, and a plain read lets LLVM const-fold the
/// default away).
#[inline(always)]
pub(crate) fn expr_list_delete_op() -> ExprListDeleteFn {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(SQLITE_EXPR_LIST_DELETE)) }
}

/// Reads the select-destructor slot (volatile — see
/// [`expr_list_delete_op`]).
#[inline(always)]
pub(crate) fn select_delete_op() -> SelectDeleteFn {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(SQLITE_SELECT_DELETE)) }
}

/// expr_delete — original: `FUN_08377e00` @ 0x08377e00 (88 bytes; 34
/// `bl` call sites).
///
/// `sqlite3ExprDelete`: recursively release one expression subtree.
/// NULL is a no-op. A heap-owned (`dyn` bit set in the packed word)
/// span string is freed first, then a heap-owned token string, both
/// through the ported [`tracked_free`]; the operands are torn down left
/// first, then right, by direct recursion; the argument list and the
/// sub-select go through the [`SQLITE_EXPR_LIST_DELETE`] and
/// [`SQLITE_SELECT_DELETE`] slots; the node's own block is the final
/// `tracked_free`. Register usage: r0 = expr, r4 = expr (saved). This
/// port is wired as the default of [`super::expr_new`]'s
/// `SQLITE_EXPR_DELETE` slot.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn expr_delete(expr: *mut u8) {
    if expr.is_null() {
        return;
    }
    let node = &*(expr as *const Expr);
    if node.span.n_dyn & 1 != 0 {
        tracked_free(node.span.z as *mut u8);
    }
    if node.token.n_dyn & 1 != 0 {
        tracked_free(node.token.z as *mut u8);
    }
    expr_delete(node.p_left);
    expr_delete(node.p_right);
    (expr_list_delete_op())(node.p_list);
    (select_delete_op())(node.p_select);
    tracked_free(expr);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::heap::tracked::{BLOCK_HEADER_SIZE, TAG_TRACKED};
    use crate::heap::types::HeapDescriptorDescriptor;
    use crate::heap::veneers::{tests::mock_heap, HEAP_OPS};
    use std::sync::Mutex;
    use std::vec::Vec;

    /// Serializes access to the list/select slots across tests.
    static SLOT_LOCK: Mutex<()> = Mutex::new(());

    /// Every (raw block, tag) the mock heap was asked to free, in order.
    static mut FREED: Vec<(*mut u8, usize)> = Vec::new();

    /// Every list the recording list destructor was handed.
    static mut LISTS: Vec<*mut u8> = Vec::new();

    /// Every select the recording select destructor was handed.
    static mut SELECTS: Vec<*mut u8> = Vec::new();

    unsafe extern "C" fn recording_free(
        _heap: *mut HeapDescriptorDescriptor,
        ptr: *mut u8,
        tag: usize,
    ) {
        (*core::ptr::addr_of_mut!(FREED)).push((ptr, tag));
    }

    unsafe extern "C" fn recording_expr_list_delete(list: *mut u8) {
        (*core::ptr::addr_of_mut!(LISTS)).push(list);
    }

    unsafe extern "C" fn recording_select_delete(select: *mut u8) {
        (*core::ptr::addr_of_mut!(SELECTS)).push(select);
    }

    fn freed() -> Vec<(*mut u8, usize)> {
        unsafe { (*core::ptr::addr_of!(FREED)).clone() }
    }

    fn lists() -> Vec<*mut u8> {
        unsafe { (*core::ptr::addr_of!(LISTS)).clone() }
    }

    fn selects() -> Vec<*mut u8> {
        unsafe { (*core::ptr::addr_of!(SELECTS)).clone() }
    }

    /// The documented defaults: the real list-destructor port on the
    /// list slot, the no-op stub on the select slot.
    unsafe fn restore_slot_defaults() {
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(SQLITE_EXPR_LIST_DELETE),
            super::super::expr_list_delete::expr_list_delete,
        );
        core::ptr::write_volatile(core::ptr::addr_of_mut!(SQLITE_SELECT_DELETE), missing_select_delete);
    }

    /// Serializes against every other heap-ops-swapping test, installs
    /// the mock heap table with the recording free, clears the
    /// recorders, installs the given slots, runs `body`, then restores
    /// the slot defaults so a failed assertion cannot leak mocks into
    /// the next test.
    unsafe fn with_bench(list: ExprListDeleteFn, select: SelectDeleteFn, body: impl FnOnce()) {
        (*core::ptr::addr_of_mut!(FREED)).clear();
        (*core::ptr::addr_of_mut!(LISTS)).clear();
        (*core::ptr::addr_of_mut!(SELECTS)).clear();
        (*core::ptr::addr_of_mut!(HEAP_OPS)).free = recording_free;
        core::ptr::write_volatile(core::ptr::addr_of_mut!(SQLITE_EXPR_LIST_DELETE), list);
        core::ptr::write_volatile(core::ptr::addr_of_mut!(SQLITE_SELECT_DELETE), select);
        body();
        restore_slot_defaults();
    }

    /// A hand-built tag-57 tracked block (layout: `heap::tracked`) big
    /// enough for the widened host `Expr`. Raw block at offset 0 of a
    /// 32-aligned buffer, payload at raw + 32, pad word 32 - 8 = 24.
    #[repr(align(32))]
    struct TrackedBlock([u8; 128]);

    impl TrackedBlock {
        fn new(size: i32) -> Self {
            let mut block = TrackedBlock([0; 128]);
            block.0[0..4].copy_from_slice(&size.to_le_bytes());
            let pad = (32 - BLOCK_HEADER_SIZE) as u32;
            block.0[28..32].copy_from_slice(&pad.to_le_bytes());
            block
        }
        fn raw(&mut self) -> *mut u8 {
            self.0.as_mut_ptr()
        }
        fn payload(&mut self) -> *mut u8 {
            // In-bounds by construction (128-byte block, payload at 32).
            unsafe { self.0.as_mut_ptr().add(32) }
        }
        /// The payload as a zeroed node.
        fn node(&mut self) -> *mut Expr {
            self.payload() as *mut Expr
        }
    }

    #[test]
    fn null_is_a_no_op() {
        let _heap = mock_heap();
        let _guard = SLOT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            with_bench(recording_expr_list_delete, recording_select_delete, || {
                expr_delete(core::ptr::null_mut());
            });
        }
        assert!(freed().is_empty(), "movs/ldmiaeq: NULL frees nothing");
        assert!(lists().is_empty() && selects().is_empty(), "the slots are not consulted");
    }

    #[test]
    fn dyn_strings_are_freed_span_first_then_token_then_the_node() {
        let _heap = mock_heap();
        let _guard = SLOT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut node_block = TrackedBlock::new(0x44);
        let mut span_text = TrackedBlock::new(6);
        let mut token_text = TrackedBlock::new(4);
        unsafe {
            let node = node_block.node();
            (*node).span = Token { z: span_text.payload(), n_dyn: (5 << 1) | 1 };
            (*node).token = Token { z: token_text.payload(), n_dyn: (3 << 1) | 1 };
            with_bench(recording_expr_list_delete, recording_select_delete, || {
                expr_delete(node_block.payload());
            });
        }
        assert_eq!(
            freed(),
            std::vec![
                (span_text.raw(), TAG_TRACKED),
                (token_text.raw(), TAG_TRACKED),
                (node_block.raw(), TAG_TRACKED),
            ],
            "span text, token text, node — in field order, all tag 57"
        );
        assert_eq!(
            lists(),
            std::vec![core::ptr::null_mut::<u8>()],
            "the slot call is unconditional; the NULL guard is the callee's"
        );
        assert_eq!(selects(), std::vec![core::ptr::null_mut::<u8>()]);
    }

    #[test]
    fn non_dyn_strings_are_never_freed_even_when_set() {
        let _heap = mock_heap();
        let _guard = SLOT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        static TEXT: [u8; 8] = *b"SELECT 1";
        let mut node_block = TrackedBlock::new(0x44);
        unsafe {
            let node = node_block.node();
            // dyn clear, z non-NULL and NOT a tracked payload: a wrong
            // free would read garbage at z-4 and corrupt the record.
            (*node).span = Token { z: TEXT.as_ptr(), n_dyn: 7 << 1 };
            (*node).token = Token { z: TEXT.as_ptr().add(3), n_dyn: 1 << 1 };
            with_bench(missing_expr_list_delete, missing_select_delete, || {
                expr_delete(node_block.payload());
            });
        }
        assert_eq!(
            freed(),
            std::vec![(node_block.raw(), TAG_TRACKED)],
            "tst #1: only the node's own block goes back"
        );
    }

    #[test]
    fn operands_are_torn_down_left_first_post_order() {
        let _heap = mock_heap();
        let _guard = SLOT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut parent = TrackedBlock::new(0x44);
        let mut left = TrackedBlock::new(0x44);
        let mut grandchild = TrackedBlock::new(0x44);
        let mut right = TrackedBlock::new(0x44);
        unsafe {
            (*parent.node()).p_left = left.payload();
            (*parent.node()).p_right = right.payload();
            (*left.node()).p_left = grandchild.payload();
            with_bench(missing_expr_list_delete, missing_select_delete, || {
                expr_delete(parent.payload());
            });
        }
        assert_eq!(
            freed(),
            std::vec![
                (grandchild.raw(), TAG_TRACKED),
                (left.raw(), TAG_TRACKED),
                (right.raw(), TAG_TRACKED),
                (parent.raw(), TAG_TRACKED),
            ],
            "left subtree fully first (its own left before it), then right, then the parent"
        );
    }

    #[test]
    fn the_list_and_select_go_through_the_slots_in_order() {
        let _heap = mock_heap();
        let _guard = SLOT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut node_block = TrackedBlock::new(0x44);
        let mut list = [0xaau8; 4];
        let mut select = [0xbbu8; 4];
        unsafe {
            let node = node_block.node();
            (*node).p_list = list.as_mut_ptr();
            (*node).p_select = select.as_mut_ptr();
            with_bench(recording_expr_list_delete, recording_select_delete, || {
                expr_delete(node_block.payload());
            });
        }
        assert_eq!(lists(), std::vec![list.as_mut_ptr()], "p_list (+0x10) handed over verbatim");
        assert_eq!(selects(), std::vec![select.as_mut_ptr()], "p_select (+0x38) handed over verbatim");
        assert_eq!(
            freed(),
            std::vec![(node_block.raw(), TAG_TRACKED)],
            "the slots release nothing themselves; the node still goes back"
        );
    }

    #[test]
    fn the_default_slots_skip_the_list_and_select_teardown() {
        let _heap = mock_heap();
        let _guard = SLOT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut node_block = TrackedBlock::new(0x44);
        // Non-NULL, deliberately untracked list/select pointers: the
        // retained no-op stubs must not touch them (a real destructor
        // would dereference and crash on 0xa5a5..).
        unsafe {
            let node = node_block.node();
            (*node).p_list = 0xa5a5_a5a5 as *mut u8;
            (*node).p_select = 0x5a5a_5a5a as *mut u8;
            with_bench(missing_expr_list_delete, missing_select_delete, || {
                expr_delete(node_block.payload());
            });
        }
        assert_eq!(freed(), std::vec![(node_block.raw(), TAG_TRACKED)]);
        assert!(lists().is_empty() && selects().is_empty());
    }

    #[test]
    fn the_shipped_list_delete_tears_down_a_real_list() {
        let _heap = mock_heap();
        let _guard = SLOT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut node_block = TrackedBlock::new(0x44);
        let mut list_block = TrackedBlock::new(0x10);
        let mut array_block = TrackedBlock::new(0x18);
        let mut item_node = TrackedBlock::new(0x44);
        let mut item_name = TrackedBlock::new(4);
        unsafe {
            // A one-item list in tracked blocks: the item's expression
            // is a zeroed node, its alias name a tracked text block.
            let array = array_block.payload()
                as *mut super::super::expr_list_delete::ExprListItem;
            core::ptr::write(
                array,
                super::super::expr_list_delete::ExprListItem {
                    p_expr: item_node.payload(),
                    p_name: item_name.payload(),
                    #[cfg(target_pointer_width = "32")]
                    _gap_08: [0; 0x0c - 0x08],
                },
            );
            let list = list_block.payload() as *mut super::super::expr_list_delete::ExprList;
            core::ptr::write(
                list,
                super::super::expr_list_delete::ExprList { n_expr: 1, _gap_04: [0; 0x0c - 0x04], items: array },
            );
            let node = node_block.node();
            (*node).p_list = list as *mut u8;
            // The shipped list default plus the retained select stub:
            // restore_slot_defaults puts exactly that pair back.
            with_bench(super::super::expr_list_delete::expr_list_delete, missing_select_delete, || {
                expr_delete(node_block.payload());
            });
        }
        assert_eq!(
            freed(),
            std::vec![
                (item_node.raw(), TAG_TRACKED),
                (item_name.raw(), TAG_TRACKED),
                (array_block.raw(), TAG_TRACKED),
                (list_block.raw(), TAG_TRACKED),
                (node_block.raw(), TAG_TRACKED),
            ],
            "the list's expr, name, array and header all go back before the node"
        );
    }

    #[test]
    fn the_node_is_only_read_until_its_own_free() {
        let _heap = mock_heap();
        let _guard = SLOT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut node_block = TrackedBlock::new(0x44);
        let mut text = TrackedBlock::new(2);
        unsafe {
            let node = node_block.node();
            (*node).token = Token { z: text.payload(), n_dyn: (1 << 1) | 1 };
            with_bench(missing_expr_list_delete, missing_select_delete, || {
                expr_delete(node_block.payload());
            });
            // The token words still read back what the test wrote —
            // the destructor stores nothing into the node.
            assert_eq!((*node).token.n_dyn, (1 << 1) | 1);
            assert_eq!((*node).token.z, text.payload());
        }
    }
}
