//! The expression-list destructor — how a finished argument/IN list
//! gives its memory back.
//!
//! - `expr_list_delete` — original: `FUN_08378670` @ 0x08378670 (80
//!   bytes; 22 `bl` call sites, binary-scanned: one in
//!   [`expr_delete`](super::expr_delete) @ 0x08377e3c, the rest across
//!   the parser/VDBE teardown paths). SQLite 3.5.x's
//!   `sqlite3ExprListDelete`, the single-argument build variant (no
//!   `db` parameter — the frees go straight to the global tracked
//!   allocator).
//!
//! Algorithm: NULL is a no-op (`movs r6,r0` / `ldmiaeq sp!,{r4,r5,r6,pc}`).
//! Otherwise walk the item array at +0x0c with stride 0xc, a signed
//! `bgt` guard against the header's `n_expr` (+0x00) re-read from the
//! header on every iteration: each item's expression at +0x00 goes
//! back through `sqlite3ExprDelete` @ 0x08377e00 (ported as
//! [`expr_delete`](super::expr_delete::expr_delete), called directly —
//! the same direct `bl` the original makes) and its alias name at
//! +0x04 is freed unconditionally through `sqlite3_free` @ 0x083906f4
//! (ported as [`tracked_free`](crate::heap::tracked::tracked_free),
//! whose internal NULL guard is the original's own `sqlite3_free`
//! NULL check). Then the item array itself is freed, and the list
//! header is the tail branch into `sqlite3_free`. Post-order: every
//! item's subtree is fully released before the list's own blocks go
//! back.
//!
//! ```text
//! 08378670:  stmdb sp!,{r4,r5,r6,lr}
//!            movs r6,r0 ; ldmiaeq sp!,{r4,r5,r6,pc}  ; NULL no-op
//! 0837867c:  ldr r4,[r6,#0xc] ; mov r5,#0x0 ; b 0x083786a0
//! 08378688:  ldr r0,[r4,#0x0] ; bl 0x08377e00   ; item.p_expr
//! 08378690:  ldr r0,[r4,#0x4] ; bl 0x083906f4   ; item.p_name
//! 08378698:  add r5,r5,#0x1 ; add r4,r4,#0xc
//! 083786a0:  ldr r0,[r6,#0x0] ; cmp r0,r5 ; bgt 0x08378688
//! 083786ac:  ldr r0,[r6,#0xc] ; bl 0x083906f4   ; the items array
//! 083786b4:  mov r0,r6 ; ldmia sp!,{r4,r5,r6,lr} ; b 0x083906f4
//! ```
//!
//! `ExprList` fields used (pinned by the original's `ldr [rX, #off]`
//! sequence; the item layout is the same one
//! [`expr_list_height`](super::expr_list_height) walks, here with the
//! +0x04 name word modeled as well):
//!
//! ```text
//! ExprList:      +0x00 n_expr (i32), +0x0c items
//! ExprList_item: +0x00 p_expr, +0x04 p_name (stride 0xc)
//! ```
//!
//! Deviations:
//! - The list and its items are typed `#[repr(C)]` structs rather than
//!   raw byte offsets, so the pointer fields stay disjoint on a 64-bit
//!   test host. The original byte offsets and the 0xc item stride are
//!   statically asserted on 32-bit targets (`_EXPR_LIST_*`).
//! - The per-item recursion calls the ported
//!   [`expr_delete`](super::expr_delete::expr_delete) directly,
//!   mirroring the original's `bl 0x08377e00` (expr_delete's own
//!   operand recursion is likewise direct self-calls, not slot
//!   dispatches).
//! - The port is the shipped default of
//!   [`expr_delete`](super::expr_delete)'s `SQLITE_EXPR_LIST_DELETE`
//!   slot, replacing the documented no-op stub (retained there for
//!   host tests): deleting an expression with an argument list now
//!   really releases the whole list instead of leaking it.

use super::expr_delete::expr_delete;
use crate::heap::tracked::tracked_free;

/// An expression list (`sqlite3ExprList`), only the fields this
/// destructor touches.
#[repr(C)]
pub struct ExprList {
    /// +0x00: number of entries in the item array (signed — the loop
    /// guard is `bgt`).
    pub n_expr: i32,
    /// +0x04..+0x0c: allocation bookkeeping — unmodeled.
    pub _gap_04: [u8; 0x0c - 0x04],
    /// +0x0c: the item array, `n_expr` entries of 12 bytes each.
    pub items: *mut ExprListItem,
}

/// One expression-list entry (`ExprList_item`), 12 bytes in the
/// original.
#[repr(C)]
pub struct ExprListItem {
    /// +0x00: the expression (`Expr *`, may be NULL).
    pub p_expr: *mut u8,
    /// +0x04: the item's alias name (heap-owned, freed unconditionally —
    /// the free NULL-guards internally).
    pub p_name: *mut u8,
    /// +0x08..+0x0c: sort-order/aggregate flags — unmodeled (32-bit
    /// target layout).
    #[cfg(target_pointer_width = "32")]
    pub _gap_08: [u8; 0x0c - 0x08],
}

// The original's byte offsets and item stride, asserted on the 32-bit
// target. On a 64-bit host the pointer fields widen and these shift —
// harmless, because all access goes through the typed structs.
#[cfg(target_pointer_width = "32")]
const _EXPR_LIST_N_EXPR_OFFSET: [u8; 0x00] = [0; core::mem::offset_of!(ExprList, n_expr)];
#[cfg(target_pointer_width = "32")]
const _EXPR_LIST_ITEMS_OFFSET: [u8; 0x0c] = [0; core::mem::offset_of!(ExprList, items)];
#[cfg(target_pointer_width = "32")]
const _EXPR_LIST_ITEM_P_EXPR_OFFSET: [u8; 0x00] = [0; core::mem::offset_of!(ExprListItem, p_expr)];
#[cfg(target_pointer_width = "32")]
const _EXPR_LIST_ITEM_P_NAME_OFFSET: [u8; 0x04] = [0; core::mem::offset_of!(ExprListItem, p_name)];
#[cfg(target_pointer_width = "32")]
const _EXPR_LIST_ITEM_STRIDE: [u8; 0x0c] = [0; core::mem::size_of::<ExprListItem>()];

/// expr_list_delete — original: `FUN_08378670` @ 0x08378670 (80 bytes;
/// 22 `bl` call sites).
///
/// `sqlite3ExprListDelete`: recursively release one expression list.
/// NULL is a no-op. Each item's expression is torn down through the
/// ported [`expr_delete`] and its alias name freed through the ported
/// [`tracked_free`] (unconditional, like the original — the free
/// NULL-guards internally), in array order; then the item array and
/// the list header go back. Register usage: r0 = list, r4 = item
/// cursor, r5 = index, r6 = list. This port is wired as the default of
/// [`super::expr_delete`]'s `SQLITE_EXPR_LIST_DELETE` slot.
///
/// Takes the list as `*mut u8` (casting to [`ExprList`] internally) so
/// it drops straight into the `ExprListDeleteFn` shape of that slot.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn expr_list_delete(list: *mut u8) {
    if list.is_null() {
        return;
    }
    let list = list as *const ExprList;
    let mut item = (*list).items;
    let mut i: i32 = 0;
    // Original: pre-tested loop, signed `bgt` guard, `n_expr` re-read
    // from the header on every iteration.
    while (*list).n_expr > i {
        expr_delete((*item).p_expr);
        tracked_free((*item).p_name);
        i += 1;
        item = item.add(1);
    }
    tracked_free((*list).items as *mut u8);
    tracked_free(list as *mut u8);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::heap::tracked::{BLOCK_HEADER_SIZE, TAG_TRACKED};
    use crate::heap::types::HeapDescriptorDescriptor;
    use crate::heap::veneers::{tests::mock_heap, HEAP_OPS};
    use std::vec::Vec;

    /// Every (raw block, tag) the mock heap was asked to free, in order.
    static mut FREED: Vec<(*mut u8, usize)> = Vec::new();

    unsafe extern "C" fn recording_free(
        _heap: *mut HeapDescriptorDescriptor,
        ptr: *mut u8,
        tag: usize,
    ) {
        (*core::ptr::addr_of_mut!(FREED)).push((ptr, tag));
    }

    fn freed() -> Vec<(*mut u8, usize)> {
        unsafe { (*core::ptr::addr_of!(FREED)).clone() }
    }

    /// A hand-built tag-57 tracked block (layout: `heap::tracked`) big
    /// enough for the widened host structs. Raw block at offset 0 of a
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
    }

    /// Writes a list header over `items` into the block's payload.
    unsafe fn list_in(block: &mut TrackedBlock, n_expr: i32, items: *mut ExprListItem) -> *mut u8 {
        let payload = block.payload() as *mut ExprList;
        core::ptr::write(payload, ExprList { n_expr, _gap_04: [0xa5; 0x0c - 0x04], items });
        payload as *mut u8
    }

    /// Writes an items array into the block's payload.
    unsafe fn items_in(block: &mut TrackedBlock, entries: &[( *mut u8, *mut u8)]) -> *mut ExprListItem {
        let payload = block.payload() as *mut ExprListItem;
        for (i, &(p_expr, p_name)) in entries.iter().enumerate() {
            core::ptr::write(
                payload.add(i),
                ExprListItem {
                    p_expr,
                    p_name,
                    #[cfg(target_pointer_width = "32")]
                    _gap_08: [0xa5; 0x0c - 0x08],
                },
            );
        }
        payload
    }

    #[test]
    fn null_is_a_no_op() {
        let _heap = mock_heap();
        unsafe {
            (*core::ptr::addr_of_mut!(FREED)).clear();
            (*core::ptr::addr_of_mut!(HEAP_OPS)).free = recording_free;
            expr_list_delete(core::ptr::null_mut());
        }
        assert!(freed().is_empty(), "movs/ldmiaeq: NULL frees nothing");
    }

    #[test]
    fn an_empty_list_frees_the_array_then_the_header() {
        let _heap = mock_heap();
        let mut header = TrackedBlock::new(0x10);
        let mut array = TrackedBlock::new(0xc);
        unsafe {
            (*core::ptr::addr_of_mut!(FREED)).clear();
            (*core::ptr::addr_of_mut!(HEAP_OPS)).free = recording_free;
            let items = items_in(&mut array, &[]);
            let list = list_in(&mut header, 0, items);
            expr_list_delete(list);
        }
        assert_eq!(
            freed(),
            std::vec![(array.raw(), TAG_TRACKED), (header.raw(), TAG_TRACKED)],
            "bgt: 0 > 0 is false — the loop never runs; array first, header last"
        );
    }

    #[test]
    fn a_negative_count_and_a_null_array_free_only_the_header() {
        let _heap = mock_heap();
        let mut header = TrackedBlock::new(0x10);
        unsafe {
            (*core::ptr::addr_of_mut!(FREED)).clear();
            (*core::ptr::addr_of_mut!(HEAP_OPS)).free = recording_free;
            let list = list_in(&mut header, -3, core::ptr::null_mut());
            expr_list_delete(list);
        }
        assert_eq!(
            freed(),
            std::vec![(header.raw(), TAG_TRACKED)],
            "signed bgt skips the loop; the NULL array free is the callee's internal guard"
        );
    }

    #[test]
    fn items_are_torn_down_in_array_order_then_the_blocks() {
        let _heap = mock_heap();
        let mut header = TrackedBlock::new(0x10);
        let mut array = TrackedBlock::new(0x24);
        let mut node0 = TrackedBlock::new(0x44);
        let mut name0 = TrackedBlock::new(4);
        let mut node1 = TrackedBlock::new(0x44);
        let mut name1 = TrackedBlock::new(6);
        unsafe {
            (*core::ptr::addr_of_mut!(FREED)).clear();
            (*core::ptr::addr_of_mut!(HEAP_OPS)).free = recording_free;
            // The item expressions are zeroed node blocks: expr_delete
            // releases each as a single tracked block (NULL operands,
            // list and select; non-dyn strings). The third item is all
            // NULL — the recursion and the name free both no-op.
            let items = items_in(
                &mut array,
                &[
                    (node0.payload(), name0.payload()),
                    (node1.payload(), name1.payload()),
                    (core::ptr::null_mut(), core::ptr::null_mut()),
                ],
            );
            let list = list_in(&mut header, 3, items);
            expr_list_delete(list);
        }
        assert_eq!(
            freed(),
            std::vec![
                (node0.raw(), TAG_TRACKED),
                (name0.raw(), TAG_TRACKED),
                (node1.raw(), TAG_TRACKED),
                (name1.raw(), TAG_TRACKED),
                (array.raw(), TAG_TRACKED),
                (header.raw(), TAG_TRACKED),
            ],
            "expr, name, expr, name — in item order — then the array, then the header"
        );
    }

    #[test]
    fn the_walk_stops_at_the_twelve_byte_stride_times_n_expr() {
        let _heap = mock_heap();
        let mut header = TrackedBlock::new(0x10);
        let mut array = TrackedBlock::new(0x24);
        let mut node = TrackedBlock::new(0x44);
        unsafe {
            (*core::ptr::addr_of_mut!(FREED)).clear();
            (*core::ptr::addr_of_mut!(HEAP_OPS)).free = recording_free;
            let items = items_in(
                &mut array,
                &[
                    (node.payload(), core::ptr::null_mut()),
                    // Poisoned slot past the counted items: a wrong
                    // stride or an off-by-one would dereference this
                    // garbage pointer and corrupt the record.
                    (0xa5a5_a5a5 as *mut u8, 0x5a5a_5a5a as *mut u8),
                ],
            );
            let list = list_in(&mut header, 1, items);
            expr_list_delete(list);
        }
        assert_eq!(
            freed(),
            std::vec![
                (node.raw(), TAG_TRACKED),
                (array.raw(), TAG_TRACKED),
                (header.raw(), TAG_TRACKED),
            ],
            "n_expr items at stride 0xc, never one more"
        );
    }
}
