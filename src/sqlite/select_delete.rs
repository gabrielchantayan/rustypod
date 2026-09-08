//! Deleting a `SELECT` tree and its backing storage.
//!
//! - `select_delete` — original: `FUN_08383c88` @ 0x08383c88 (32 bytes;
//!   21 `bl` call sites, binary-scanned).
//!
//! Algorithm: NULL is a no-op. Otherwise release the select's owned
//! substructures in the retail field order, then free the `Select`
//! block itself: result list, FROM-source list, WHERE, GROUP BY,
//! HAVING, ORDER BY, prior select, LIMIT, OFFSET.
//!
//! Deliberate deviations: the FROM-source list cleanup still routes
//! through the `SQLITE_SRC_LIST_DELETE` dispatch seam because the retail
//! helper at 0x083843e8 is not ported yet. The select layout is modeled
//! as a typed `#[repr(C)]` view so offsets stay correct on the 64-bit
//! host; the 32-bit field offsets are asserted.

use super::expr_delete::expr_delete;
use super::expr_list_delete::expr_list_delete;
use crate::heap::tracked::tracked_free;

/// The source-list destructor seam used by `select_delete` for the FROM
/// clause. The retail helper is not ported yet.
pub type SrcListDeleteFn = unsafe extern "C" fn(source_list: *mut u8);

/// Documented no-op default retained until the source-list destructor is
/// ported.
pub(crate) unsafe extern "C" fn missing_src_list_delete(_source_list: *mut u8) {}

/// The active source-list destructor. Host tests install recording
/// mocks; the real port will replace the default when 0x083843e8 lands.
pub static mut SQLITE_SRC_LIST_DELETE: SrcListDeleteFn = missing_src_list_delete;

#[inline(always)]
fn src_list_delete_op() -> SrcListDeleteFn {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(SQLITE_SRC_LIST_DELETE)) }
}

/// A `SELECT` statement (`sqlite3Select`), only the fields this delete
/// path touches. The full layout is documented by `select_height.rs`;
/// this view inserts the FROM-source list pointer at +0x0c, where the
/// delete path reaches it.
#[repr(C)]
pub struct Select {
    /// +0x00: result column list (`ExprList *`, may be NULL).
    pub p_elist: *mut u8,
    /// +0x04..+0x0c: opcode/distinct bytes and FROM-clause bookkeeping.
    pub _gap_04: [u8; 0x0c - 0x04],
    /// +0x0c: FROM source list (`SrcList *`, may be NULL).
    pub p_src: *mut u8,
    /// +0x10: WHERE clause (`Expr *`, may be NULL).
    pub p_where: *mut u8,
    /// +0x14: GROUP BY clause (`ExprList *`, may be NULL).
    pub p_group_by: *mut u8,
    /// +0x18: HAVING clause (`Expr *`, may be NULL).
    pub p_having: *mut u8,
    /// +0x1c: ORDER BY clause (`ExprList *`, may be NULL).
    pub p_order_by: *mut u8,
    /// +0x20: prior select of a compound select (`Select *`, may be NULL).
    pub p_prior: *mut Select,
    /// +0x24..+0x2c: compound-select bookkeeping — unmodeled.
    pub _gap_24: [u8; 0x2c - 0x24],
    /// +0x2c: LIMIT expression (`Expr *`, may be NULL).
    pub p_limit: *mut u8,
    /// +0x30: OFFSET expression (`Expr *`, may be NULL).
    pub p_offset: *mut u8,
}

#[cfg(target_pointer_width = "32")]
const _SELECT_P_ELIST_OFFSET: [u8; 0x00] = [0; core::mem::offset_of!(Select, p_elist)];
#[cfg(target_pointer_width = "32")]
const _SELECT_P_SRC_OFFSET: [u8; 0x0c] = [0; core::mem::offset_of!(Select, p_src)];
#[cfg(target_pointer_width = "32")]
const _SELECT_P_WHERE_OFFSET: [u8; 0x10] = [0; core::mem::offset_of!(Select, p_where)];
#[cfg(target_pointer_width = "32")]
const _SELECT_P_GROUP_BY_OFFSET: [u8; 0x14] = [0; core::mem::offset_of!(Select, p_group_by)];
#[cfg(target_pointer_width = "32")]
const _SELECT_P_HAVING_OFFSET: [u8; 0x18] = [0; core::mem::offset_of!(Select, p_having)];
#[cfg(target_pointer_width = "32")]
const _SELECT_P_ORDER_BY_OFFSET: [u8; 0x1c] = [0; core::mem::offset_of!(Select, p_order_by)];
#[cfg(target_pointer_width = "32")]
const _SELECT_P_PRIOR_OFFSET: [u8; 0x20] = [0; core::mem::offset_of!(Select, p_prior)];
#[cfg(target_pointer_width = "32")]
const _SELECT_P_LIMIT_OFFSET: [u8; 0x2c] = [0; core::mem::offset_of!(Select, p_limit)];
#[cfg(target_pointer_width = "32")]
const _SELECT_P_OFFSET_OFFSET: [u8; 0x30] = [0; core::mem::offset_of!(Select, p_offset)];
#[cfg(target_pointer_width = "32")]
const _SELECT_SIZE_CHECK: [u8; 0x34] = [0; core::mem::size_of::<Select>()];

/// select_delete — original: `FUN_08383c88` @ 0x08383c88 (32 bytes;
/// 21 `bl` call sites).
///
/// SQLite's `sqlite3SelectDelete`: recursively release one `Select`.
/// NULL is a no-op. Owned substructures are dropped in field order, the
/// compound-select chain recurses through `p_prior`, and the `Select`
/// block itself is the final `tracked_free`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn select_delete(select: *mut u8) {
    if select.is_null() {
        return;
    }

    let node = &*(select as *const Select);
    expr_list_delete(node.p_elist);
    (src_list_delete_op())(node.p_src);
    expr_delete(node.p_where);
    expr_list_delete(node.p_group_by);
    expr_delete(node.p_having);
    expr_list_delete(node.p_order_by);
    select_delete(node.p_prior.cast());
    expr_delete(node.p_limit);
    expr_delete(node.p_offset);
    tracked_free(select);
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

    static SLOT_LOCK: Mutex<()> = Mutex::new(());
    static mut FREED: Vec<(*mut u8, usize)> = Vec::new();
    static mut SRC_LISTS: Vec<*mut u8> = Vec::new();

    unsafe extern "C" fn recording_free(
        _heap: *mut HeapDescriptorDescriptor,
        ptr: *mut u8,
        tag: usize,
    ) {
        (*core::ptr::addr_of_mut!(FREED)).push((ptr, tag));
    }

    unsafe extern "C" fn recording_src_list_delete(source_list: *mut u8) {
        (*core::ptr::addr_of_mut!(SRC_LISTS)).push(source_list);
    }

    fn freed() -> Vec<(*mut u8, usize)> {
        unsafe { (*core::ptr::addr_of!(FREED)).clone() }
    }

    fn src_lists() -> Vec<*mut u8> {
        unsafe { (*core::ptr::addr_of!(SRC_LISTS)).clone() }
    }

    unsafe fn restore_defaults() {
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(SQLITE_SRC_LIST_DELETE),
            missing_src_list_delete,
        );
    }

    unsafe fn with_slots(body: impl FnOnce()) {
        let saved_heap_ops = core::ptr::read(core::ptr::addr_of!(HEAP_OPS));
        (*core::ptr::addr_of_mut!(FREED)).clear();
        (*core::ptr::addr_of_mut!(SRC_LISTS)).clear();
        (*core::ptr::addr_of_mut!(HEAP_OPS)).free = recording_free;
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(SQLITE_SRC_LIST_DELETE),
            recording_src_list_delete,
        );
        body();
        core::ptr::write(core::ptr::addr_of_mut!(HEAP_OPS), saved_heap_ops);
        restore_defaults();
    }

    #[repr(align(32))]
    struct TrackedBlock([u8; 256]);

    impl TrackedBlock {
        fn new(size: i32) -> Self {
            let mut block = TrackedBlock([0; 256]);
            block.0[0..4].copy_from_slice(&size.to_le_bytes());
            let pad = (32 - BLOCK_HEADER_SIZE) as u32;
            block.0[28..32].copy_from_slice(&pad.to_le_bytes());
            block
        }

        fn raw(&mut self) -> *mut u8 {
            self.0.as_mut_ptr()
        }

        fn payload(&mut self) -> *mut u8 {
            unsafe { self.0.as_mut_ptr().add(32) }
        }
    }

    fn write_empty_list(block: &mut TrackedBlock) -> *mut u8 {
        let list = block.payload() as *mut super::super::expr_list_delete::ExprList;
        unsafe {
            core::ptr::write(
                list,
                super::super::expr_list_delete::ExprList {
                    n_expr: 0,
                    n_alloc: 0,
                    _gap_08: [0xa5; 0x0c - 0x08],
                    items: core::ptr::null_mut(),
                },
            );
        }
        list as *mut u8
    }

    fn write_expr(block: &mut TrackedBlock) -> *mut u8 {
        block.payload()
    }

    fn write_select(block: &mut TrackedBlock, select: Select) -> *mut u8 {
        let ptr = block.payload() as *mut Select;
        unsafe { core::ptr::write(ptr, select) };
        ptr as *mut u8
    }

    #[test]
    fn null_is_a_no_op() {
        let _heap = mock_heap();
        let _guard = SLOT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            with_slots(|| {
                select_delete(core::ptr::null_mut());
            });
        }
        assert!(freed().is_empty(), "NULL frees nothing");
        assert!(src_lists().is_empty(), "the source-list seam is not consulted");
    }

    #[test]
    fn owned_fields_free_in_order_and_the_source_list_is_handed_through() {
        let _heap = mock_heap();
        let _guard = SLOT_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let mut top_elist_block = TrackedBlock::new(core::mem::size_of::<super::super::expr_list_delete::ExprList>() as i32);
        let mut top_where_block = TrackedBlock::new(core::mem::size_of::<super::super::expr_delete::Expr>() as i32);
        let mut top_group_block = TrackedBlock::new(core::mem::size_of::<super::super::expr_list_delete::ExprList>() as i32);
        let mut top_having_block = TrackedBlock::new(core::mem::size_of::<super::super::expr_delete::Expr>() as i32);
        let mut top_order_block = TrackedBlock::new(core::mem::size_of::<super::super::expr_list_delete::ExprList>() as i32);
        let mut top_limit_block = TrackedBlock::new(core::mem::size_of::<super::super::expr_delete::Expr>() as i32);
        let mut top_offset_block = TrackedBlock::new(core::mem::size_of::<super::super::expr_delete::Expr>() as i32);
        let mut prior_where_block = TrackedBlock::new(core::mem::size_of::<super::super::expr_delete::Expr>() as i32);
        let mut prior_block = TrackedBlock::new(core::mem::size_of::<Select>() as i32);
        let mut top_block = TrackedBlock::new(core::mem::size_of::<Select>() as i32);

        let top_elist = write_empty_list(&mut top_elist_block);
        let top_group = write_empty_list(&mut top_group_block);
        let top_order = write_empty_list(&mut top_order_block);
        let top_where = write_expr(&mut top_where_block);
        let top_having = write_expr(&mut top_having_block);
        let top_limit = write_expr(&mut top_limit_block);
        let top_offset = write_expr(&mut top_offset_block);
        let prior_where = write_expr(&mut prior_where_block);

        let prior = Select {
            p_elist: core::ptr::null_mut(),
            _gap_04: [0xa5; 0x0c - 0x04],
            p_src: core::ptr::null_mut(),
            p_where: prior_where,
            p_group_by: core::ptr::null_mut(),
            p_having: core::ptr::null_mut(),
            p_order_by: core::ptr::null_mut(),
            p_prior: core::ptr::null_mut(),
            _gap_24: [0xa5; 0x2c - 0x24],
            p_limit: core::ptr::null_mut(),
            p_offset: core::ptr::null_mut(),
        };
        let prior_ptr = write_select(&mut prior_block, prior) as *mut Select;

        let top = Select {
            p_elist: top_elist,
            _gap_04: [0xa5; 0x0c - 0x04],
            p_src: 0x5a5a_5a5a as *mut u8,
            p_where: top_where,
            p_group_by: top_group,
            p_having: top_having,
            p_order_by: top_order,
            p_prior: prior_ptr,
            _gap_24: [0xa5; 0x2c - 0x24],
            p_limit: top_limit,
            p_offset: top_offset,
        };
        let top_ptr = write_select(&mut top_block, top);

        unsafe {
            with_slots(|| {
                select_delete(top_ptr);
            });
        }

        assert_eq!(
            src_lists(),
            std::vec![0x5a5a_5a5a as *mut u8, core::ptr::null_mut()],
            "p_src is handed through verbatim, including the null prior"
        );
        assert_eq!(
            freed(),
            std::vec![
                (top_elist_block.raw(), TAG_TRACKED),
                (top_where_block.raw(), TAG_TRACKED),
                (top_group_block.raw(), TAG_TRACKED),
                (top_having_block.raw(), TAG_TRACKED),
                (top_order_block.raw(), TAG_TRACKED),
                (prior_where_block.raw(), TAG_TRACKED),
                (prior_block.raw(), TAG_TRACKED),
                (top_limit_block.raw(), TAG_TRACKED),
                (top_offset_block.raw(), TAG_TRACKED),
                (top_block.raw(), TAG_TRACKED),
            ],
            "owned children free before the select block, and the prior chain recurses in place"
        );
    }
}
