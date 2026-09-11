//! Releasing SQLite FROM-clause source lists.
//!
//! - `src_list_delete` — original: `FUN_083843e8` @ 0x083843e8 (112
//!   bytes; 9 direct `bl` call sites, binary-scanned).
//!
//! Raw ARM spans 0x083843e8..0x08384454 inclusive; the separately linked
//! constructor begins at 0x08384458. NULL is a no-op. Otherwise, the
//! signed `n_src` header count is re-read for each of the inline, 0x30-byte
//! `SrcListItem`s beginning at +0x08. Each item releases its database, table
//! name, and alias strings; releases its table; then tears down its SELECT,
//! ON expression, and USING identifier list in that order. Finally the list
//! header tail-branches to the tracked allocator.
//!
//! The table releaser at 0x0837521c and identifier-list releaser at
//! 0x0837b11c are real ARM entries but are not yet ledger-ported, so their
//! calls remain volatile dispatch seams with no-op defaults. The other four
//! callees are direct calls to existing ports. `#[repr(C)]` views preserve
//! target offsets; their pointer fields deliberately widen for host tests.

use super::expr_delete::expr_delete;
use super::select_delete::select_delete;
use crate::heap::tracked::tracked_free;

/// The unported table release helper at 0x0837521c.
pub type TableReleaseFn = unsafe extern "C" fn(table: *mut u8);

/// The unported identifier-list release helper at 0x0837b11c.
pub type IdListReleaseFn = unsafe extern "C" fn(id_list: *mut u8);

/// Default for the unported table release helper.
pub(crate) unsafe extern "C" fn missing_table_release(_table: *mut u8) {}

/// Default for the unported identifier-list release helper.
pub(crate) unsafe extern "C" fn missing_id_list_release(_id_list: *mut u8) {}

/// Active target for the 0x0837521c table-release call.
pub static mut SQLITE_TABLE_RELEASE: TableReleaseFn = missing_table_release;

/// Active target for the 0x0837b11c identifier-list-release call.
pub static mut SQLITE_ID_LIST_RELEASE: IdListReleaseFn = missing_id_list_release;

#[inline(always)]
fn table_release_op() -> TableReleaseFn {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(SQLITE_TABLE_RELEASE)) }
}

#[inline(always)]
fn id_list_release_op() -> IdListReleaseFn {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(SQLITE_ID_LIST_RELEASE)) }
}

/// `SrcList`'s fixed header. Its `a[]` member begins immediately afterward.
#[repr(C)]
pub struct SrcList {
    /// +0x00: number of source entries; the ARM loop treats it as signed.
    pub n_src: i16,
    /// +0x02: allocated source-entry capacity.
    pub n_alloc: i16,
    /// +0x04..+0x08: parser bookkeeping not read by this destructor.
    pub _reserved: [u8; 0x08 - 0x04],
}

/// One inline `SrcList::a[]` entry, 0x30 bytes on the ARM target.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SrcListItem {
    /// +0x00: database qualifier string, released unconditionally.
    pub z_database: *mut u8,
    /// +0x04: table name string, released unconditionally.
    pub z_name: *mut u8,
    /// +0x08: alias string, released unconditionally.
    pub z_alias: *mut u8,
    /// +0x0c: resolved table, released through 0x0837521c.
    pub p_table: *mut u8,
    /// +0x10: subquery SELECT, released through `select_delete`.
    pub p_select: *mut u8,
    /// +0x14: resolved index, not released by this routine.
    pub p_index: *mut u8,
    /// +0x18: packed join/index flags, not read by this routine.
    pub join_flags: u32,
    /// +0x1c: join ON expression, released through `expr_delete`.
    pub p_on: *mut u8,
    /// +0x20: USING identifier list, released through 0x0837b11c.
    pub p_using: *mut u8,
    /// +0x24..+0x30: parser bookkeeping not read by this destructor.
    pub _tail: [u8; 0x30 - 0x24],
}

#[cfg(target_pointer_width = "32")]
const _SRC_LIST_N_SRC_OFFSET: [u8; 0x00] = [0; core::mem::offset_of!(SrcList, n_src)];
#[cfg(target_pointer_width = "32")]
const _SRC_LIST_HEADER_SIZE: [u8; 0x08] = [0; core::mem::size_of::<SrcList>()];
#[cfg(target_pointer_width = "32")]
const _SRC_LIST_ITEM_Z_DATABASE_OFFSET: [u8; 0x00] = [0; core::mem::offset_of!(SrcListItem, z_database)];
#[cfg(target_pointer_width = "32")]
const _SRC_LIST_ITEM_Z_NAME_OFFSET: [u8; 0x04] = [0; core::mem::offset_of!(SrcListItem, z_name)];
#[cfg(target_pointer_width = "32")]
const _SRC_LIST_ITEM_Z_ALIAS_OFFSET: [u8; 0x08] = [0; core::mem::offset_of!(SrcListItem, z_alias)];
#[cfg(target_pointer_width = "32")]
const _SRC_LIST_ITEM_TABLE_OFFSET: [u8; 0x0c] = [0; core::mem::offset_of!(SrcListItem, p_table)];
#[cfg(target_pointer_width = "32")]
const _SRC_LIST_ITEM_SELECT_OFFSET: [u8; 0x10] = [0; core::mem::offset_of!(SrcListItem, p_select)];
#[cfg(target_pointer_width = "32")]
const _SRC_LIST_ITEM_ON_OFFSET: [u8; 0x1c] = [0; core::mem::offset_of!(SrcListItem, p_on)];
#[cfg(target_pointer_width = "32")]
const _SRC_LIST_ITEM_USING_OFFSET: [u8; 0x20] = [0; core::mem::offset_of!(SrcListItem, p_using)];
#[cfg(target_pointer_width = "32")]
const _SRC_LIST_ITEM_STRIDE: [u8; 0x30] = [0; core::mem::size_of::<SrcListItem>()];

/// `src_list_delete` — original: `FUN_083843e8` @ 0x083843e8 (112 bytes;
/// 9 direct `bl` call sites, binary-scanned).
///
/// SQLite's `sqlite3SrcListDelete`: NULL returns immediately. The signed
/// header count controls a pre-tested, inline-item walk; all seven per-item
/// cleanup calls run in retail order before the list block is freed. The
/// current index stays signed and the count is re-read on every iteration,
/// matching the ARM `ldrsh`/`cmp`/`bgt` loop.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn src_list_delete(source_list: *mut u8) {
    if source_list.is_null() {
        return;
    }

    let list = source_list as *const SrcList;
    let mut item = list.add(1).cast::<SrcListItem>();
    let mut index: i32 = 0;
    while i32::from((*list).n_src) > index {
        tracked_free((*item).z_database);
        tracked_free((*item).z_name);
        tracked_free((*item).z_alias);
        (table_release_op())((*item).p_table);
        select_delete((*item).p_select);
        expr_delete((*item).p_on);
        (id_list_release_op())((*item).p_using);
        index += 1;
        item = item.add(1);
    }

    tracked_free(source_list);
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
    static mut TABLES: Vec<*mut u8> = Vec::new();
    static mut ID_LISTS: Vec<*mut u8> = Vec::new();

    unsafe extern "C" fn recording_free(
        _heap: *mut HeapDescriptorDescriptor,
        ptr: *mut u8,
        tag: usize,
    ) {
        (*core::ptr::addr_of_mut!(FREED)).push((ptr, tag));
    }

    unsafe extern "C" fn recording_table_release(table: *mut u8) {
        (*core::ptr::addr_of_mut!(TABLES)).push(table);
    }

    unsafe extern "C" fn recording_id_list_release(id_list: *mut u8) {
        (*core::ptr::addr_of_mut!(ID_LISTS)).push(id_list);
    }

    fn freed() -> Vec<(*mut u8, usize)> {
        unsafe { (*core::ptr::addr_of!(FREED)).clone() }
    }

    fn tables() -> Vec<*mut u8> {
        unsafe { (*core::ptr::addr_of!(TABLES)).clone() }
    }

    fn id_lists() -> Vec<*mut u8> {
        unsafe { (*core::ptr::addr_of!(ID_LISTS)).clone() }
    }

    unsafe fn with_ops(body: impl FnOnce()) {
        let saved_heap_ops = core::ptr::read(core::ptr::addr_of!(HEAP_OPS));
        let saved_table_release = core::ptr::read_volatile(core::ptr::addr_of!(SQLITE_TABLE_RELEASE));
        let saved_id_list_release = core::ptr::read_volatile(core::ptr::addr_of!(SQLITE_ID_LIST_RELEASE));
        (*core::ptr::addr_of_mut!(FREED)).clear();
        (*core::ptr::addr_of_mut!(TABLES)).clear();
        (*core::ptr::addr_of_mut!(ID_LISTS)).clear();
        (*core::ptr::addr_of_mut!(HEAP_OPS)).free = recording_free;
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(SQLITE_TABLE_RELEASE),
            recording_table_release,
        );
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(SQLITE_ID_LIST_RELEASE),
            recording_id_list_release,
        );
        body();
        core::ptr::write(core::ptr::addr_of_mut!(HEAP_OPS), saved_heap_ops);
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(SQLITE_TABLE_RELEASE),
            saved_table_release,
        );
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(SQLITE_ID_LIST_RELEASE),
            saved_id_list_release,
        );
    }

    #[repr(align(32))]
    struct TrackedBlock([u8; 512]);

    impl TrackedBlock {
        fn new(size: i32) -> Self {
            let mut block = TrackedBlock([0; 512]);
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

    unsafe fn source_list_in(
        block: &mut TrackedBlock,
        n_src: i16,
        items: &[SrcListItem],
    ) -> *mut u8 {
        let list = block.payload() as *mut SrcList;
        core::ptr::write(
            list,
            SrcList { n_src, n_alloc: n_src, _reserved: [0xa5; 0x08 - 0x04] },
        );
        let first_item = list.add(1).cast::<SrcListItem>();
        for (index, item) in items.iter().enumerate() {
            core::ptr::write(first_item.add(index), *item);
        }
        list.cast()
    }

    fn item(
        z_database: *mut u8,
        z_name: *mut u8,
        z_alias: *mut u8,
        p_table: *mut u8,
        p_using: *mut u8,
    ) -> SrcListItem {
        SrcListItem {
            z_database,
            z_name,
            z_alias,
            p_table,
            p_select: core::ptr::null_mut(),
            p_index: 0xa5a5_a5a5 as *mut u8,
            join_flags: 0x5a5a_5a5a,
            p_on: core::ptr::null_mut(),
            p_using,
            _tail: [0xa5; 0x30 - 0x24],
        }
    }

    #[test]
    fn null_is_a_no_op() {
        let _heap = mock_heap();
        let _guard = SLOT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe { with_ops(|| src_list_delete(core::ptr::null_mut())) };
        assert!(freed().is_empty(), "NULL frees nothing");
        assert!(tables().is_empty(), "NULL reaches no table release");
        assert!(id_lists().is_empty(), "NULL reaches no identifier-list release");
    }

    #[test]
    fn non_positive_count_skips_items_and_frees_header() {
        let _heap = mock_heap();
        let _guard = SLOT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut header = TrackedBlock::new(0x30);
        let source_list = unsafe { source_list_in(&mut header, -1, &[]) };
        unsafe { with_ops(|| src_list_delete(source_list)) };
        assert_eq!(freed(), std::vec![(header.raw(), TAG_TRACKED)]);
        assert!(tables().is_empty(), "signed bgt skips negative n_src");
        assert!(id_lists().is_empty(), "signed bgt skips negative n_src");
    }

    #[test]
    fn releases_each_item_in_order_then_the_header() {
        let _heap = mock_heap();
        let _guard = SLOT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut header = TrackedBlock::new(0x80);
        let mut database0 = TrackedBlock::new(8);
        let mut name0 = TrackedBlock::new(8);
        let mut alias0 = TrackedBlock::new(8);
        let mut database1 = TrackedBlock::new(8);
        let mut name1 = TrackedBlock::new(8);
        let mut alias1 = TrackedBlock::new(8);
        let source_list = unsafe {
            source_list_in(
                &mut header,
                2,
                &[
                    item(
                        database0.payload(), name0.payload(), alias0.payload(),
                        0x1111_1111 as *mut u8, 0x2222_2222 as *mut u8,
                    ),
                    item(
                        database1.payload(), name1.payload(), alias1.payload(),
                        0x3333_3333 as *mut u8, 0x4444_4444 as *mut u8,
                    ),
                ],
            )
        };

        unsafe { with_ops(|| src_list_delete(source_list)) };

        assert_eq!(
            freed(),
            std::vec![
                (database0.raw(), TAG_TRACKED),
                (name0.raw(), TAG_TRACKED),
                (alias0.raw(), TAG_TRACKED),
                (database1.raw(), TAG_TRACKED),
                (name1.raw(), TAG_TRACKED),
                (alias1.raw(), TAG_TRACKED),
                (header.raw(), TAG_TRACKED),
            ],
            "database, name, and alias free before each item's other cleanup"
        );
        assert_eq!(
            tables(),
            std::vec![0x1111_1111 as *mut u8, 0x3333_3333 as *mut u8],
            "table releases follow the three strings in inline-item order"
        );
        assert_eq!(
            id_lists(),
            std::vec![0x2222_2222 as *mut u8, 0x4444_4444 as *mut u8],
            "identifier-list releases complete each item before the next"
        );
    }
}
