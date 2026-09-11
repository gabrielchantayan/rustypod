//! Releasing SQLite identifier lists.
//!
//! - `id_list_delete` — original: `FUN_0837b11c` @ 0x0837b11c (68 bytes;
//!   9 direct `bl` call sites, binary-scanned).
//!
//! Raw ARM spans 0x0837b11c..0x0837b15f; the separately linked identifier
//! list constructor begins at 0x0837b160. A whole-image ARM B/BL decode found
//! nine unconditional direct `bl` callers (0x083701d4, 0x08375358,
//! 0x083753b8, 0x0837b0f4, 0x0837ca68, 0x08384330, 0x08384434,
//! 0x08385204, and 0x08391a14), no predicated `bl`, and one unconditional
//! tail-branch caller at 0x083997c4.
//!
//! Algorithm: NULL returns immediately. Otherwise a signed, pre-tested `bgt`
//! walk re-reads `n_id` at +0x04 and frees the name word in each 8-byte item
//! from the array at +0x00. It then frees the item array and tail-branches to
//! `sqlite3_free` for the list header. `sqlite3_free` is the ported
//! [`tracked_free`], whose NULL guard supplies the original's unconditional
//! NULL-item and NULL-name behavior.
//!
//! Deliberate deviation: named `#[repr(C)]` views replace the original
//! word-addressed structures so pointer fields remain disjoint in host tests.
//! The target's offsets and 8-byte item stride are asserted on 32-bit builds.

use crate::heap::tracked::tracked_free;

/// SQLite's `IdList` header, only the fields this destructor reads.
#[repr(C)]
pub struct IdList {
    /// +0x00: pointer to `IdListItem` entries.
    pub items: *mut IdListItem,
    /// +0x04: number of identifier entries; the ARM loop compares signed.
    pub n_id: i32,
    /// +0x08: allocated item capacity, not read by this destructor.
    pub n_alloc: i32,
}

/// One `IdList` entry, 8 bytes on the ARM target.
#[repr(C)]
pub struct IdListItem {
    /// +0x00: heap-owned identifier text, freed unconditionally.
    pub z_name: *mut u8,
    /// +0x04: parser index, not read by this destructor.
    pub index: i32,
}

#[cfg(target_pointer_width = "32")]
const _ID_LIST_ITEMS_OFFSET: [u8; 0x00] = [0; core::mem::offset_of!(IdList, items)];
#[cfg(target_pointer_width = "32")]
const _ID_LIST_N_ID_OFFSET: [u8; 0x04] = [0; core::mem::offset_of!(IdList, n_id)];
#[cfg(target_pointer_width = "32")]
const _ID_LIST_N_ALLOC_OFFSET: [u8; 0x08] = [0; core::mem::offset_of!(IdList, n_alloc)];
#[cfg(target_pointer_width = "32")]
const _ID_LIST_HEADER_SIZE: [u8; 0x0c] = [0; core::mem::size_of::<IdList>()];
#[cfg(target_pointer_width = "32")]
const _ID_LIST_ITEM_NAME_OFFSET: [u8; 0x00] = [0; core::mem::offset_of!(IdListItem, z_name)];
#[cfg(target_pointer_width = "32")]
const _ID_LIST_ITEM_INDEX_OFFSET: [u8; 0x04] = [0; core::mem::offset_of!(IdListItem, index)];
#[cfg(target_pointer_width = "32")]
const _ID_LIST_ITEM_STRIDE: [u8; 0x08] = [0; core::mem::size_of::<IdListItem>()];

/// `id_list_delete` — original: `FUN_0837b11c` @ 0x0837b11c (68 bytes;
/// 9 direct `bl` call sites, binary-scanned).
///
/// SQLite's `sqlite3IdListDelete`: NULL is a no-op. A positive signed `n_id`
/// releases each `z_name` in array order, then the item array and header go
/// through [`tracked_free`]. The original tail-branches to the final free;
/// this Rust function returns after its equivalent direct call.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn id_list_delete(id_list: *mut u8) {
    if id_list.is_null() {
        return;
    }

    let id_list = id_list as *const IdList;
    let mut item = (*id_list).items;
    let mut index: i32 = 0;
    while (*id_list).n_id > index {
        tracked_free((*item).z_name);
        index += 1;
        item = item.add(1);
    }
    tracked_free((*id_list).items.cast());
    tracked_free(id_list as *mut u8);
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

    unsafe fn with_recording_free(body: impl FnOnce()) {
        let saved_heap_ops = core::ptr::read(core::ptr::addr_of!(HEAP_OPS));
        (*core::ptr::addr_of_mut!(FREED)).clear();
        (*core::ptr::addr_of_mut!(HEAP_OPS)).free = recording_free;
        body();
        core::ptr::write(core::ptr::addr_of_mut!(HEAP_OPS), saved_heap_ops);
    }

    /// A hand-built tag-57 tracked block with payload at raw + 32.
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
            unsafe { self.0.as_mut_ptr().add(32) }
        }
    }

    unsafe fn list_in(
        block: &mut TrackedBlock,
        n_id: i32,
        items: *mut IdListItem,
    ) -> *mut u8 {
        let list = block.payload() as *mut IdList;
        core::ptr::write(list, IdList { items, n_id, n_alloc: n_id });
        list.cast()
    }

    unsafe fn items_in(
        block: &mut TrackedBlock,
        entries: &[( *mut u8, i32)],
    ) -> *mut IdListItem {
        let items = block.payload() as *mut IdListItem;
        for (index, &(z_name, item_index)) in entries.iter().enumerate() {
            core::ptr::write(items.add(index), IdListItem { z_name, index: item_index });
        }
        items
    }

    #[test]
    fn null_is_a_no_op() {
        let _heap = mock_heap();
        let _guard = SLOT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe { with_recording_free(|| id_list_delete(core::ptr::null_mut())) };
        assert!(freed().is_empty(), "movs/popeq: NULL frees nothing");
    }

    #[test]
    fn zero_count_frees_the_array_then_the_header() {
        let _heap = mock_heap();
        let _guard = SLOT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut header = TrackedBlock::new(0x0c);
        let mut array = TrackedBlock::new(8);
        unsafe {
            let items = items_in(&mut array, &[]);
            let list = list_in(&mut header, 0, items);
            with_recording_free(|| id_list_delete(list));
        }
        assert_eq!(
            freed(),
            std::vec![(array.raw(), TAG_TRACKED), (header.raw(), TAG_TRACKED)],
            "bgt skips zero entries but still frees the array before the header"
        );
    }

    #[test]
    fn negative_count_and_null_array_free_only_the_header() {
        let _heap = mock_heap();
        let _guard = SLOT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut header = TrackedBlock::new(0x0c);
        unsafe {
            let list = list_in(&mut header, -1, core::ptr::null_mut());
            with_recording_free(|| id_list_delete(list));
        }
        assert_eq!(
            freed(),
            std::vec![(header.raw(), TAG_TRACKED)],
            "signed bgt skips negative entries; tracked_free ignores the NULL array"
        );
    }

    #[test]
    fn names_are_freed_in_array_order_before_items_and_header() {
        let _heap = mock_heap();
        let _guard = SLOT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut header = TrackedBlock::new(0x0c);
        let mut array = TrackedBlock::new(0x10);
        let mut name0 = TrackedBlock::new(6);
        let mut name1 = TrackedBlock::new(8);
        unsafe {
            let items = items_in(
                &mut array,
                &[(name0.payload(), 7), (core::ptr::null_mut(), 11), (name1.payload(), -1)],
            );
            let list = list_in(&mut header, 3, items);
            with_recording_free(|| id_list_delete(list));
        }
        assert_eq!(
            freed(),
            std::vec![
                (name0.raw(), TAG_TRACKED),
                (name1.raw(), TAG_TRACKED),
                (array.raw(), TAG_TRACKED),
                (header.raw(), TAG_TRACKED),
            ],
            "each z_name is attempted in order; NULL is the free callee's no-op"
        );
    }
}
