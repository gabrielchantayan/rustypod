//! Deep-copying SQLite identifier lists.
//!
//! - `id_list_dup` — original: `FUN_0837b160` @ 0x0837b160 (164 bytes;
//!   4 direct `bl` call sites, binary-scanned).
//!
//! Raw ARM spans 0x0837b160..0x0837b203; the next function's `stmdb` opens
//! at 0x0837b204. A whole-image ARM B/BL decode found four unconditional
//! direct `bl` callers (0x082c42ac, 0x083701a4, 0x08384548, and 0x08391a08)
//! and no predicated `bl`. The body itself issues four `bl`s: two to
//! `db_malloc_raw` @ 0x08374960, one to `db_str_dup` @ 0x08374a14, and one
//! to `tracked_free` @ 0x083906f4.
//!
//! Algorithm (`sqlite3IdListDup`): NULL in, NULL out. The new 12-byte
//! header is allocated first; on failure NULL is returned. The source
//! `n_id` at +0x04 seeds both `n_alloc` (+0x08) and `n_id` (+0x04) of the
//! copy, and a fresh `n_id << 3`-byte item array is allocated into +0x00.
//! If the array allocation fails the header goes straight to
//! `tracked_free` and NULL is returned. Otherwise a signed, pre-tested
//! `bgt` loop re-reads the source `n_id` each pass: every 8-byte item's
//! `z_name` (+0x00) is deep-copied through `db_str_dup` and the trailing
//! index word (+0x04) is copied verbatim. A failed name duplication is
//! NOT abortive — the NULL is stored and the walk continues.
//!
//! Deliberate deviation: the [`IdList`]/[`IdListItem`] `#[repr(C)]` views
//! from [`crate::sqlite::id_list_delete`] replace word addressing so
//! pointer fields stay disjoint in host tests; the 12-byte header and
//! 8-byte stride are asserted there on 32-bit builds.

use crate::heap::tracked::tracked_free;
use crate::sqlite::id_list_delete::{IdList, IdListItem};
use crate::sqlite::mem::db_malloc_raw;
use crate::sqlite::strdup::db_str_dup;

/// `id_list_dup` — original: `FUN_0837b160` @ 0x0837b160 (164 bytes;
/// 4 direct `bl` call sites, binary-scanned).
///
/// SQLite's `sqlite3IdListDup`: deep-copy `src` on connection `db`.
/// Returns NULL when `src` is NULL or when either allocation fails; on
/// the array-allocation failure path the already-allocated header is
/// released through [`tracked_free`] before returning NULL. Per-item name
/// failures leave a NULL `z_name` in the copy without stopping the loop,
/// exactly like the original.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn id_list_dup(db: *mut u8, src: *const IdList) -> *mut IdList {
    if src.is_null() {
        return core::ptr::null_mut();
    }
    let new = db_malloc_raw(db, 0x0c) as *mut IdList;
    if new.is_null() {
        return core::ptr::null_mut();
    }
    let n_id = (*src).n_id;
    (*new).n_alloc = n_id;
    (*new).n_id = n_id;
    let items = db_malloc_raw(db, n_id.wrapping_shl(3)) as *mut IdListItem;
    (*new).items = items;
    if items.is_null() {
        tracked_free(new.cast());
        return core::ptr::null_mut();
    }
    let mut index: i32 = 0;
    while (*src).n_id > index {
        let dst_item = items.add(index as usize);
        let src_item = (*src).items.add(index as usize);
        (*dst_item).z_name = db_str_dup(db, (*src_item).z_name);
        (*dst_item).index = (*src_item).index;
        index += 1;
    }
    new
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::tracked::{BLOCK_HEADER_SIZE, TAG_TRACKED};
    use crate::heap::types::HeapDescriptorDescriptor;
    use crate::heap::veneers::{tests::mock_heap, HEAP_OPS};
    use crate::sqlite::mem::tests::{Connection, OPS_LOCK};
    use crate::sqlite::mem::{DbMemOps, DB_MEM_OPS};
    use std::sync::Mutex;
    use std::vec::Vec;

    static FREE_LOCK: Mutex<()> = Mutex::new(());
    static mut FREED: Vec<(*mut u8, usize)> = Vec::new();
    /// Blocks the queue allocator hands out, in request order; NULL fails.
    static mut ALLOCATION_QUEUE: Vec<*mut u8> = Vec::new();
    static mut ALLOCATION_LOG: Vec<i32> = Vec::new();

    unsafe extern "C" fn queue_malloc(n: i32) -> *mut u8 {
        (*core::ptr::addr_of_mut!(ALLOCATION_LOG)).push(n);
        let queue = core::ptr::addr_of_mut!(ALLOCATION_QUEUE);
        if (*queue).is_empty() {
            return core::ptr::null_mut();
        }
        (*queue).remove(0)
    }

    unsafe extern "C" fn queue_realloc(_p: *mut u8, n: i32) -> *mut u8 {
        queue_malloc(n)
    }

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

    fn allocation_log() -> Vec<i32> {
        unsafe { (*core::ptr::addr_of!(ALLOCATION_LOG)).clone() }
    }

    /// Installs the queue allocator, the recording free, and the block
    /// queue. Both global slots are restored on scope exit; `blocks` must
    /// outlive the guard.
    struct Rig {
        saved_mem: DbMemOps,
        saved_heap: crate::heap::veneers::HeapVeneerOps,
    }

    unsafe fn install(blocks: &[*mut u8]) -> Rig {
        let rig = Rig {
            saved_mem: core::ptr::read(core::ptr::addr_of!(DB_MEM_OPS)),
            saved_heap: core::ptr::read(core::ptr::addr_of!(HEAP_OPS)),
        };
        (*core::ptr::addr_of_mut!(FREED)).clear();
        (*core::ptr::addr_of_mut!(ALLOCATION_LOG)).clear();
        (*core::ptr::addr_of_mut!(ALLOCATION_QUEUE)).extend_from_slice(blocks);
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(DB_MEM_OPS),
            DbMemOps { malloc: queue_malloc, realloc: queue_realloc },
        );
        (*core::ptr::addr_of_mut!(HEAP_OPS)).free = recording_free;
        rig
    }

    impl Drop for Rig {
        fn drop(&mut self) {
            unsafe {
                core::ptr::write_volatile(core::ptr::addr_of_mut!(DB_MEM_OPS), self.saved_mem);
                core::ptr::write(core::ptr::addr_of_mut!(HEAP_OPS), self.saved_heap);
            }
        }
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

    unsafe fn list_in(block: &mut TrackedBlock, entries: &[( *mut u8, i32)]) -> *const IdList {
        let items = block.payload() as *mut IdListItem;
        for (index, &(z_name, item_index)) in entries.iter().enumerate() {
            core::ptr::write(items.add(index), IdListItem { z_name, index: item_index });
        }
        let list = block.payload().add(64) as *mut IdList;
        core::ptr::write(
            list,
            IdList { items, n_id: entries.len() as i32, n_alloc: entries.len() as i32 },
        );
        list
    }

    /// `name\0` in an owned buffer; returns (buffer, pointer).
    fn name(text: &str) -> (Vec<u8>, *mut u8) {
        let mut buf = Vec::from(text.as_bytes());
        buf.push(0);
        let ptr = buf.as_mut_ptr();
        (buf, ptr)
    }

    #[test]
    fn null_source_returns_null_without_touching_the_heap() {
        let _mem_guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _rig = unsafe { install(&[]) };
        let mut db = Connection::healthy();

        assert!(unsafe { id_list_dup(db.ptr(), core::ptr::null()) }.is_null());
        assert!(allocation_log().is_empty(), "moveq/bxeq: no allocation for NULL");
    }

    #[test]
    fn header_allocation_failure_returns_null() {
        let _mem_guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _rig = unsafe { install(&[]) };
        let mut db = Connection::healthy();
        let mut source = TrackedBlock::new(0x0c);
        let list = unsafe { list_in(&mut source, &[]) };

        assert!(unsafe { id_list_dup(db.ptr(), list) }.is_null());
        assert_eq!(allocation_log(), std::vec![0x0c], "only the 12-byte header request");
        assert_eq!(db.failed_flag(), 1, "db_malloc_raw records the failure");
        assert!(freed().is_empty(), "nothing was allocated, nothing is freed");
    }

    #[test]
    fn array_allocation_failure_frees_the_header() {
        let _heap = mock_heap();
        let _mem_guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _free_guard = FREE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut header = TrackedBlock::new(0x0c);
        let _rig = unsafe { install(&[header.payload()]) };
        let mut db = Connection::healthy();
        let mut source = TrackedBlock::new(0x0c);
        let list = unsafe { list_in(&mut source, &[(core::ptr::null_mut(), 7)]) };

        assert!(unsafe { id_list_dup(db.ptr(), list) }.is_null());
        assert_eq!(
            allocation_log(),
            std::vec![0x0c, 8],
            "header (12) then one 8-byte item array"
        );
        assert_eq!(
            freed(),
            std::vec![(header.raw(), TAG_TRACKED)],
            "the header goes straight to tracked_free"
        );
    }

    #[test]
    fn zero_count_still_allocates_the_array_and_skips_the_loop() {
        let _mem_guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut header = TrackedBlock::new(0x0c);
        let mut array = TrackedBlock::new(0);
        let _rig = unsafe { install(&[header.payload(), array.payload()]) };
        let mut db = Connection::healthy();
        let mut source = TrackedBlock::new(0x0c);
        let list = unsafe { list_in(&mut source, &[]) };

        let dup = unsafe { id_list_dup(db.ptr(), list) } as *mut IdList;
        assert_eq!(dup, header.payload() as *mut IdList);
        unsafe {
            assert_eq!((*dup).n_id, 0);
            assert_eq!((*dup).n_alloc, 0);
            assert_eq!((*dup).items, array.payload() as *mut IdListItem);
        }
        assert_eq!(allocation_log(), std::vec![0x0c, 0], "n_id << 3 is 0");
    }

    #[test]
    fn copies_names_through_db_str_dup_and_indices_verbatim() {
        let _mem_guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut header = TrackedBlock::new(0x0c);
        let mut array = TrackedBlock::new(16);
        let mut dup_a = TrackedBlock::new(8);
        let mut dup_b = TrackedBlock::new(8);
        let _rig = unsafe {
            install(&[header.payload(), array.payload(), dup_a.payload(), dup_b.payload()])
        };
        let mut db = Connection::healthy();

        let (name_a, ptr_a) = name("alpha");
        let (name_b, ptr_b) = name("beta");
        let mut source = TrackedBlock::new(0x0c);
        let list = unsafe { list_in(&mut source, &[(ptr_a, 11), (ptr_b, -3)]) };

        let dup = unsafe { id_list_dup(db.ptr(), list) };
        assert_eq!(dup, header.payload() as *mut IdList);
        unsafe {
            assert_eq!((*dup).n_id, 2);
            assert_eq!((*dup).n_alloc, 2, "n_alloc mirrors n_id");
            let items = (*dup).items;
            assert_eq!(items, array.payload() as *mut IdListItem);
            assert_eq!((*items).z_name, dup_a.payload());
            assert_eq!((*items).index, 11, "index word copied verbatim");
            let second = items.add(1);
            assert_eq!((*second).z_name, dup_b.payload());
            assert_eq!((*second).index, -3);
        }
        assert_eq!(
            &unsafe { core::slice::from_raw_parts(dup_a.payload(), 6) },
            b"alpha\0",
            "name text deep-copied, not aliased"
        );
        assert_eq!(
            &unsafe { core::slice::from_raw_parts(dup_b.payload(), 5) },
            b"beta\0"
        );
        assert_eq!(
            allocation_log(),
            std::vec![0x0c, 16, 6, 5],
            "header, n_id << 3 array, then len + 1 per name"
        );
        drop(name_a);
        drop(name_b);
    }

    #[test]
    fn a_null_name_passes_through_without_allocating() {
        let _mem_guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut header = TrackedBlock::new(0x0c);
        let mut array = TrackedBlock::new(8);
        let _rig = unsafe { install(&[header.payload(), array.payload()]) };
        let mut db = Connection::healthy();
        let mut source = TrackedBlock::new(0x0c);
        let list = unsafe { list_in(&mut source, &[(core::ptr::null_mut(), 42)]) };

        let dup = unsafe { id_list_dup(db.ptr(), list) };
        assert!(!dup.is_null());
        unsafe {
            assert!((*(*dup).items).z_name.is_null(), "NULL z_name stays NULL");
            assert_eq!((*(*dup).items).index, 42);
        }
        assert_eq!(
            allocation_log(),
            std::vec![0x0c, 8],
            "db_str_dup does not allocate for a NULL name"
        );
        assert_eq!(db.failed_flag(), 0, "a NULL name is not a failure");
    }

    #[test]
    fn a_failed_name_dup_stores_null_and_keeps_walking() {
        let _mem_guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut header = TrackedBlock::new(0x0c);
        let mut array = TrackedBlock::new(16);
        // The first name's allocation fails (NULL slot); once the sticky
        // flag is set, db_str_dup short-circuits the second name too.
        let _rig =
            unsafe { install(&[header.payload(), array.payload(), core::ptr::null_mut()]) };
        let mut db = Connection::healthy();

        let (name_a, ptr_a) = name("one");
        let (name_b, ptr_b) = name("two");
        let mut source = TrackedBlock::new(0x0c);
        let list = unsafe { list_in(&mut source, &[(ptr_a, 1), (ptr_b, 2)]) };

        let dup = unsafe { id_list_dup(db.ptr(), list) };
        assert!(!dup.is_null(), "name failures do not abort the duplication");
        unsafe {
            assert!((*(*dup).items).z_name.is_null());
            assert!((*(*dup).items.add(1)).z_name.is_null(), "sticky failure short-circuits");
            assert_eq!((*(*dup).items).index, 1);
            assert_eq!((*(*dup).items.add(1)).index, 2);
        }
        assert_eq!(db.failed_flag(), 1);
        drop(name_a);
        drop(name_b);
    }
}
