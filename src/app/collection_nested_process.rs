//! collection_nested_process — `FUN_08210fc0` @ `0x08210fc0`.
//!
//! Raw A32 words establish 96 bytes, ending at the next prologue at
//! `0x08211020`. Four plain BLs, zero predicated BLs, and one virtual BLX
//! occur in the body; whole-image decoding finds two plain BL callers
//! (`0x08211c88`, `0x082120f0`) and no predicated BL callers.
//!
//! Walk the supplied collection, pass each item's embedded collection at
//! byte +8 to retail `0x08211460` with the unchanged context, then invoke
//! the outer collection's virtual slot +0x30 and invalidate the cursor.
//! Deviations: Ghidra's extra r2/r3 arguments are stack-local cursor storage,
//! not inputs. The unported nested processor retains its exact address ABI;
//! host execution substitutes that operation. No stronger meaning is assigned
//! to the virtual slot. As with existing cursor ports, incidental r0 is void.
//! LLVM removes the final cursor invalidation because the local is dead;
//! no caller or virtual operation can observe that final stack-local write.

use crate::util::cursor::{Collection, Cursor, cursor_init, cursor_advance, cursor_invalidate};

pub type NestedCollectionProcess = unsafe extern "C" fn(*mut u8, *mut Collection);

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_nested_process(_context: *mut u8, _collection: *mut Collection) {
    panic!("install nested collection processor before host execution")
}

#[cfg(not(target_os = "none"))]
pub static mut NESTED_COLLECTION_PROCESS: NestedCollectionProcess = missing_nested_process;

#[inline(always)]
unsafe fn process_nested(context: *mut u8, collection: *mut Collection) {
    #[cfg(target_os = "none")]
    let process: NestedCollectionProcess = core::mem::transmute(0x0821_1460usize);
    #[cfg(not(target_os = "none"))]
    let process = core::ptr::read_volatile(core::ptr::addr_of!(NESTED_COLLECTION_PROCESS));
    process(context, collection);
}

/// # Safety
/// `collection` must support cursor item_at and virtual slot +0x30 with ABI
/// `void(Collection *)`. Each yielded item must contain a valid collection
/// at byte +8, and `context` must satisfy retail 0x08211460's requirements.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn collection_nested_process(context: *mut u8, collection: *mut Collection) {
    let mut cursor = Cursor { collection: core::ptr::null_mut(), index: 0 };
    cursor_init(&mut cursor, collection);
    let mut item = core::ptr::null_mut::<u32>();
    while cursor_advance(&mut cursor, core::ptr::addr_of_mut!(item).cast()) != 0 {
        process_nested(context, item.add(2).cast());
    }
    let finish: unsafe extern "C" fn(*mut Collection) =
        core::mem::transmute((*(*collection).vtable).unresolved[12]);
    finish(collection);
    cursor_invalidate(&mut cursor);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::util::cursor::CollectionVtable;
    use std::vec::Vec;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());

    #[repr(C)]
    struct Fixture {
        collection: Collection,
        items: [[u32; 8]; 3],
        count: usize,
        append_during_processing: bool,
        events: Vec<(u32, usize)>,
    }

    unsafe extern "C" fn item_at(collection: *mut Collection, index: i32, out: *mut u8) -> u32 {
        let fixture = &mut *collection.cast::<Fixture>();
        fixture.events.push((0, index as usize));
        if index as usize >= fixture.count { return 0; }
        out.cast::<*mut u32>().write(fixture.items[index as usize].as_mut_ptr());
        7 // Any nonzero result must continue the walk.
    }

    unsafe extern "C" fn nested(context: *mut u8, collection: *mut Collection) {
        let fixture = &mut *context.cast::<Fixture>();
        let index = fixture.items.iter().position(|item|
            item.as_ptr().add(2).cast::<Collection>() == collection).unwrap();
        fixture.events.push((1, index));
        if fixture.append_during_processing { fixture.count = 3; }
    }

    unsafe extern "C" fn finish(collection: *mut Collection) {
        let fixture = &mut *collection.cast::<Fixture>();
        fixture.events.push((2, fixture.count));
        fixture.count = 0;
    }

    fn exercise(count: usize, append: bool, expected: &[(u32, usize)]) {
        let _lock = LOCK.lock();
        let mut table = CollectionVtable { unresolved: [0; 15], item_at };
        table.unresolved[12] = finish as *const () as usize;
        let mut fixture = Fixture {
            collection: Collection { vtable: &table }, items: [[0xa5a5a5a5; 8]; 3],
            count, append_during_processing: append, events: Vec::new(),
        };
        unsafe {
            let old = NESTED_COLLECTION_PROCESS;
            NESTED_COLLECTION_PROCESS = nested;
            let context = core::ptr::addr_of_mut!(fixture).cast();
            collection_nested_process(context, &mut fixture.collection);
            NESTED_COLLECTION_PROCESS = old;
        }
        assert_eq!(fixture.events, expected);
        assert_eq!(fixture.count, 0);
        assert_eq!(fixture.items, [[0xa5a5a5a5; 8]; 3]);
    }

    #[test]
    fn empty_collection_still_finishes() {
        exercise(0, false, &[(0, 0), (2, 0)]);
    }

    #[test]
    fn processes_all_items_before_finishing() {
        exercise(3, false, &[(0, 0), (1, 0), (0, 1), (1, 1), (0, 2), (1, 2), (0, 3), (2, 3)]);
    }

    #[test]
    fn iteration_observes_items_added_by_nested_processor() {
        exercise(1, true, &[(0, 0), (1, 0), (0, 1), (1, 1), (0, 2), (1, 2), (0, 3), (2, 3)]);
    }
}
