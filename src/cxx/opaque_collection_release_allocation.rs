//! Deletes the string pair referenced by the first occupied collection cell.
//!
//! Original FUN_083d0738 @ 0x083d0738, 88 bytes; two plain BLs and
//! no predicated BLs. Calls string_pair_destroy at 0x083d0778, then
//! operator_delete at 0x083d077c. The existing first-occupied-cell scan
//! is retained. Host cell pointers widen with native pointers.

use crate::heap::veneers::operator_delete;
use crate::cxx::string_object::StringObjectPair;
use crate::cxx::string_pair_destroy::string_pair_destroy;

const COLLECTION_ITEM_SLOT: usize = 0x40 / 4;
type CollectionItemMethod = unsafe extern "C" fn(*mut u8, i32) -> *mut u8;

#[cfg(target_os = "none")]
const COLLECTION_COUNT_OFFSET: usize = 4;
#[cfg(not(target_os = "none"))]
const COLLECTION_COUNT_OFFSET: usize = core::mem::size_of::<usize>();


/// Destroys and deletes the pair referenced by the first occupied cell.
///
/// # Safety
/// `collection` must designate the target layout, have a callable vtable slot
/// `+0x40`, and return readable cell pointers from that slot.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn opaque_collection_release_allocation(collection: *mut u8) {
    if unsafe { collection.add(0x10).read_volatile() } == 0 {
        return;
    }
    let count = unsafe { collection.add(COLLECTION_COUNT_OFFSET).cast::<i32>().read_volatile() };
    for index in 0..count {
        let vtable = unsafe { collection.cast::<*const usize>().read() };
        let item_at: CollectionItemMethod = unsafe { core::mem::transmute(vtable.add(COLLECTION_ITEM_SLOT).read()) };
        let cell = unsafe { item_at(collection, index) };
        let pair = unsafe { cell.cast::<*mut StringObjectPair>().read() };
        if !pair.is_null() {
            let allocation = unsafe { string_pair_destroy(pair) };
            unsafe { operator_delete(allocation.cast()) };
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut CELLS: [*mut u8; 3] = [core::ptr::null_mut(); 3];
    static mut LOOKUPS: [i32; 3] = [0; 3];
    static mut LOOKUP_COUNT: usize = 0;

    unsafe extern "C" fn item_at(_: *mut u8, index: i32) -> *mut u8 {
        unsafe { LOOKUPS[LOOKUP_COUNT] = index; LOOKUP_COUNT += 1; CELLS[index as usize] }
    }

    #[repr(C)]
    struct CollectionFixture { vtable: *const usize, count: i32, padding: [u8; 4], active: u8 }
    struct Bench { _lock: MutexGuard<'static, ()>, _strings: MutexGuard<'static, ()>, _heap: MutexGuard<'static, ()> }

    fn bench() -> Bench {
        let lock = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            CELLS = [core::ptr::null_mut(); 3]; LOOKUPS = [0; 3]; LOOKUP_COUNT = 0;
            Bench { _lock: lock,
                _strings: crate::cxx::string_object::tests::STRING_OBJECT_OPS_TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner()),
                _heap: crate::heap::veneers::tests::mock_heap() }
        }
    }


    #[test]
    fn destroys_and_deletes_only_the_first_occupied_pair() {
        let _bench = bench();
        use crate::cxx::string_object::{StringObject, STRING_OBJECT_VTABLE};
        let string = || StringObject { vtable: core::ptr::null(), payload: core::ptr::null_mut() };
        let mut pair = StringObjectPair { first: string(), second: string() };
        let mut later_pair = StringObjectPair { first: string(), second: string() };
        let mut empty: *mut StringObjectPair = core::ptr::null_mut();
        let mut occupied = &mut pair as *mut StringObjectPair;
        let mut later = &mut later_pair as *mut StringObjectPair;
        unsafe { CELLS = [&mut empty as *mut _ as *mut u8, &mut occupied as *mut _ as *mut u8, &mut later as *mut _ as *mut u8] };
        let mut vtable = [0usize; COLLECTION_ITEM_SLOT + 1];
        vtable[COLLECTION_ITEM_SLOT] = item_at as usize;
        let mut collection = CollectionFixture { vtable: vtable.as_ptr(), count: 3, padding: [0; 4], active: 1 };
        unsafe { opaque_collection_release_allocation((&mut collection as *mut CollectionFixture).cast()) };
        assert_eq!(unsafe { &LOOKUPS[..LOOKUP_COUNT] }, &[0, 1]);
        assert_eq!(pair.first.vtable, &STRING_OBJECT_VTABLE as *const _);
        assert_eq!(pair.second.vtable, &STRING_OBJECT_VTABLE as *const _);
        assert!(later_pair.first.vtable.is_null() && later_pair.second.vtable.is_null());
        assert_eq!(crate::heap::veneers::tests::free_log(), (1, occupied.cast(), 2));
    }

    #[test]
    fn inactive_or_nonpositive_count_skips_lookup_allocation_and_delete() {
        let _bench = bench();
        let mut vtable = [item_at as usize; COLLECTION_ITEM_SLOT + 1];
        let mut collection = CollectionFixture { vtable: vtable.as_ptr(), count: 1, padding: [0; 4], active: 0 };
        unsafe { opaque_collection_release_allocation((&mut collection as *mut CollectionFixture).cast()) };
        collection.active = 1;
        collection.count = -1;
        unsafe { opaque_collection_release_allocation((&mut collection as *mut CollectionFixture).cast()) };
        assert_eq!(unsafe { LOOKUP_COUNT }, 0);
        assert_eq!(crate::heap::veneers::tests::free_log().0, 0);
    }
}
