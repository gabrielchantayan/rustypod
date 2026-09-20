//! Releases the first occupied entry in an opaque polymorphic collection.
//!
//! `collection_release_first_occupied` — original: `FUN_083cfaf8` @
//! **0x083cfaf8**, 88 bytes (`0x083cfaf8..0x083cfb50`). The next real sibling
//! begins with `push {r4,r5,r6,lr}` at `0x083cfb50`. The body has two plain
//! direct `bl` calls (`0x080fe744`, `0x082aad24`), no predicated direct calls,
//! and one indirect `blx` through vtable slot `+0x40`; it has three
//! branch-with-link calls and no predicated form.
//! Its three inbound direct calls are all plain `bl` (`0x0817e458`,
//! `0x083cfba8`, and `0x083cfbe0`); none is predicated.
//!
//! # Algorithm
//!
//! If collection byte `+0x10` is clear, do nothing. Otherwise scan indexes
//! `[0, count)` using its opaque vtable slot `+0x40`. The first returned record
//! whose first word is nonzero has its optional nested object at `+0x04`
//! destructed through that object's vtable slot `+0x04`, then the record is
//! released with tag-2 `operator_delete`; later entries are untouched.
//!
//! # Deliberate deviations
//!
//! The collection-slot and nested-destructor targets are runtime vtable data;
//! their concrete identities are not established. Rust uses normal branches.
//! Host vtable pointers are native-width, so host fixtures place the count and
//! nested-object pointer after that pointer instead of at their four-byte ARM
//! offsets; target builds use the verified ARM offsets.

use crate::heap::veneers::operator_delete;

const COLLECTION_ITEM_SLOT: usize = 0x40 / 4;
type CollectionItemMethod = unsafe extern "C" fn(*mut u8, i32) -> *mut u8;
type NestedDestructor = unsafe extern "C" fn(*mut u8);

#[cfg(target_os = "none")]
const COLLECTION_COUNT_OFFSET: usize = 4;
#[cfg(not(target_os = "none"))]
const COLLECTION_COUNT_OFFSET: usize = core::mem::size_of::<usize>();
#[cfg(target_os = "none")]
const RECORD_NESTED_OFFSET: usize = 4;
#[cfg(not(target_os = "none"))]
const RECORD_NESTED_OFFSET: usize = core::mem::size_of::<usize>();

/// Releases only the first occupied record returned by the collection.
///
/// # Safety
/// `collection` must designate an object whose vtable has a callable slot
/// `+0x40`, byte `+0x10`, and signed count. Each returned record must be
/// readable through its nested-object word and acceptable to `operator_delete`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn collection_release_first_occupied(collection: *mut u8) {
    if unsafe { collection.add(0x10).read_volatile() } == 0 {
        return;
    }
    let count = unsafe { (collection.add(COLLECTION_COUNT_OFFSET) as *const i32).read_volatile() };
    for index in 0..count {
        let vtable = unsafe { (collection as *const *const usize).read() };
        let method: CollectionItemMethod = unsafe { core::mem::transmute(vtable.add(COLLECTION_ITEM_SLOT).read()) };
        let record = unsafe { method(collection, index) };
        if unsafe { (record as *const u32).read_volatile() } != 0 {
            let nested = unsafe { (record.add(RECORD_NESTED_OFFSET) as *const *mut u8).read() };
            if !nested.is_null() {
                let nested_vtable = unsafe { (nested as *const *const usize).read() };
                let destruct: NestedDestructor = unsafe { core::mem::transmute(nested_vtable.add(1).read()) };
                unsafe { destruct(nested) };
            }
            unsafe { operator_delete(record) };
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
    static mut RECORDS: [*mut u8; 3] = [core::ptr::null_mut(); 3];
    static mut LOOKUPS: [i32; 3] = [0; 3];
    static mut LOOKUP_COUNT: usize = 0;
    static mut DESTROYED: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn item_at(_collection: *mut u8, index: i32) -> *mut u8 {
        unsafe { LOOKUPS[LOOKUP_COUNT] = index; LOOKUP_COUNT += 1; RECORDS[index as usize] }
    }
    unsafe extern "C" fn nested_destruct(object: *mut u8) { unsafe { DESTROYED = object }; }

    #[repr(C)]
    struct CollectionFixture { vtable: *const usize, count: i32, padding: [u8; 4], active: u8 }
    #[repr(C)]
    struct RecordFixture { occupied: u32, nested: *mut u8 }
    struct Bench { _lock: MutexGuard<'static, ()>, _heap: MutexGuard<'static, ()> }

    fn bench() -> Bench {
        let lock = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe { RECORDS = [core::ptr::null_mut(); 3]; LOOKUPS = [0; 3]; LOOKUP_COUNT = 0; DESTROYED = core::ptr::null_mut(); }
        Bench { _lock: lock, _heap: crate::heap::veneers::tests::mock_heap() }
    }

    #[test]
    fn skips_empty_records_then_destroys_and_deletes_the_first_occupied_one() {
        let _bench = bench();
        let nested_vtable = [0usize, nested_destruct as usize];
        let mut nested_vtable_pointer = nested_vtable.as_ptr() as *mut u8;
        let mut empty = RecordFixture { occupied: 0, nested: core::ptr::null_mut() };
        let mut occupied = RecordFixture { occupied: 1, nested: &mut nested_vtable_pointer as *mut _ as *mut u8 };
        let mut later = RecordFixture { occupied: 1, nested: core::ptr::null_mut() };
        let mut collection_vtable = [0usize; COLLECTION_ITEM_SLOT + 1];
        collection_vtable[COLLECTION_ITEM_SLOT] = item_at as usize;
        let mut collection = CollectionFixture { vtable: collection_vtable.as_ptr(), count: 3, padding: [0; 4], active: 1 };
        unsafe { RECORDS = [&mut empty as *mut _ as *mut u8, &mut occupied as *mut _ as *mut u8, &mut later as *mut _ as *mut u8] };
        unsafe { collection_release_first_occupied((&mut collection as *mut CollectionFixture).cast()) };
        assert_eq!(unsafe { &LOOKUPS[..LOOKUP_COUNT] }, &[0, 1]);
        assert_eq!(unsafe { DESTROYED }, &mut nested_vtable_pointer as *mut _ as *mut u8);
        assert_eq!(crate::heap::veneers::tests::free_log(), (1, &mut occupied as *mut _ as *mut u8, 2));
    }

    #[test]
    fn inactive_or_nonpositive_count_performs_no_virtual_lookup_or_delete() {
        let _bench = bench();
        let mut collection_vtable = [item_at as usize; COLLECTION_ITEM_SLOT + 1];
        let mut collection = CollectionFixture { vtable: collection_vtable.as_ptr(), count: 1, padding: [0; 4], active: 0 };
        unsafe { collection_release_first_occupied((&mut collection as *mut CollectionFixture).cast()) };
        collection.active = 1;
        collection.count = -1;
        unsafe { collection_release_first_occupied((&mut collection as *mut CollectionFixture).cast()) };
        assert_eq!(unsafe { LOOKUP_COUNT }, 0);
        assert_eq!(crate::heap::veneers::tests::free_log().0, 0);
    }
}
