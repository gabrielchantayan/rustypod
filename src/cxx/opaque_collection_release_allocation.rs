//! Releases an allocation created from the first occupied opaque collection cell.
//!
//! `opaque_collection_release_allocation` — original: `FUN_083d0738` @
//! **0x083d0738**, 88 bytes (`0x083d0738..0x083d078f`). The next independently
//! entered function begins with `push {r4,r5,r6,lr}` at `0x083d0790`. The body
//! has two plain direct `bl` calls, to the still-retail allocation helper at
//! `0x081991bc` and `operator_delete` at `0x082aad24`; it has no predicated
//! direct `bl` calls and one indirect `blx` through vtable slot `+0x40`.
//! Raw whole-image A32 decoding finds two inbound plain `bl` sites
//! (`0x083d07e8`, `0x083d0820`) and no predicated inbound `bl` sites.
//!
//! # Algorithm
//!
//! If byte `+0x10` is nonzero, scan signed indices `[0, count)` through the
//! opaque vtable's `+0x40` slot. For the first returned cell with a nonzero
//! first word, pass that word to the retail allocation helper, then tag-2-delete
//! its returned allocation. Later cells are untouched.
//!
//! # Deliberate deviations
//!
//! The allocation helper's concrete identity is not established. Target Rust
//! calls its verified load address; host tests inject the same ABI through a
//! seam. Host vtable pointers widen, so the count word follows the native-width
//! pointer rather than fixed ARM offset `+0x04`.

use crate::heap::veneers::operator_delete;

const COLLECTION_ITEM_SLOT: usize = 0x40 / 4;
type CollectionItemMethod = unsafe extern "C" fn(*mut u8, i32) -> *mut u8;
type OpaqueHeaderAllocate = unsafe extern "C" fn(u32) -> *mut u8;

#[cfg(target_os = "none")]
const COLLECTION_COUNT_OFFSET: usize = 4;
#[cfg(not(target_os = "none"))]
const COLLECTION_COUNT_OFFSET: usize = core::mem::size_of::<usize>();

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_opaque_header_allocate(size: u32) -> *mut u8 {
    unsafe { core::mem::transmute::<usize, OpaqueHeaderAllocate>(0x0819_91bc)(size) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_opaque_header_allocate(_: u32) -> *mut u8 {
    panic!("install opaque collection allocation host seam")
}

#[cfg(target_os = "none")]
static mut OPAQUE_HEADER_ALLOCATE: OpaqueHeaderAllocate = firmware_opaque_header_allocate;
#[cfg(not(target_os = "none"))]
static mut OPAQUE_HEADER_ALLOCATE: OpaqueHeaderAllocate = missing_opaque_header_allocate;

/// Releases the allocation produced for the first occupied collection cell.
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
        let allocation_size = unsafe { cell.cast::<u32>().read_volatile() };
        if allocation_size != 0 {
            let allocation = unsafe { OPAQUE_HEADER_ALLOCATE(allocation_size) };
            unsafe { operator_delete(allocation) };
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
    static mut ALLOCATION_SIZE: u32 = 0;
    static mut ALLOCATION: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn item_at(_: *mut u8, index: i32) -> *mut u8 {
        unsafe { LOOKUPS[LOOKUP_COUNT] = index; LOOKUP_COUNT += 1; CELLS[index as usize] }
    }
    unsafe extern "C" fn allocate(size: u32) -> *mut u8 {
        unsafe { ALLOCATION_SIZE = size; ALLOCATION }
    }

    #[repr(C)]
    struct CollectionFixture { vtable: *const usize, count: i32, padding: [u8; 4], active: u8 }
    struct Bench { _lock: MutexGuard<'static, ()>, _heap: MutexGuard<'static, ()>, old_allocate: OpaqueHeaderAllocate }

    fn bench() -> Bench {
        let lock = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            CELLS = [core::ptr::null_mut(); 3]; LOOKUPS = [0; 3]; LOOKUP_COUNT = 0;
            ALLOCATION_SIZE = 0; ALLOCATION = core::ptr::null_mut();
            let old_allocate = OPAQUE_HEADER_ALLOCATE;
            OPAQUE_HEADER_ALLOCATE = allocate;
            Bench { _lock: lock, _heap: crate::heap::veneers::tests::mock_heap(), old_allocate }
        }
    }

    impl Drop for Bench {
        fn drop(&mut self) { unsafe { OPAQUE_HEADER_ALLOCATE = self.old_allocate }; }
    }

    #[test]
    fn allocates_and_deletes_only_for_the_first_occupied_cell() {
        let _bench = bench();
        let mut empty = 0u32;
        let mut occupied = 0x31u32;
        let mut later = 0x52u32;
        let mut allocation = [0u8; 16];
        unsafe { ALLOCATION = allocation.as_mut_ptr(); CELLS = [&mut empty as *mut _ as *mut u8, &mut occupied as *mut _ as *mut u8, &mut later as *mut _ as *mut u8] };
        let mut vtable = [0usize; COLLECTION_ITEM_SLOT + 1];
        vtable[COLLECTION_ITEM_SLOT] = item_at as usize;
        let mut collection = CollectionFixture { vtable: vtable.as_ptr(), count: 3, padding: [0; 4], active: 1 };
        unsafe { opaque_collection_release_allocation((&mut collection as *mut CollectionFixture).cast()) };
        assert_eq!(unsafe { &LOOKUPS[..LOOKUP_COUNT] }, &[0, 1]);
        assert_eq!(unsafe { ALLOCATION_SIZE }, 0x31);
        assert_eq!(crate::heap::veneers::tests::free_log(), (1, allocation.as_mut_ptr(), 2));
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
        assert_eq!(unsafe { ALLOCATION_SIZE }, 0);
        assert_eq!(crate::heap::veneers::tests::free_log().0, 0);
    }
}
