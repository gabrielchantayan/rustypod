//! Menu-resource collection factory — FUN_0826b794 @ 0x0826b794.
//!
//! True extent: 68 bytes (64 code plus literal 0x4d656e75 at 0x0826b7d4);
//! next real function begins at 0x0826b7d8 with push {r4,r5,r6,lr}.
//! Whole-image raw A32 decoding: two inbound plain BLs at 0x0828917c and
//! 0x082891cc, zero predicated BLs. Body: three plain BLs, zero predicated.
//! Looks up ("Menu", id) in the supplied provider chain. A NULL resource
//! returns NULL without allocating; otherwise allocates 12 bytes and constructs
//! a relative-record collection with the original provider pointer as context.
//! Deviations: calls the existing Rust lookup, allocator, and constructor ports
//! instead of retail BL targets. Context remains a target u32 pointer word;
//! host fixtures therefore use low-address providers. No allocation NULL guard
//! is added: the original passes allocation failure into the constructor.

use crate::app::resource_chain::{resource_chain_find, ResourceKind, ResourceProvider};
use crate::cxx::relative_record_collection_construct::{relative_record_collection_construct, RelativeRecordCollection};
use crate::heap::veneers::operator_new;

const MENU: ResourceKind = ResourceKind(0x4d65_6e75);

/// # Safety
/// Provider chain and returned menu records must satisfy their existing port
/// contracts. Allocations must succeed; the provider pointer must fit in u32.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn menu_resource_collection_create(
    resources: *mut ResourceProvider, id: u32,
) -> *mut RelativeRecordCollection {
    let records = resource_chain_find(resources, MENU, id);
    if records.is_null() {
        return core::ptr::null_mut();
    }
    relative_record_collection_construct(
        operator_new(12).cast(), resources as usize as u32, records.cast(),
    )
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::app::resource_chain::ResourceProviderVTable;
    use crate::heap::veneers::{tests as heap_tests, HEAP_OPS};
    use core::ptr;

    static mut SLAB: *mut u8 = ptr::null_mut();
    static mut ALLOCATIONS: usize = 0;

    unsafe extern "C" fn allocate(
        _: *mut crate::heap::types::HeapDescriptorDescriptor, size: usize, tag: usize,
    ) -> *mut u8 {
        assert_eq!(tag, 2);
        assert_eq!(size, if ALLOCATIONS == 0 { 12 } else { 16 });
        let result = SLAB.add(256 + ALLOCATIONS * 64);
        ALLOCATIONS += 1;
        result
    }
    unsafe extern "C" fn find(provider: *mut ResourceProvider, kind: ResourceKind, id: u32, out: *mut *mut u8) -> u32 {
        if kind == MENU && id == u32::MAX {
            *out = (*provider).state_below_next[0];
            return 1;
        }
        0
    }
    unsafe extern "C" fn read(_: *mut ResourceProvider, _: ResourceKind, _: u32) -> u32 { 0 }
    unsafe extern "C" fn replace(_: *mut ResourceProvider, _: *mut ResourceProvider) -> u32 { 0 }
    unsafe extern "C" fn write(_: *mut ResourceProvider, _: ResourceKind, _: u32, _: u32, _: u32) -> u32 { 0 }

    #[test]
    fn misses_do_not_allocate_and_empty_menu_builds_real_collection() {
        let _guard = heap_tests::mock_heap();
        unsafe {
            SLAB = crate::testing::try_map_u32_slab(
                crate::testing::hints::MENU_RESOURCE_COLLECTION_CREATE, 4096,
            ).expect("low-address menu provider fixture");
            ALLOCATIONS = 0;
            let old_allocate = HEAP_OPS.alloc;
            HEAP_OPS.alloc = allocate;
            let vtable = ResourceProviderVTable {
                slots_below: [None; 22], read, slot_5c: None,
                replacement_allowed: replace, find, write,
            };
            let provider = SLAB.cast::<ResourceProvider>();
            let child = SLAB.add(128).cast::<ResourceProvider>();
            let parent_vtable = ResourceProviderVTable {
                slots_below: [None; 22], read, slot_5c: None,
                replacement_allowed: replace, find: decline, write,
            };
            provider.write(ResourceProvider {
                vtable: &vtable, state_below_next: [ptr::null_mut(); 4], next: child,
            });
            child.write(ResourceProvider {
                vtable: &vtable, state_below_next: [ptr::null_mut(); 4], next: ptr::null_mut(),
            });
            assert!(menu_resource_collection_create(ptr::null_mut(), u32::MAX).is_null());
            assert!(menu_resource_collection_create(provider, 0).is_null());
            // Even an accepted NULL resource must not trigger allocation.
            assert!(menu_resource_collection_create(provider, u32::MAX).is_null());
            assert_eq!(ALLOCATIONS, 0);
            let mut records = [0u32];
            (*child).state_below_next[0] = records.as_mut_ptr().cast();
            for count in [0, u32::MAX, 0x8000_0000] {
                records[0] = count;
                ALLOCATIONS = 0;
                (*provider).state_below_next[0] = ptr::null_mut();
                // Parent must decline for the child to supply the resource.
                (*provider).vtable = &parent_vtable;
                SLAB.add(256).write_bytes(0xa5, 128);
                let collection = menu_resource_collection_create(provider, u32::MAX);
                assert_eq!(collection.cast::<u8>(), SLAB.add(256));
                assert_eq!(((*collection).vtable, (*collection).lower, (*collection).upper, (*collection).padding),
                    (0x089a_59a0, 127, 0, [0xa5; 2]));
                let array = (*collection).items as usize as *const u32;
                assert_eq!(core::slice::from_raw_parts(array, 4),
                    &[crate::cxx::observable_array::OBSERVABLE_ARRAY_VTABLE, 0, 0, 0]);
                assert_eq!(ALLOCATIONS, 2);
                std::println!("menu factory count={count:#x}: descriptor={:#x}, bounds=127/0, array empty, allocations=2", (*collection).vtable);
            }
            HEAP_OPS.alloc = old_allocate;
        }
    }
    unsafe extern "C" fn decline(_: *mut ResourceProvider, _: ResourceKind, _: u32, _: *mut *mut u8) -> u32 { 0 }
}
