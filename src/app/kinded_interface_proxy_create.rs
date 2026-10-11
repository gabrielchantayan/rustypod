//! Kind-2 interface proxy constructor — retailOS 0x080586b8.
//! True extent: 60 bytes, [0x080586b8, 0x080586f4); next word is a new PUSH.
//! Raw A32: two plain outgoing BLs (calloc_tag4, kinded_interface_initialize),
//! two plain incoming BLs (0x0813e4d8, 0x0813e508), no predicated BLs.
//!
//! Allocate 0xf00 zeroed bytes. On failure return -108 without touching the
//! output. Otherwise initialize and register kind 2, ignore the initializer's
//! result, store the backend word at +0xefc, publish the pointer, and return 0.
//! Deviations: reuse existing Rust allocator and initializer seams. Backend
//! remains a target-width u32 on hosts; the output slot uses a native pointer.

use crate::heap::veneers::calloc_tag4;
use super::kinded_interface_initialize::kinded_interface_initialize;

/// # Safety
/// On successful allocation, `output` must be writable and pointer-aligned.
/// Heap and interface-registry access must be externally serialized.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn kinded_interface_proxy_create(backend: u32, output: *mut *mut u8) -> i32 {
    let proxy = calloc_tag4(0xf00);
    if proxy.is_null() { return -108; }
    kinded_interface_initialize(proxy, 2);
    proxy.add(0xefc).cast::<u32>().write(backend);
    output.write(proxy);
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;
    use crate::heap::types::HeapDescriptorDescriptor;
    use crate::heap::veneers::{HEAP_OPS, HeapVeneerOps, tests::mock_heap};
    use crate::app::kinded_interface_initialize::{HOST_REGISTRY, REGISTRY_TEST_LOCK};

    static mut ALLOCATION: *mut u8 = ptr::null_mut();
    unsafe extern "C" fn allocate(_: *mut HeapDescriptorDescriptor, bytes: usize, _: usize) -> *mut u8 {
        let block = ALLOCATION;
        if !block.is_null() { block.write_bytes(0, bytes); }
        block
    }
    struct Restore(HeapVeneerOps, [*mut u8; 5]);
    impl Drop for Restore {
        fn drop(&mut self) { unsafe {
            ptr::addr_of_mut!(HEAP_OPS).write(self.0);
            ptr::addr_of_mut!(HOST_REGISTRY).write(self.1);
            ALLOCATION = ptr::null_mut();
        } }
    }
    #[repr(align(4))]
    struct Storage([u8; 0xf08]);

    #[test]
    fn failure_preserves_output_and_registry_success_publishes_complete_proxy() {
        let _heap = mock_heap();
        let _registry = REGISTRY_TEST_LOCK.lock();
        unsafe {
            let _restore = Restore(ptr::addr_of!(HEAP_OPS).read(), ptr::addr_of!(HOST_REGISTRY).read());
            HEAP_OPS.alloc_zero = allocate;
            for occupied in 0..=4 {
                let mut slots = [ptr::dangling_mut::<u8>(); 5];
                if occupied < 4 { slots[occupied] = ptr::null_mut(); }
                ptr::addr_of_mut!(HOST_REGISTRY).write(slots);
                let mut output = ptr::dangling_mut::<u8>();
                ALLOCATION = ptr::null_mut();
                assert_eq!(kinded_interface_proxy_create(u32::MAX, &mut output), -108);
                assert_eq!(output, ptr::dangling_mut::<u8>());
                assert_eq!(ptr::addr_of!(HOST_REGISTRY).read(), slots);
                // A failed allocation must not even dereference the output slot.
                assert_eq!(kinded_interface_proxy_create(0, ptr::null_mut()), -108);
                for backend in [0, 0x08000000, u32::MAX] {
                    let mut storage = Storage([0xa5; 0xf08]);
                    let proxy = storage.0.as_mut_ptr().add(4);
                    ALLOCATION = proxy;
                    assert_eq!(kinded_interface_proxy_create(backend, &mut output), 0);
                    assert_eq!(output, proxy);
                    let mut expected = [0xa5; 0xf08];
                    expected[4..0xf04].fill(0);
                    expected[4] = 2;
                    expected[5] = occupied as u8;
                    expected[0xf00..0xf04].copy_from_slice(&backend.to_le_bytes());
                    assert_eq!(storage.0, expected);
                    let mut registered = slots;
                    registered[occupied] = proxy;
                    assert_eq!(ptr::addr_of!(HOST_REGISTRY).read(), registered);
                    ptr::addr_of_mut!(HOST_REGISTRY).write(slots);
                }
            }
        }
    }
}
