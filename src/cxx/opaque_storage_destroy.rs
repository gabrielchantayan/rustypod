//! Port of the unidentified tagged-storage destructor at 0x083e7210.

use crate::heap::veneers::{free_wrapper, operator_delete};

/// Target-width owner slot observed by [`opaque_storage_destroy`].
#[repr(C)]
pub struct OpaqueStorageOwner {
    pub object: u32,
}

/// Target-width heap object held by [`OpaqueStorageOwner`].
///
/// The first two words have no recovered meaning. `storage` is the conditional
/// allocation at +0x08 and `heap_tag` is the ownership byte at +0x0c.
#[repr(C)]
pub struct OpaqueStorageObject {
    pub header: [u32; 2],
    pub storage: u32,
    pub heap_tag: u8,
    pub reserved: [u8; 3],
}

const _: [u8; 0x00] = [0; core::mem::offset_of!(OpaqueStorageOwner, object)];
const _: [u8; 0x04] = [0; core::mem::size_of::<OpaqueStorageOwner>()];
const _: [u8; 0x08] = [0; core::mem::offset_of!(OpaqueStorageObject, storage)];
const _: [u8; 0x0c] = [0; core::mem::offset_of!(OpaqueStorageObject, heap_tag)];
const _: [u8; 0x10] = [0; core::mem::size_of::<OpaqueStorageObject>()];

/// opaque_storage_destroy — original: `FUN_083e7210` @ 0x083e7210
/// (**60 bytes**, 0x083e7210..0x083e7248; the following `push {r4,r5,r6,lr}`
/// at 0x083e724c starts the separately linked next function). **3 plain
/// inbound `bl` call sites, 0 predicated inbound `bl`**; the body contains one
/// predicated `blne` to `free_wrapper` and one plain `bl` to `operator_delete`.
///
/// Loads `owner.object`; when non-NULL, it releases `object.storage` through
/// [`free_wrapper`] with tag zero only if that word is non-NULL and
/// `object.heap_tag != 0x3a`, then releases the object itself through
/// [`operator_delete`]. It never changes the owner and returns it. The `0x3a`
/// byte is an ownership sentinel: borrowed storage remains live. The raw body
/// ignores Ghidra's second parameter.
///
/// Deliberate deviation: calls the ported [`free_wrapper`] and
/// [`operator_delete`] directly rather than their retailOS addresses; both
/// dispatch through `HEAP_OPS`.
///
/// # Safety
///
/// `owner` must point to a live target-layout owner. Its non-NULL `object`
/// must point to a live [`OpaqueStorageObject`], whose owned storage and object
/// allocation are releasable by the default heap.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn opaque_storage_destroy(owner: *mut OpaqueStorageOwner) -> *mut OpaqueStorageOwner {
    let object = (*owner).object as usize as *mut OpaqueStorageObject;
    if !object.is_null() {
        let storage = (*object).storage;
        if storage != 0 && (*object).heap_tag != 0x3a {
            free_wrapper(storage as usize as *mut u8, 0);
        }
        operator_delete(object.cast());
    }
    owner
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use crate::heap::types::{HeapDescriptorDescriptor, DEFAULT_HEAP};
    use crate::heap::veneers::{DEFAULT_HEAP_OPS, HEAP_OPS};
    use core::ptr;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{LazyLock, Mutex};

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static FREE_COUNT: AtomicUsize = AtomicUsize::new(0);
    static FREED_FIRST: AtomicUsize = AtomicUsize::new(0);
    static FREED_SECOND: AtomicUsize = AtomicUsize::new(0);
    static FIRST_TAG: AtomicUsize = AtomicUsize::new(usize::MAX);
    static SECOND_TAG: AtomicUsize = AtomicUsize::new(usize::MAX);
    static OBJECT_SLAB: LazyLock<usize> = LazyLock::new(|| {
        crate::testing::try_map_u32_slab(crate::testing::hints::OPAQUE_STORAGE_DESTROY, 0x1000)
            .map(|slab| slab as usize)
            .unwrap_or(0)
    });

    unsafe extern "C" fn record_free(
        _heap: *mut HeapDescriptorDescriptor,
        storage: *mut u8,
        tag: usize,
    ) {
        match FREE_COUNT.fetch_add(1, Ordering::SeqCst) {
            0 => {
                FREED_FIRST.store(storage as usize, Ordering::SeqCst);
                FIRST_TAG.store(tag, Ordering::SeqCst);
            }
            1 => {
                FREED_SECOND.store(storage as usize, Ordering::SeqCst);
                SECOND_TAG.store(tag, Ordering::SeqCst);
            }
            _ => panic!("unexpected third free"),
        }
    }

    struct HeapOpsRestore {
        old_ops: crate::heap::veneers::HeapVeneerOps,
        old_heap: *mut HeapDescriptorDescriptor,
    }

    impl Drop for HeapOpsRestore {
        fn drop(&mut self) {
            unsafe {
                ptr::write_volatile(ptr::addr_of_mut!(HEAP_OPS), self.old_ops);
                ptr::write_volatile(ptr::addr_of_mut!(DEFAULT_HEAP), self.old_heap);
            }
        }
    }

    fn install_recording_heap() -> HeapOpsRestore {
        unsafe {
            let old_ops = ptr::read_volatile(ptr::addr_of!(HEAP_OPS));
            let old_heap = ptr::read_volatile(ptr::addr_of!(DEFAULT_HEAP));
            let mut ops = DEFAULT_HEAP_OPS;
            ops.free = record_free;
            ptr::write_volatile(ptr::addr_of_mut!(HEAP_OPS), ops);
            ptr::write_volatile(ptr::addr_of_mut!(DEFAULT_HEAP), 1usize as *mut _);
            HeapOpsRestore { old_ops, old_heap }
        }
    }

    fn reset_frees() {
        FREE_COUNT.store(0, Ordering::SeqCst);
        FREED_FIRST.store(0, Ordering::SeqCst);
        FREED_SECOND.store(0, Ordering::SeqCst);
        FIRST_TAG.store(usize::MAX, Ordering::SeqCst);
        SECOND_TAG.store(usize::MAX, Ordering::SeqCst);
    }

    #[test]
    fn releases_owned_storage_then_object_and_returns_owner() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let object_address = *OBJECT_SLAB;
        if object_address == 0 {
            assert!(crate::testing::note_missing_u32_fixture("cxx/opaque_storage_destroy"));
            return;
        }
        let _restore = install_recording_heap();
        let object = object_address as *mut OpaqueStorageObject;
        unsafe { object.write(OpaqueStorageObject { header: [0x1234_5678, 0x9abc_def0], storage: object_address as u32 + 0x100, heap_tag: 0, reserved: [7; 3] }) };
        let mut owner = OpaqueStorageOwner { object: object_address as u32 };
        reset_frees();

        assert_eq!(unsafe { opaque_storage_destroy(&mut owner) }, ptr::addr_of_mut!(owner));
        assert_eq!(FREE_COUNT.load(Ordering::SeqCst), 2);
        assert_eq!(FREED_FIRST.load(Ordering::SeqCst), object_address + 0x100);
        assert_eq!(FIRST_TAG.load(Ordering::SeqCst), 0);
        assert_eq!(FREED_SECOND.load(Ordering::SeqCst), object_address);
        assert_eq!(SECOND_TAG.load(Ordering::SeqCst), 2);
        assert_eq!(owner.object, object_address as u32);
    }

    #[test]
    fn null_owner_object_returns_without_heap_traffic() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _restore = install_recording_heap();
        let mut owner = OpaqueStorageOwner { object: 0 };
        reset_frees();
        assert_eq!(unsafe { opaque_storage_destroy(&mut owner) }, ptr::addr_of_mut!(owner));
        assert_eq!(FREE_COUNT.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn borrowed_or_null_storage_skips_only_the_storage_free() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let object_address = *OBJECT_SLAB;
        if object_address == 0 {
            assert!(crate::testing::note_missing_u32_fixture("cxx/opaque_storage_destroy"));
            return;
        }
        let _restore = install_recording_heap();
        for (storage, heap_tag) in [(0, 0), (object_address as u32 + 0x100, 0x3a)] {
            unsafe { (object_address as *mut OpaqueStorageObject).write(OpaqueStorageObject { header: [0; 2], storage, heap_tag, reserved: [0; 3] }) };
            let mut owner = OpaqueStorageOwner { object: object_address as u32 };
            reset_frees();
            assert_eq!(unsafe { opaque_storage_destroy(&mut owner) }, ptr::addr_of_mut!(owner));
            assert_eq!(FREE_COUNT.load(Ordering::SeqCst), 1);
            assert_eq!(FREED_FIRST.load(Ordering::SeqCst), object_address);
            assert_eq!(FIRST_TAG.load(Ordering::SeqCst), 2);
        }
    }
}
