//! Lazy allocation of the shared opaque record-source object.
//!
//! `opaque_record_source_get` — retailOS `FUN_082841c8` at load address
//! **0x082841c8**. Raw decoding establishes 44 instruction bytes through the
//! `pop {r4,pc}` at 0x082841f0, followed by its cache-word literal at
//! 0x082841f4: **48 bytes** total. Complete decoding of every ARM B/BL
//! immediate in `osos.dec` finds **6 direct `bl` call sites**, all
//! unconditional; it also finds the unconditional tail branch at 0x080b43e4.
//! There are no predicated inbound branches.
//!
//! ## Algorithm
//!
//! Read the shared cache. On NULL, allocate 32 bytes through `operator_new`,
//! pass that result (including NULL) to the 0x08284534 constructor, cache the
//! constructor's return value, then reload and return the cache. A NULL
//! constructor result therefore leaves the cache NULL and repeats allocation
//! on the next call.
//!
//! ## Deliberate deviation
//!
//! The constructor at 0x08284534 is not yet ported or recorded in
//! `names.yaml`. Target builds call that fixed address through the volatile
//! constructor slot; host tests install a recorder. The firmware cache word
//! at 0x08a0e140 is represented by this crate static.

use core::ptr;

use crate::heap::veneers::operator_new;

/// The opaque record-source prefix initialized by `FUN_08284534`.
#[repr(C)]
pub struct OpaqueRecordSource {
    _opaque: [u8; OPAQUE_RECORD_SOURCE_BYTES],
}

/// Bytes cleared by the unported constructor: six words, one byte, and one
/// halfword at offsets 0x00..0x1b.
pub const OPAQUE_RECORD_SOURCE_BYTES: usize = 0x1c;
/// Allocation size passed to `operator_new` (`mov r0,#0x20`).
pub const OPAQUE_RECORD_SOURCE_ALLOCATION_SIZE: usize = 0x20;
/// Unported default constructor called on the allocation result.
pub const OPAQUE_RECORD_SOURCE_CTOR_ADDRESS: usize = 0x0828_4534;

/// ABI of the unported ADS constructor: it returns the constructed `this`.
pub type OpaqueRecordSourceCtor = unsafe extern "C" fn(
    this: *mut OpaqueRecordSource,
) -> *mut OpaqueRecordSource;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_opaque_record_source_ctor(
    this: *mut OpaqueRecordSource,
) -> *mut OpaqueRecordSource {
    let ctor: OpaqueRecordSourceCtor = unsafe { core::mem::transmute(OPAQUE_RECORD_SOURCE_CTOR_ADDRESS) };
    unsafe { ctor(this) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_opaque_record_source_ctor(
    _this: *mut OpaqueRecordSource,
) -> *mut OpaqueRecordSource {
    panic!("opaque_record_source_get requires firmware constructor 0x08284534")
}

/// Active constructor slot. It is volatile because a future constructor port
/// replaces it and host tests install a recorder.
#[cfg(target_os = "none")]
pub static mut OPAQUE_RECORD_SOURCE_CTOR: OpaqueRecordSourceCtor = firmware_opaque_record_source_ctor;
#[cfg(not(target_os = "none"))]
pub static mut OPAQUE_RECORD_SOURCE_CTOR: OpaqueRecordSourceCtor = missing_opaque_record_source_ctor;

/// Firmware cache word 0x08a0e140, relocated into crate-owned storage.
pub static mut OPAQUE_RECORD_SOURCE: *mut OpaqueRecordSource = ptr::null_mut();

#[inline(always)]
unsafe fn opaque_record_source_ctor() -> OpaqueRecordSourceCtor {
    unsafe { ptr::addr_of!(OPAQUE_RECORD_SOURCE_CTOR).read_volatile() }
}

/// `opaque_record_source_get` — retailOS `FUN_082841c8` @ **0x082841c8**
/// (**48 bytes** including the pool literal; **6 direct unconditional `bl`
/// callers**, plus one unconditional tail branch).
///
/// Lazily allocates a 32-byte opaque record-source block, caches the return
/// from its unported constructor, and returns the reloaded cache value.
///
/// # Safety
///
/// The installed allocator and constructor must accept the 32-byte allocation
/// result. Like retailOS, the constructor is called even when allocation
/// returns NULL.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn opaque_record_source_get() -> *mut OpaqueRecordSource {
    let cache = ptr::addr_of_mut!(OPAQUE_RECORD_SOURCE);
    if unsafe { cache.read_volatile() }.is_null() {
        let allocation = unsafe { operator_new(OPAQUE_RECORD_SOURCE_ALLOCATION_SIZE) };
        let source = unsafe { opaque_record_source_ctor()(allocation.cast()) };
        unsafe { cache.write_volatile(source) };
    }
    unsafe { cache.read_volatile() }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::app::singletons::SINGLETON_LOCK;
    use crate::heap::types::{HeapDescriptor, HeapDescriptorDescriptor, DEFAULT_HEAP};
    use crate::heap::veneers::{HeapVeneerOps, HEAP_OPS};
    use core::ptr;
    use std::sync::MutexGuard;
    use std::vec::Vec;

    static mut ARENA: [u8; OPAQUE_RECORD_SOURCE_ALLOCATION_SIZE] = [0xa5; OPAQUE_RECORD_SOURCE_ALLOCATION_SIZE];
    static mut FAKE_HEAP: usize = 0;
    static mut ALLOC_RESULT: *mut u8 = ptr::null_mut();
    static mut CTOR_RESULT: *mut OpaqueRecordSource = ptr::null_mut();
    static mut ALLOC_SIZES: Vec<usize> = Vec::new();
    static mut CTOR_BLOCKS: Vec<*mut OpaqueRecordSource> = Vec::new();

    unsafe extern "C" fn stub_alloc(
        _heap: *mut HeapDescriptorDescriptor,
        size: usize,
        _tag: usize,
    ) -> *mut u8 {
        unsafe { (*ptr::addr_of_mut!(ALLOC_SIZES)).push(size) };
        unsafe { ptr::addr_of!(ALLOC_RESULT).read_volatile() }
    }

    unsafe extern "C" fn stub_create(
        _desc: *mut HeapDescriptor,
        _start: *mut u8,
        _size: usize,
    ) -> *mut HeapDescriptorDescriptor {
        unreachable!("the pre-seeded default heap skips lazy creation")
    }

    unsafe extern "C" fn recording_ctor(
        this: *mut OpaqueRecordSource,
    ) -> *mut OpaqueRecordSource {
        unsafe { (*ptr::addr_of_mut!(CTOR_BLOCKS)).push(this) };
        unsafe { ptr::addr_of!(CTOR_RESULT).read_volatile() }
    }

    struct Restore {
        heap_ops: HeapVeneerOps,
        default_heap: *mut HeapDescriptorDescriptor,
        ctor: OpaqueRecordSourceCtor,
        cache: *mut OpaqueRecordSource,
    }

    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe {
                ptr::addr_of_mut!(HEAP_OPS).write_volatile(self.heap_ops);
                ptr::addr_of_mut!(DEFAULT_HEAP).write_volatile(self.default_heap);
                ptr::addr_of_mut!(OPAQUE_RECORD_SOURCE_CTOR).write_volatile(self.ctor);
                ptr::addr_of_mut!(OPAQUE_RECORD_SOURCE).write_volatile(self.cache);
            }
        }
    }

    unsafe fn install_mock(
        allocation: *mut u8,
        constructed: *mut OpaqueRecordSource,
    ) -> Restore {
        let heap_ops = unsafe { ptr::addr_of!(HEAP_OPS).read_volatile() };
        let default_heap = unsafe { ptr::addr_of!(DEFAULT_HEAP).read_volatile() };
        let ctor = unsafe { ptr::addr_of!(OPAQUE_RECORD_SOURCE_CTOR).read_volatile() };
        let cache = unsafe { ptr::addr_of!(OPAQUE_RECORD_SOURCE).read_volatile() };
        unsafe {
            let mut mocked_ops = heap_ops;
            mocked_ops.alloc = stub_alloc;
            mocked_ops.create = stub_create;
            ptr::addr_of_mut!(HEAP_OPS).write_volatile(mocked_ops);
            ptr::addr_of_mut!(DEFAULT_HEAP)
                .write_volatile(ptr::addr_of_mut!(FAKE_HEAP).cast::<HeapDescriptorDescriptor>());
            ptr::addr_of_mut!(OPAQUE_RECORD_SOURCE_CTOR).write_volatile(recording_ctor);
            ptr::addr_of_mut!(OPAQUE_RECORD_SOURCE).write_volatile(ptr::null_mut());
            ptr::addr_of_mut!(ALLOC_RESULT).write_volatile(allocation);
            ptr::addr_of_mut!(CTOR_RESULT).write_volatile(constructed);
            (*ptr::addr_of_mut!(ALLOC_SIZES)).clear();
            (*ptr::addr_of_mut!(CTOR_BLOCKS)).clear();
        }
        Restore { heap_ops, default_heap, ctor, cache }
    }

    /// The constructor's r0, not the raw allocation, becomes the cached value;
    /// the hot path does not invoke either callee again.
    #[test]
    fn getter_caches_constructor_return_and_skips_the_hot_path_calls() {
        let _heap_guard: MutexGuard<'static, ()> = SINGLETON_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            let allocation = ptr::addr_of_mut!(ARENA) as *mut u8;
            let constructed = allocation.add(4).cast::<OpaqueRecordSource>();
            let _restore = install_mock(allocation, constructed);

            assert_eq!(opaque_record_source_get(), constructed);
            assert_eq!(opaque_record_source_get(), constructed);
            assert_eq!(*ptr::addr_of!(ALLOC_SIZES), std::vec![OPAQUE_RECORD_SOURCE_ALLOCATION_SIZE]);
            assert_eq!(*ptr::addr_of!(CTOR_BLOCKS), std::vec![allocation.cast::<OpaqueRecordSource>()]);
        }
    }

    /// A NULL constructor return is stored unconditionally, so every later
    /// call repeats both allocation and construction.
    #[test]
    fn null_constructor_return_retries_allocation_on_every_call() {
        let _heap_guard: MutexGuard<'static, ()> = SINGLETON_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            let allocation = ptr::addr_of_mut!(ARENA) as *mut u8;
            let _restore = install_mock(allocation, ptr::null_mut());

            assert!(opaque_record_source_get().is_null());
            assert!(opaque_record_source_get().is_null());
            assert_eq!(
                *ptr::addr_of!(ALLOC_SIZES),
                std::vec![OPAQUE_RECORD_SOURCE_ALLOCATION_SIZE, OPAQUE_RECORD_SOURCE_ALLOCATION_SIZE]
            );
            assert_eq!(
                *ptr::addr_of!(CTOR_BLOCKS),
                std::vec![allocation.cast::<OpaqueRecordSource>(), allocation.cast::<OpaqueRecordSource>()]
            );
        }
    }

    /// The original has no allocation-failure guard between `operator_new` and
    /// its constructor call.
    #[test]
    fn getter_forwards_null_allocation_to_constructor() {
        let _heap_guard: MutexGuard<'static, ()> = SINGLETON_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            let constructed = ptr::addr_of_mut!(ARENA).cast::<OpaqueRecordSource>();
            let _restore = install_mock(ptr::null_mut(), constructed);

            assert_eq!(opaque_record_source_get(), constructed);
            assert_eq!(*ptr::addr_of!(ALLOC_SIZES), std::vec![OPAQUE_RECORD_SOURCE_ALLOCATION_SIZE]);
            assert_eq!(*ptr::addr_of!(CTOR_BLOCKS), std::vec![ptr::null_mut()]);
        }
    }
}
