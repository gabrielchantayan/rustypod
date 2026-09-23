//! Resource-arena activation and teardown.
//!
//! `resource_arena_set_active` is `FUN_0817f1c0` @ `0x0817f1c0` (204 bytes:
//! 200 bytes of instructions plus the owned word at `0x0817f288`; the next
//! separately linked function starts at `0x0817f28c`). A complete `osos.dec`
//! ARM B/BL decode finds six direct, unconditional `bl` callers and one
//! direct tail `b` caller; there are no predicated incoming calls.
//!
//! With a nonzero activation argument, it acquires a lazy shared handle when
//! the state field is `-1`, allocates a 0x398-byte heap descriptor over the
//! acquired region, and saves that descriptor. With zero, it first releases
//! the owner's transient resources, destroys and deletes that descriptor,
//! releases the lazy handle, then frees the optional pool allocation.
//!
//! The direct prepare, lazy-handle acquire, and lazy-handle release callees
//! are not ported, so host builds use replaceable operations while ARM builds
//! call their retailOS entries. The literal at `0x0817f288` points to
//! `0x083e235c`; in this image that address contains the ARM instruction word
//! `0xe5941004`, not identified data. ARM therefore reads that word
//! volatily exactly as the original does; host tests supply it through the
//! operations table rather than assigning an identity to the anomaly.

use core::ptr;
#[cfg(not(target_os = "none"))]
use core::ptr::addr_of;

use crate::heap::types::HeapDescriptor;

const RESOURCE_ARENA_DESCRIPTOR_SIZE: usize = 0x398;
const RESOURCE_ARENA_EXTENT_WORD_ADDRESS: usize = 0x083e_235c;
const LAZY_HANDLE_ACQUIRE_ADDRESS: usize = 0x081b_bff0;
const LAZY_HANDLE_RELEASE_ADDRESS: usize = 0x081b_c07c;

/// Fields read by `resource_arena_set_active`.
///
/// On ARM these fields are at `+0x14`, `+0x18`, and `+0x1c`. The named
/// `repr(C)` fields preserve that 32-bit layout; host pointers naturally
/// widen, so tests must use fields rather than firmware byte offsets.
#[repr(C)]
pub struct ResourceArenaState {
    pub opaque_00: [u32; 5],
    pub lazy_handle: i32,
    pub resource_pool: *mut u8,
    pub arena: *mut HeapDescriptor,
}

pub type ResourceArenaPrepare = unsafe extern "C" fn(*mut ResourceArenaState);
pub type LazyHandleAcquire = unsafe extern "C" fn(*mut u8, *mut i32) -> *mut u8;
pub type LazyHandleRelease = unsafe extern "C" fn(*mut u8, i32);

/// Host-only substitutes for calls that cannot dereference retailOS globals.
#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct ResourceArenaOps {
    pub manager_get: unsafe extern "C" fn() -> *mut u8,
    pub prepare: ResourceArenaPrepare,
    pub acquire: LazyHandleAcquire,
    pub release: LazyHandleRelease,
    pub allocate: unsafe extern "C" fn(usize) -> *mut u8,
    pub heap_create: unsafe extern "C" fn(*mut HeapDescriptor, usize, usize) -> *mut HeapDescriptor,
    pub heap_destroy: unsafe extern "C" fn(*mut HeapDescriptor) -> *mut HeapDescriptor,
    pub delete: unsafe extern "C" fn(*mut u8),
    pub pool_get: unsafe extern "C" fn(u32) -> *mut u8,
    pub pool_free: unsafe extern "C" fn(*mut u8, *mut u8),
    pub extent_word: usize,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_manager_get() -> *mut u8 {
    panic!("install resource-arena host operations before use")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_prepare(_state: *mut ResourceArenaState) {
    panic!("install resource-arena host operations before use")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_acquire(_manager: *mut u8, _handle: *mut i32) -> *mut u8 {
    panic!("install resource-arena host operations before use")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_release(_manager: *mut u8, _handle: i32) {
    panic!("install resource-arena host operations before use")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_allocate(_size: usize) -> *mut u8 {
    panic!("install resource-arena host operations before use")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_heap_create(
    _descriptor: *mut HeapDescriptor,
    _start: usize,
    _size: usize,
) -> *mut HeapDescriptor {
    panic!("install resource-arena host operations before use")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_heap_destroy(_descriptor: *mut HeapDescriptor) -> *mut HeapDescriptor {
    panic!("install resource-arena host operations before use")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_delete(_ptr: *mut u8) {
    panic!("install resource-arena host operations before use")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_pool_get(_index: u32) -> *mut u8 {
    panic!("install resource-arena host operations before use")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_pool_free(_pool: *mut u8, _ptr: *mut u8) {
    panic!("install resource-arena host operations before use")
}

/// Default host operations deliberately fail rather than dereferencing ARM
/// addresses. Tests install a complete recording implementation.
#[cfg(not(target_os = "none"))]
pub const DEFAULT_RESOURCE_ARENA_OPS: ResourceArenaOps = ResourceArenaOps {
    manager_get: missing_manager_get,
    prepare: missing_prepare,
    acquire: missing_acquire,
    release: missing_release,
    allocate: missing_allocate,
    heap_create: missing_heap_create,
    heap_destroy: missing_heap_destroy,
    delete: missing_delete,
    pool_get: missing_pool_get,
    pool_free: missing_pool_free,
    extent_word: 0xe594_1004,
};

#[cfg(not(target_os = "none"))]
pub static mut RESOURCE_ARENA_OPS: ResourceArenaOps = DEFAULT_RESOURCE_ARENA_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn host_ops() -> ResourceArenaOps {
    ptr::read_volatile(addr_of!(RESOURCE_ARENA_OPS))
}


#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn retail_acquire(manager: *mut u8, handle: *mut i32) -> *mut u8 {
    let acquire: LazyHandleAcquire = core::mem::transmute(LAZY_HANDLE_ACQUIRE_ADDRESS);
    acquire(manager, handle)
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn retail_release(manager: *mut u8, handle: i32) {
    let release: LazyHandleRelease = core::mem::transmute(LAZY_HANDLE_RELEASE_ADDRESS);
    release(manager, handle)
}

/// resource_arena_set_active — original: `FUN_0817f1c0` @ `0x0817f1c0` (204
/// bytes: 200 instruction bytes plus its literal at `0x0817f288`; six plain,
/// unconditional incoming `bl` sites and one tail `b`, binary-verified).
///
/// Treats only `-1` as an absent lazy handle. A failed acquire overwrites any
/// value written by the acquire helper with `-1`. Deactivation reloads all
/// fields after the prepare callback; in particular it destroys an arena and
/// continues through lazy-handle and pool cleanup even though Ghidra marks the
/// intervening `operator_delete` as non-returning.
///
/// # Safety
///
/// `state` must be valid, writable, and naturally aligned. Its non-sentinel
/// fields must satisfy the direct retailOS callees' contracts. As in ARM,
/// there are no null or alignment guards.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.resource_arena_set_active")]
#[inline(never)]
pub unsafe extern "C" fn resource_arena_set_active(state: *mut ResourceArenaState, active: u32) {
    if active != 0 {
        if (*state).lazy_handle != -1 {
            return;
        }

        #[cfg(target_os = "none")]
        let region = retail_acquire(
            crate::app::lazy_handle_manager::lazy_handle_manager_get().cast(),
            ptr::addr_of_mut!((*state).lazy_handle),
        );
        #[cfg(not(target_os = "none"))]
        let region = (host_ops().acquire)(
            (host_ops().manager_get)(),
            ptr::addr_of_mut!((*state).lazy_handle),
        );

        if region.is_null() {
            (*state).lazy_handle = -1;
            return;
        }

        #[cfg(target_os = "none")]
        {
            let descriptor = crate::heap::veneers::operator_new(RESOURCE_ARENA_DESCRIPTOR_SIZE)
                .cast::<HeapDescriptor>();
            let extent = ptr::read_volatile(RESOURCE_ARENA_EXTENT_WORD_ADDRESS as *const u32) as usize;
            (*state).arena = crate::heap::init::heap_create(descriptor, region as usize, extent);
        }
        #[cfg(not(target_os = "none"))]
        {
            let ops = host_ops();
            let descriptor = (ops.allocate)(RESOURCE_ARENA_DESCRIPTOR_SIZE).cast::<HeapDescriptor>();
            (*state).arena = (ops.heap_create)(descriptor, region as usize, ops.extent_word);
        }
        return;
    }

    if (*state).lazy_handle == -1 {
        return;
    }

    #[cfg(target_os = "none")]
    super::prepare::resource_arena_prepare(state.cast());
    #[cfg(not(target_os = "none"))]
    (host_ops().prepare)(state);

    let arena = (*state).arena;
    if !arena.is_null() {
        #[cfg(target_os = "none")]
        {
            let destroyed = crate::heap::init::heap_destroy(arena);
            crate::heap::veneers::operator_delete(destroyed.cast());
        }
        #[cfg(not(target_os = "none"))]
        {
            let ops = host_ops();
            let destroyed = (ops.heap_destroy)(arena);
            (ops.delete)(destroyed.cast());
        }
    }
    (*state).arena = ptr::null_mut();

    let handle = (*state).lazy_handle;
    #[cfg(target_os = "none")]
    retail_release(crate::app::lazy_handle_manager::lazy_handle_manager_get().cast(), handle);
    #[cfg(not(target_os = "none"))]
    (host_ops().release)((host_ops().manager_get)(), handle);
    (*state).lazy_handle = -1;

    let resource_pool = (*state).resource_pool;
    if !resource_pool.is_null() {
        #[cfg(target_os = "none")]
        {
            let pool = crate::app::tbm_app_client_cache::tbm_app_client_cache_get(1);
            if !pool.is_null() {
                crate::heap::pool::pool_free(pool.cast(), resource_pool);
                (*state).resource_pool = ptr::null_mut();
            }
        }
        #[cfg(not(target_os = "none"))]
        {
            let ops = host_ops();
            let pool = (ops.pool_get)(1);
            if !pool.is_null() {
                (ops.pool_free)(pool, resource_pool);
                (*state).resource_pool = ptr::null_mut();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut EVENTS: Vec<&str> = Vec::new();
    static mut MANAGER: *mut u8 = ptr::null_mut();
    static mut ACQUIRED_REGION: *mut u8 = ptr::null_mut();
    static mut ACQUIRED_HANDLE: i32 = -1;
    static mut DESCRIPTOR: *mut u8 = ptr::null_mut();
    static mut CREATED_ARENA: *mut HeapDescriptor = ptr::null_mut();
    static mut DESTROY_RESULT: *mut HeapDescriptor = ptr::null_mut();
    static mut CACHE_POOL: *mut u8 = ptr::null_mut();
    static mut LAST_ALLOC_SIZE: usize = 0;
    static mut LAST_CREATE: (*mut HeapDescriptor, usize, usize) = (ptr::null_mut(), 0, 0);
    static mut LAST_DELETE: *mut u8 = ptr::null_mut();
    static mut LAST_RELEASE: (*mut u8, i32) = (ptr::null_mut(), -1);
    static mut LAST_POOL_FREE: (*mut u8, *mut u8) = (ptr::null_mut(), ptr::null_mut());

    unsafe extern "C" fn manager_get() -> *mut u8 {
        EVENTS.push("manager");
        MANAGER
    }

    unsafe extern "C" fn prepare(_state: *mut ResourceArenaState) {
        EVENTS.push("prepare");
    }

    unsafe extern "C" fn acquire(manager: *mut u8, handle: *mut i32) -> *mut u8 {
        EVENTS.push("acquire");
        assert_eq!(manager, MANAGER);
        *handle = ACQUIRED_HANDLE;
        ACQUIRED_REGION
    }

    unsafe extern "C" fn release(manager: *mut u8, handle: i32) {
        EVENTS.push("release");
        LAST_RELEASE = (manager, handle);
    }

    unsafe extern "C" fn allocate(size: usize) -> *mut u8 {
        EVENTS.push("allocate");
        LAST_ALLOC_SIZE = size;
        DESCRIPTOR
    }

    unsafe extern "C" fn heap_create(
        descriptor: *mut HeapDescriptor,
        start: usize,
        size: usize,
    ) -> *mut HeapDescriptor {
        EVENTS.push("create");
        LAST_CREATE = (descriptor, start, size);
        CREATED_ARENA
    }

    unsafe extern "C" fn heap_destroy(descriptor: *mut HeapDescriptor) -> *mut HeapDescriptor {
        EVENTS.push("destroy");
        assert_eq!(descriptor, CREATED_ARENA);
        DESTROY_RESULT
    }

    unsafe extern "C" fn delete(ptr: *mut u8) {
        EVENTS.push("delete");
        LAST_DELETE = ptr;
    }

    unsafe extern "C" fn pool_get(index: u32) -> *mut u8 {
        EVENTS.push("pool_get");
        assert_eq!(index, 1);
        CACHE_POOL
    }

    unsafe extern "C" fn pool_free(pool: *mut u8, ptr: *mut u8) {
        EVENTS.push("pool_free");
        LAST_POOL_FREE = (pool, ptr);
    }

    const TEST_OPS: ResourceArenaOps = ResourceArenaOps {
        manager_get,
        prepare,
        acquire,
        release,
        allocate,
        heap_create,
        heap_destroy,
        delete,
        pool_get,
        pool_free,
        extent_word: 0xe594_1004,
    };

    unsafe fn reset() {
        EVENTS.clear();
        MANAGER = ptr::addr_of_mut!(MANAGER).cast();
        ACQUIRED_REGION = ptr::addr_of_mut!(ACQUIRED_REGION).cast();
        ACQUIRED_HANDLE = 0x2468;
        DESCRIPTOR = ptr::addr_of_mut!(DESCRIPTOR).cast();
        CREATED_ARENA = ptr::addr_of_mut!(CREATED_ARENA).cast();
        DESTROY_RESULT = CREATED_ARENA;
        CACHE_POOL = ptr::addr_of_mut!(CACHE_POOL).cast();
        LAST_ALLOC_SIZE = 0;
        LAST_CREATE = (ptr::null_mut(), 0, 0);
        LAST_DELETE = ptr::null_mut();
        LAST_RELEASE = (ptr::null_mut(), -1);
        LAST_POOL_FREE = (ptr::null_mut(), ptr::null_mut());
        RESOURCE_ARENA_OPS = TEST_OPS;
    }

    unsafe fn teardown() {
        RESOURCE_ARENA_OPS = DEFAULT_RESOURCE_ARENA_OPS;
    }

    fn state() -> ResourceArenaState {
        ResourceArenaState {
            opaque_00: [0; 5],
            lazy_handle: -1,
            resource_pool: ptr::null_mut(),
            arena: ptr::null_mut(),
        }
    }

    #[test]
    fn activation_acquires_and_creates_once() {
        let guard = OPS_LOCK.lock();
        unsafe {
            reset();
            let mut resource = state();
            resource_arena_set_active(&mut resource, 7);
            assert_eq!(resource.lazy_handle, ACQUIRED_HANDLE);
            assert_eq!(resource.arena, CREATED_ARENA);
            assert_eq!(LAST_ALLOC_SIZE, 0x398);
            assert_eq!(LAST_CREATE, (DESCRIPTOR.cast(), ACQUIRED_REGION as usize, 0xe594_1004));
            assert_eq!(EVENTS, ["manager", "acquire", "allocate", "create"]);

            resource_arena_set_active(&mut resource, 1);
            assert_eq!(EVENTS, ["manager", "acquire", "allocate", "create"]);
            teardown();
        }
        drop(guard);
    }

    #[test]
    fn failed_acquire_restores_absent_sentinel() {
        let guard = OPS_LOCK.lock();
        unsafe {
            reset();
            ACQUIRED_REGION = ptr::null_mut();
            ACQUIRED_HANDLE = 0x7777;
            let mut resource = state();
            resource_arena_set_active(&mut resource, 1);
            assert_eq!(resource.lazy_handle, -1);
            assert!(resource.arena.is_null());
            assert_eq!(EVENTS, ["manager", "acquire"]);
            teardown();
        }
        drop(guard);
    }

    #[test]
    fn disabled_absent_state_is_untouched() {
        let guard = OPS_LOCK.lock();
        unsafe {
            reset();
            let mut resource = state();
            resource_arena_set_active(&mut resource, 0);
            assert!(EVENTS.is_empty());
            assert_eq!(resource.lazy_handle, -1);
            teardown();
        }
        drop(guard);
    }

    #[test]
    fn deactivation_destroys_then_releases_and_frees_pool() {
        let guard = OPS_LOCK.lock();
        unsafe {
            reset();
            let mut resource = state();
            resource.lazy_handle = 0x53;
            resource.arena = CREATED_ARENA;
            resource.resource_pool = ptr::addr_of_mut!(resource).cast();
            resource_arena_set_active(&mut resource, 0);
            assert!(resource.arena.is_null());
            assert_eq!(resource.lazy_handle, -1);
            assert!(resource.resource_pool.is_null());
            assert_eq!(LAST_DELETE, DESTROY_RESULT.cast());
            assert_eq!(LAST_RELEASE, (MANAGER, 0x53));
            assert_eq!(LAST_POOL_FREE, (CACHE_POOL, ptr::addr_of_mut!(resource).cast()));
            assert_eq!(
                EVENTS,
                ["prepare", "destroy", "delete", "manager", "release", "pool_get", "pool_free"]
            );
            teardown();
        }
        drop(guard);
    }

    #[test]
    fn deactivation_without_arena_still_releases_handle_and_pool() {
        let guard = OPS_LOCK.lock();
        unsafe {
            reset();
            let mut resource = state();
            resource.lazy_handle = 2;
            resource.resource_pool = ptr::addr_of_mut!(resource).cast();
            resource_arena_set_active(&mut resource, 0);
            assert_eq!(LAST_RELEASE, (MANAGER, 2));
            assert_eq!(
                EVENTS,
                ["prepare", "manager", "release", "pool_get", "pool_free"]
            );
            teardown();
        }
        drop(guard);
    }
}
