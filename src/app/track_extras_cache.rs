//! The `TTrackExtrasCache` fixed-static accessor.
//!
//! Port:
//! - [`track_extras_cache_get`] — original: `FUN_081ba3ac` @ `0x081ba3ac`
//!   (**192 bytes**: 176 bytes of code followed by the four-word literal pool
//!   at `0x081ba46c..0x081ba478`; **10 unconditional `bl` call sites, no
//!   predicated forms or tail branches**, verified by decoding every ARM
//!   B/BL word in `osos.dec`).
//!
//! ## Stock algorithm
//!
//! The accessor first initializes the fixed `TTrackExtrasCache` at
//! `0x08a77828` through its C++ guard word at `0x089cb1ac`, registering the
//! constructor result with `cxa_atexit`. It then reads the two-level client
//! handle at `cache + 0x44`. When that handle has no payload, it asks the
//! block manager to register the embedded node at `cache + 0x38`; lazily
//! constructs and caches a 24-byte resource at `cache + 0x48`; and hands the
//! cache to the result of [`framework_root_get`] through `FUN_08124af4`. It
//! returns the fixed cache address.
//!
//! ## Deliberate deviations
//!
//! `FUN_081ba710`, `FUN_083b51f4`, `FUN_081f7450`, and `FUN_08124af4` are
//! unported. Target builds call their verified fixed addresses; host builds
//! expose them through [`TRACK_EXTRAS_CACHE_OPS`]. The ported
//! [`framework_root_get`] is called directly. The existing
//! `MANAGER_CLIENT_REGISTER` seam is reused for `FUN_0818a630`.
//! The literal shutdown target `0x081af920` is **not a function entry**: raw
//! ARM starts there with `add sl, sp, #44` in the middle of an extant frame,
//! so it cannot be named or called as a valid callback. The port deliberately
//! registers a no-op handler instead.

use core::ffi::c_void;
use core::ptr;

use crate::app::framework_root::framework_root_get;
use crate::cxx::handle::handle_deref_or_null;
use crate::cxx::shared_cell::{shared_cell_release_direct, SharedCell};
use crate::heap::block_mgr::block_manager_get;
use crate::heap::client_register::MANAGER_CLIENT_REGISTER;
use crate::heap::pool_client::ClientNode;
use crate::heap::veneers::operator_new;
use crate::runtime::cxa_guard::{cxa_guard_acquire, cxa_guard_release};
use crate::runtime::shutdown_chain::cxa_atexit;

const TRACK_EXTRAS_CACHE_SIZE: usize = 24;
const DSO_HANDLE: i32 = 0x089c_a09c;

#[cfg(target_os = "none")]
type TargetWord = u32;
#[cfg(not(target_os = "none"))]
type TargetWord = usize;

/// The manager-registration node at `TTrackExtrasCache + 0x38`.
///
/// Its individual fields are not recovered. A target word is deliberately
/// native-width on hosts so the later pointer fields remain disjoint.
#[repr(C)]
pub struct TrackExtrasRegistrationNode {
    words: [TargetWord; 3],
}

/// The fixed object whose constructor's final observed member is byte `+0x64`.
///
/// `repr(C)` keeps the documented offsets on the 32-bit target. Host fields
/// widen so the two-level handle can carry a real host pointer without a
/// truncating `u32` fixture.
#[repr(C)]
pub struct TrackExtrasCache {
    opaque_00: [u32; 14],
    registration_node: TrackExtrasRegistrationNode,
    client_ref: *const *mut u8,
    cached_resource: *mut u8,
    opaque_4c: [u32; 7],
}

impl TrackExtrasCache {
    const fn empty() -> Self {
        Self {
            opaque_00: [0; 14],
            registration_node: TrackExtrasRegistrationNode { words: [0; 3] },
            client_ref: ptr::null(),
            cached_resource: ptr::null_mut(),
            opaque_4c: [0; 7],
        }
    }
}

/// Fixed storage replacing the firmware object at `0x08a77828`.
pub static mut TRACK_EXTRAS_CACHE: TrackExtrasCache = TrackExtrasCache::empty();
/// C++ local-static guard replacing the word at `0x089cb1ac`.
pub static mut TRACK_EXTRAS_CACHE_GUARD: u32 = 0;

pub type TrackExtrasCacheConstructor = unsafe extern "C" fn(
    cache: *mut TrackExtrasCache,
    arg1: u32,
    arg2: u32,
) -> *mut TrackExtrasCache;
pub type TemporaryHandleConstructor = unsafe extern "C" fn(
    temporary: *mut *const *mut u8,
    source: *const *const *mut u8,
);
pub type CachedResourceConstructor = unsafe extern "C" fn(
    block: *mut u8,
    temporary: *const *mut u8,
) -> *mut u8;
pub type CacheAttach = unsafe extern "C" fn(root: *mut u8, cache: *mut TrackExtrasCache);

/// Boundaries whose names cannot safely identify their still-unported bodies.
#[derive(Clone, Copy)]
pub struct TrackExtrasCacheOps {
    pub cache_construct: TrackExtrasCacheConstructor,
    pub temporary_handle_construct: TemporaryHandleConstructor,
    pub cached_resource_construct: CachedResourceConstructor,
    pub attach_cache: CacheAttach,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_cache_construct(
    cache: *mut TrackExtrasCache,
    arg1: u32,
    arg2: u32,
) -> *mut TrackExtrasCache {
    let function: TrackExtrasCacheConstructor = core::mem::transmute(0x081b_a710usize);
    function(cache, arg1, arg2)
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_cache_construct(
    cache: *mut TrackExtrasCache,
    _arg1: u32,
    _arg2: u32,
) -> *mut TrackExtrasCache { cache }

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_temporary_handle_construct(
    temporary: *mut *const *mut u8,
    source: *const *const *mut u8,
) {
    let function: TemporaryHandleConstructor = core::mem::transmute(0x083b_51f4usize);
    function(temporary, source);
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_temporary_handle_construct(
    temporary: *mut *const *mut u8,
    source: *const *const *mut u8,
) { temporary.write(source.read()); }

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_cached_resource_construct(
    block: *mut u8,
    temporary: *const *mut u8,
) -> *mut u8 {
    let function: CachedResourceConstructor = core::mem::transmute(0x081f_7450usize);
    function(block, temporary)
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_cached_resource_construct(
    block: *mut u8,
    _temporary: *const *mut u8,
) -> *mut u8 { block }


#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_attach_cache(root: *mut u8, cache: *mut TrackExtrasCache) {
    let function: CacheAttach = core::mem::transmute(0x0812_4af4usize);
    function(root, cache);
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_attach_cache(_root: *mut u8, _cache: *mut TrackExtrasCache) {}

pub const DEFAULT_TRACK_EXTRAS_CACHE_OPS: TrackExtrasCacheOps = TrackExtrasCacheOps {
    cache_construct: firmware_cache_construct,
    temporary_handle_construct: firmware_temporary_handle_construct,
    cached_resource_construct: firmware_cached_resource_construct,
    attach_cache: firmware_attach_cache,
};

/// Unported dependency boundaries; volatile loading retains their calls in
/// target code.
pub static mut TRACK_EXTRAS_CACHE_OPS: TrackExtrasCacheOps = DEFAULT_TRACK_EXTRAS_CACHE_OPS;

#[inline(always)]
unsafe fn ops() -> TrackExtrasCacheOps {
    ptr::read_volatile(ptr::addr_of!(TRACK_EXTRAS_CACHE_OPS))
}

/// Stand-in for invalid `0x081af920`; see the module-level anomaly note.
unsafe extern "C" fn track_extras_cache_destructor(_object: *mut c_void) {}

/// `track_extras_cache_get` — original: `FUN_081ba3ac` @ `0x081ba3ac`
/// (192 bytes including its literal pool; 10 unconditional `bl` callers).
///
/// Initializes and returns the fixed `TTrackExtrasCache`; when its client
/// handle has no payload, performs registration and lazy resource creation
/// before attaching the cache to the framework root.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.track_extras_cache_get")]
pub unsafe extern "C" fn track_extras_cache_get() -> *mut TrackExtrasCache {
    let guard = ptr::addr_of_mut!(TRACK_EXTRAS_CACHE_GUARD);
    let cache = ptr::addr_of_mut!(TRACK_EXTRAS_CACHE);
    if (guard.read_volatile() & 1) == 0 && cxa_guard_acquire(guard) != 0 {
        let this = (ops().cache_construct)(cache, 0, 0);
        cxa_atexit(this.cast::<c_void>(), track_extras_cache_destructor, DSO_HANDLE);
        cxa_guard_release(guard);
    }

    let client_ref = ptr::addr_of_mut!((*cache).client_ref);
    if handle_deref_or_null(client_ref).is_null() {
        let manager_register = ptr::read_volatile(ptr::addr_of!(MANAGER_CLIENT_REGISTER));
        manager_register(
            block_manager_get(),
            ptr::addr_of_mut!((*cache).registration_node).cast::<ClientNode>(),
            0,
            client_ref,
        );
        let resource = ptr::addr_of_mut!((*cache).cached_resource);
        if resource.read_volatile().is_null() {
            let mut temporary = ptr::null();
            (ops().temporary_handle_construct)(ptr::addr_of_mut!(temporary), client_ref);
            resource.write_volatile((ops().cached_resource_construct)(
                operator_new(TRACK_EXTRAS_CACHE_SIZE),
                ptr::addr_of!(temporary).cast::<*mut u8>(),
            ));
            shared_cell_release_direct(ptr::addr_of_mut!(temporary).cast::<*mut SharedCell>());
        }
        (ops().attach_cache)(framework_root_get(), cache);
    }
    cache
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::types::{HeapDescriptor, HeapDescriptorDescriptor};
    use crate::heap::veneers::{HeapVeneerOps, DEFAULT_HEAP_OPS, HEAP_OPS};
    use crate::runtime::shutdown_chain::{
        lib_shutdown_chain, shutdown_chain_head, ShutdownNode, SHUTDOWN_ALLOC, SHUTDOWN_FREE,
    };
    use std::boxed::Box;
    use std::sync::{Mutex, MutexGuard};

    static LOCK: Mutex<()> = Mutex::new(());
    static mut CONSTRUCT_CALLS: u32 = 0;
    static mut TEMPORARY_CALLS: u32 = 0;
    static mut RESOURCE_CALLS: u32 = 0;
    static mut ATTACH_CALLS: u32 = 0;
    static mut CLIENT: u8 = 0;
    static mut CLIENT_CELL: *mut u8 = ptr::null_mut();
    static mut RESOURCE: u8 = 0;
    static mut RESOURCE_BLOCK: [u8; TRACK_EXTRAS_CACHE_SIZE] = [0; TRACK_EXTRAS_CACHE_SIZE];

    unsafe extern "C" fn cache_alloc(
        _heap: *mut HeapDescriptorDescriptor,
        size: usize,
        tag: usize,
    ) -> *mut u8 {
        assert_eq!((size, tag), (TRACK_EXTRAS_CACHE_SIZE, 2));
        ptr::addr_of_mut!(RESOURCE_BLOCK).cast()
    }

    unsafe extern "C" fn unused_alloc(
        _heap: *mut HeapDescriptorDescriptor,
        _size: usize,
        _tag: usize,
    ) -> *mut u8 { ptr::null_mut() }
    unsafe extern "C" fn unused_free(
        _heap: *mut HeapDescriptorDescriptor,
        _block: *mut u8,
        _tag: usize,
    ) {}
    unsafe extern "C" fn unused_realloc(
        _heap: *mut HeapDescriptorDescriptor,
        _block: *mut u8,
        _size: usize,
        _arg3: usize,
        _arg4: usize,
    ) -> *mut u8 { ptr::null_mut() }
    unsafe extern "C" fn cache_create(
        descriptor: *mut HeapDescriptor,
        _start: *mut u8,
        _size: usize,
    ) -> *mut HeapDescriptorDescriptor { descriptor.cast() }
    unsafe extern "C" fn unused_new_handler(_code: usize) {}
    unsafe extern "C" fn unused_raise(_sig: i32, _code: i32) -> i32 { 0 }
    unsafe extern "C" fn unused_exit() {}
    unsafe extern "C" fn unused_terminate(_code: i32) {}

    const CACHE_HEAP_OPS: HeapVeneerOps = HeapVeneerOps {
        alloc: cache_alloc,
        alloc_zero: unused_alloc,
        free: unused_free,
        realloc: unused_realloc,
        create: cache_create,
        new_handler: unused_new_handler,
        raise: unused_raise,
        exit: unused_exit,
        terminate: unused_terminate,
    };


    unsafe extern "C" fn shutdown_alloc(_size: usize) -> *mut u8 {
        Box::into_raw(Box::new(ShutdownNode {
            next: ptr::null_mut(),
            arg: ptr::null_mut(),
            handler: track_extras_cache_destructor,
            key: 0,
        })) as *mut u8
    }

    unsafe extern "C" fn shutdown_free(block: *mut u8) {
        drop(Box::from_raw(block as *mut ShutdownNode));
    }

    unsafe extern "C" fn initialized_cache(
        cache: *mut TrackExtrasCache,
        arg1: u32,
        arg2: u32,
    ) -> *mut TrackExtrasCache {
        assert_eq!((arg1, arg2), (0, 0));
        CONSTRUCT_CALLS += 1;
        CLIENT_CELL = ptr::addr_of_mut!(CLIENT);
        (*cache).client_ref = ptr::addr_of!(CLIENT_CELL);
        cache
    }
    unsafe extern "C" fn record_temporary(
        temporary: *mut *const *mut u8,
        source: *const *const *mut u8,
    ) { TEMPORARY_CALLS += 1; temporary.write(source.read()); }
    unsafe extern "C" fn record_resource(_block: *mut u8, _temporary: *const *mut u8) -> *mut u8 {
        RESOURCE_CALLS += 1;
        ptr::addr_of_mut!(RESOURCE)
    }
    unsafe extern "C" fn record_attach(_root: *mut u8, _cache: *mut TrackExtrasCache) { ATTACH_CALLS += 1; }

    const RECORDING_OPS: TrackExtrasCacheOps = TrackExtrasCacheOps {
        cache_construct: initialized_cache,
        temporary_handle_construct: record_temporary,
        cached_resource_construct: record_resource,
        attach_cache: record_attach,
    };

    fn reset() -> MutexGuard<'static, ()> {
        let lock = LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        unsafe {
            TRACK_EXTRAS_CACHE = TrackExtrasCache::empty();
            TRACK_EXTRAS_CACHE_GUARD = 0;
            TRACK_EXTRAS_CACHE_OPS = RECORDING_OPS;
            CONSTRUCT_CALLS = 0;
            TEMPORARY_CALLS = 0;
            RESOURCE_CALLS = 0;
            ATTACH_CALLS = 0;
            CLIENT_CELL = ptr::null_mut();
            *shutdown_chain_head() = ptr::null_mut();
            SHUTDOWN_ALLOC = shutdown_alloc;
            SHUTDOWN_FREE = shutdown_free;
            HEAP_OPS = CACHE_HEAP_OPS;
        }
        lock
    }

    fn restore(lock: MutexGuard<'static, ()>) {
        unsafe {
            lib_shutdown_chain(0);
            TRACK_EXTRAS_CACHE_OPS = DEFAULT_TRACK_EXTRAS_CACHE_OPS;
            TRACK_EXTRAS_CACHE = TrackExtrasCache::empty();
            TRACK_EXTRAS_CACHE_GUARD = 0;
            SHUTDOWN_ALLOC = crate::malloc_rt::malloc;
            SHUTDOWN_FREE = crate::malloc_rt::free;
            HEAP_OPS = DEFAULT_HEAP_OPS;
        }
        drop(lock);
    }

    #[test]
    fn initializes_once_and_returns_fixed_cache() {
        let lock = reset();
        unsafe {
            let first = track_extras_cache_get();
            assert_eq!(first, ptr::addr_of_mut!(TRACK_EXTRAS_CACHE));
            assert_eq!(track_extras_cache_get(), first);
            assert_eq!(CONSTRUCT_CALLS, 1, "guard admits exactly one constructor call");
            assert_eq!(TRACK_EXTRAS_CACHE_GUARD, 1);
            assert_eq!(TEMPORARY_CALLS, 0, "live handle skips registration path");
            assert!(!shutdown_chain_head().read().is_null(), "constructor result is registered");
        }
        restore(lock);
    }

    #[test]
    fn absent_client_creates_resource_once_and_attaches_each_time() {
        let lock = reset();
        unsafe {
            TRACK_EXTRAS_CACHE_GUARD = 1;
            let first = track_extras_cache_get();
            assert_eq!(first, ptr::addr_of_mut!(TRACK_EXTRAS_CACHE));
            assert_eq!(TEMPORARY_CALLS, 1);
            assert_eq!(RESOURCE_CALLS, 1);
            assert_eq!(ATTACH_CALLS, 1);
            track_extras_cache_get();
            assert_eq!(TEMPORARY_CALLS, 1, "cached resource suppresses reconstruction");
            assert_eq!(RESOURCE_CALLS, 1);
            assert_eq!(ATTACH_CALLS, 2, "unregistered client repeats the attach path");
        }
        restore(lock);
    }
}
