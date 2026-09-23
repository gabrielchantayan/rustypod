//! Lazy buffer-pool storage accessor.
//!
//! `buffer_pool_get_or_create` — original: `FUN_081cda30` @ `0x081cda30`
//! (48 bytes: twelve instruction words; the literal global-pointer word at
//! `0x081cda60` begins after the body). The next real function begins at
//! `0x081cda64` with `push {r4, lr}`.
//!
//! # Verified calls and algorithm
//!
//! Raw ARM decoding finds two outbound plain `bl` calls — `operator_new(0x3c)`
//! @ `0x082aadd4` and the unported storage initializer @ `0x081cd904` — and
//! no predicated outbound `bl`. Complete A32 branch decoding finds three
//! inbound plain `bl` calls and no predicated inbound `bl` calls. The global
//! word at `0x089cfe74` caches a 15-word pointer table. On a NULL cache, the
//! function allocates its 60-byte table, gives that allocation to the
//! initializer, publishes it, and returns the reloaded cached value. A
//! non-NULL cache is returned without either call.
//!
//! # Deliberate deviations
//!
//! The storage initializer has no recovered semantic identity beyond its
//! pointer-table ABI. Target builds call its verified retailOS address; host
//! builds expose a narrow seam. The host cache replaces the live target global.

/// Firmware global word holding the lazy 15-entry pointer table.
pub const BUFFER_POOL_GLOBAL: usize = 0x089c_fe74;
const BUFFER_POOL_WORDS: usize = 15;

/// ABI of the unported initializer at `0x081cd904`.
pub type BufferPoolStorageInitialize = unsafe extern "C" fn(*mut u32);

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_buffer_pool_storage_initialize(_table: *mut u32) {}

/// Host seam for the unported pointer-table initializer.
#[cfg(not(target_os = "none"))]
pub static mut BUFFER_POOL_STORAGE_INITIALIZE: BufferPoolStorageInitialize = missing_buffer_pool_storage_initialize;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn buffer_pool_storage_initialize_target() -> BufferPoolStorageInitialize {
    core::mem::transmute(0x081c_d904usize)
}

#[cfg(not(target_os = "none"))]
static mut HOST_BUFFER_POOL: *mut u32 = core::ptr::null_mut();

/// Returns the cached buffer-pool pointer table, constructing it on first use.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn buffer_pool_get_or_create() -> *mut u32 {
    #[cfg(target_os = "none")]
    let cache = BUFFER_POOL_GLOBAL as *mut *mut u32;
    #[cfg(not(target_os = "none"))]
    let cache = core::ptr::addr_of_mut!(HOST_BUFFER_POOL);

    if unsafe { cache.read() }.is_null() {
        let table = unsafe { crate::heap::veneers::operator_new(BUFFER_POOL_WORDS * core::mem::size_of::<u32>()) }.cast::<u32>();
        #[cfg(target_os = "none")]
        unsafe { buffer_pool_storage_initialize_target()(table) };
        #[cfg(not(target_os = "none"))]
        unsafe { BUFFER_POOL_STORAGE_INITIALIZE(table) };
        unsafe { cache.write(table) };
    }
    unsafe { cache.read() }
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heap::types::{HeapDescriptor, HeapDescriptorDescriptor};
    use crate::heap::veneers::{HeapVeneerOps, HEAP_OPS};
    use core::ptr;

    static LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    static mut TABLE: [u32; BUFFER_POOL_WORDS] = [0; BUFFER_POOL_WORDS];
    static mut ALLOC_CALLS: usize = 0;
    static mut INITIALIZE_CALLS: usize = 0;

    unsafe extern "C" fn allocate(_heap: *mut HeapDescriptorDescriptor, size: usize, tag: usize) -> *mut u8 {
        assert_eq!(size, 0x3c);
        assert_eq!(tag, 2);
        unsafe { ALLOC_CALLS += 1; ptr::addr_of_mut!(TABLE).cast() }
    }
    unsafe extern "C" fn create(desc: *mut HeapDescriptor, _start: *mut u8, _size: usize) -> *mut HeapDescriptorDescriptor { desc.cast() }
    unsafe extern "C" fn no_alloc(_heap: *mut HeapDescriptorDescriptor, _size: usize, _tag: usize) -> *mut u8 { ptr::null_mut() }
    unsafe extern "C" fn no_free(_heap: *mut HeapDescriptorDescriptor, _ptr: *mut u8, _tag: usize) {}
    unsafe extern "C" fn no_realloc(_heap: *mut HeapDescriptorDescriptor, _ptr: *mut u8, _size: usize, _a3: usize, _a4: usize) -> *mut u8 { ptr::null_mut() }
    unsafe extern "C" fn no_handler(_code: usize) {}
    unsafe extern "C" fn no_raise(_sig: i32, _code: i32) -> i32 { 0 }
    unsafe extern "C" fn no_exit() {}
    unsafe extern "C" fn no_terminate(_code: i32) {}
    unsafe extern "C" fn initialize(table: *mut u32) {
        unsafe { INITIALIZE_CALLS += 1; table.add(BUFFER_POOL_WORDS - 1).write(0xa5a5_5a5a) };
    }

    struct Restore { heap: HeapVeneerOps, initializer: BufferPoolStorageInitialize, cache: *mut u32 }
    impl Drop for Restore {
        fn drop(&mut self) { unsafe {
            ptr::addr_of_mut!(HEAP_OPS).write_volatile(self.heap);
            BUFFER_POOL_STORAGE_INITIALIZE = self.initializer;
            HOST_BUFFER_POOL = self.cache;
        }}
    }

    #[test]
    fn allocates_initializes_publishes_then_returns_the_cached_table() {
        let _lock = LOCK.lock();
        let restore = unsafe { Restore {
            heap: ptr::addr_of!(HEAP_OPS).read_volatile(), initializer: BUFFER_POOL_STORAGE_INITIALIZE, cache: HOST_BUFFER_POOL,
        }};
        unsafe {
            HEAP_OPS = HeapVeneerOps { alloc: allocate, alloc_zero: no_alloc, free: no_free, realloc: no_realloc, create, new_handler: no_handler, raise: no_raise, exit: no_exit, terminate: no_terminate };
            HOST_BUFFER_POOL = ptr::null_mut(); ALLOC_CALLS = 0; INITIALIZE_CALLS = 0; TABLE = [0; BUFFER_POOL_WORDS];
            BUFFER_POOL_STORAGE_INITIALIZE = initialize;
            let first = buffer_pool_get_or_create();
            let second = buffer_pool_get_or_create();
            assert_eq!(first, ptr::addr_of_mut!(TABLE).cast());
            assert_eq!(second, first);
            assert_eq!(ALLOC_CALLS, 1);
            assert_eq!(INITIALIZE_CALLS, 1);
            assert_eq!(*first.add(BUFFER_POOL_WORDS - 1), 0xa5a5_5a5a);
        }
        drop(restore);
    }
}
