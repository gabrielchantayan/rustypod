//! Kernel-service heap veneers: the tag-0 entry points into the retailOS
//! heap, used by the RAM-side kernel-object layer.
//!
//! - `os_malloc` — original: `FUN_080769b8` @ 0x080769b8 (8 bytes).
//!   `mov r1, #0; b 0x080eb67c` — a pure tail veneer onto `malloc_wrapper`
//!   (heap/veneers.rs) with caller tag 0. 4 call sites, all in the
//!   kernel-service layer: `sem_create` (0x08056724), the mailbox create
//!   (0x0805675c) and the two-slot kernel-object create (0x080563a0,
//!   twice).
//! - `os_free` — original: `FUN_080f151c` @ 0x080f151c (8 bytes).
//!   `mov r1, #0; b 0x080e7970` — the matching tail veneer onto
//!   `free_wrapper` with tag 0. Reached from `sem_delete` (0x0805646c,
//!   conditional tail `bne`), the kernel-object delete (0x080564b0, `bl`)
//!   and the queue-node free 0x080b4c4c (`bl` + tail `b`).
//! - `heap_mutex_creating` — original: `FUN_080bead8` @ 0x080bead8
//!   (24 bytes). `bl 0x08077250` (lazy_init_default_heap), then
//!   `ldrb r0, [*0x089ca638, #0xb5]` — reads `mutex_state2` of the
//!   default-heap descriptor (the global @ 0x089ca638 holds the
//!   descriptor pointer; see heap/veneers.rs). That byte is `heap_lock`'s
//!   (0x0819d6cc, heap/wrappers.rs) "mutex creation in progress" marker:
//!   it is 1 exactly while `heap_lock` is creating the heap's own RTXC
//!   semaphore. `sem_create` (0x08056724) uses this as a recursion guard —
//!   while the heap is creating its own semaphore, semaphore cells must
//!   come from the static slot @ 0x089cc8f8, not from the heap.
//!   NAMING CORRECTION: earlier module headers (sync_sem.rs, sync_mutex.rs)
//!   described this function as an "ISR/system-context check" or "early
//!   boot flag" — both readings are stale; the byte is only ever written
//!   by `heap_lock` around its `mutex_create` call.
//!
//! Caller-tag map (the heap telemetry keeps per-tag byte counters): tag 0 =
//! kernel-service objects (these veneers), tag 1 = the ADS C runtime
//! malloc/free (runtime/malloc_rt.rs), tags 2/3 = the C++ `operator
//! new`/`operator delete` pairs (heap/veneers.rs), tag 0x2b = the aligned
//! pool (heap/pool.rs).
//!
//! Unlike the sibling kernel modules there is no dispatch table here: both
//! callees are already ported in this crate, so the exported functions
//! call them directly — the same direct tail branches as the original.
//!
//! Host-test seam (deviation, test-only): the real path cannot run on the
//! host — `malloc_wrapper` lazily creates the default heap through
//! `HEAP_OPS`, whose default `create` stub spins, and installing a mock
//! table here would race heap/veneers.rs's own tests (that table is
//! serialized by a lock private to their test module). The argument/tag
//! forwarding is therefore proven through `os_malloc_with`/`os_free_with`,
//! which take the wrapper as a parameter; the exported veneers pass the
//! real wrappers.

use crate::heap::types::{HeapDescriptor, DEFAULT_HEAP};
use crate::heap::veneers::{free_wrapper, lazy_init_default_heap, malloc_wrapper};

/// Caller tag 0: kernel-service allocations (original `mov r1, #0` in
/// both veneers; see the tag map in the module header).
const TAG_KERNEL: usize = 0;

/// Forwarding core of `os_malloc`, parameterized over the wrapper for the
/// host-test seam (see the module header).
#[inline(always)]
unsafe fn os_malloc_with(
    malloc: unsafe extern "C" fn(size: usize, tag: usize) -> *mut u8,
    size: usize,
) -> *mut u8 {
    malloc(size, TAG_KERNEL)
}

/// Forwarding core of `os_free`, parameterized over the wrapper for the
/// host-test seam. Like the original, there is no NULL guard here —
/// `free_wrapper`/`heap_free` ignore NULL downstream.
#[inline(always)]
unsafe fn os_free_with(free: unsafe extern "C" fn(ptr: *mut u8, tag: usize), ptr: *mut u8) {
    free(ptr, TAG_KERNEL)
}

/// os_malloc — original: `FUN_080769b8` @ 0x080769b8 (8 bytes).
///
/// Tag-0 allocation veneer: `malloc_wrapper(size, 0)`.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn os_malloc(size: usize) -> *mut u8 {
    os_malloc_with(malloc_wrapper, size)
}

/// os_free — original: `FUN_080f151c` @ 0x080f151c (8 bytes).
///
/// Tag-0 free veneer: `free_wrapper(ptr, 0)`.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn os_free(ptr: *mut u8) {
    os_free_with(free_wrapper, ptr)
}

/// Forwarding core of `heap_mutex_creating`, parameterized for the
/// host-test seam (the real path would run `HEAP_OPS.create` and race the
/// heap module's own tests — same reasoning as `os_malloc_with`).
/// Faithful shape: ensure the default heap exists, then read the byte.
#[inline(always)]
unsafe fn heap_mutex_creating_with(
    ensure_heap: unsafe extern "C" fn(),
    default_heap: unsafe fn() -> *mut HeapDescriptor,
) -> u32 {
    ensure_heap();
    (*default_heap()).mutex_state2 as u32
}

/// Reads the default-heap descriptor pointer (original global word @
/// 0x089ca638). The stored handle value is the descriptor pointer — see
/// `alloc_ported` in heap/veneers.rs for the same cast.
unsafe fn default_heap_desc() -> *mut HeapDescriptor {
    core::ptr::addr_of!(DEFAULT_HEAP).read() as *mut HeapDescriptor
}

/// heap_mutex_creating — original: `FUN_080bead8` @ 0x080bead8 (24 bytes).
///
/// Ensures the default heap exists, then returns its `mutex_state2` byte
/// (nonzero exactly while `heap_lock` is creating the heap's own RTXC
/// semaphore). `sem_create`'s recursion guard — see the module header.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn heap_mutex_creating() -> u32 {
    heap_mutex_creating_with(lazy_init_default_heap, default_heap_desc)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::Mutex;
    use std::vec;
    use std::vec::Vec;

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Call {
        Malloc { size: usize, tag: usize },
        Free { ptr: usize, tag: usize },
    }

    /// Module-local recorder — no shared crate globals are touched, so
    /// these tests are race-free under parallel `cargo test`.
    static CALLS: Mutex<Vec<Call>> = Mutex::new(Vec::new());

    /// Sentinel returned by the mock allocator.
    const MOCK_PTR: usize = 0x08a1_2710;

    unsafe extern "C" fn mock_malloc(size: usize, tag: usize) -> *mut u8 {
        CALLS.lock().unwrap().push(Call::Malloc { size, tag });
        MOCK_PTR as *mut u8
    }

    unsafe extern "C" fn mock_free(ptr: *mut u8, tag: usize) {
        CALLS.lock().unwrap().push(Call::Free {
            ptr: ptr as usize,
            tag,
        });
    }

    fn drain() -> Vec<Call> {
        core::mem::take(&mut *CALLS.lock().unwrap())
    }

    #[test]
    fn malloc_forwards_size_with_tag_0() {
        for size in [0usize, 1, 4, 0x8000, usize::MAX] {
            let p = unsafe { os_malloc_with(mock_malloc, size) };
            assert_eq!(p as usize, MOCK_PTR, "wrapper result is returned as-is");
            assert_eq!(drain(), vec![Call::Malloc { size, tag: 0 }]);
        }
    }

    #[test]
    fn free_forwards_ptr_with_tag_0() {
        let mut cell = 0u32;
        let ptr = &mut cell as *mut u32 as *mut u8;
        unsafe { os_free_with(mock_free, ptr) };
        assert_eq!(
            drain(),
            vec![Call::Free {
                ptr: ptr as usize,
                tag: 0,
            }]
        );
    }

    #[test]
    fn free_does_not_guard_null() {
        // The original has no NULL check — NULL is forwarded and ignored
        // downstream by heap_free.
        unsafe { os_free_with(mock_free, core::ptr::null_mut()) };
        assert_eq!(drain(), vec![Call::Free { ptr: 0, tag: 0 }]);
    }

    // --- heap_mutex_creating (0x080bead8) ---

    use crate::heap::types::HeapDescriptor;
    use core::mem::MaybeUninit;

    /// Zeroed descriptor storage + ensure-call recorder for the flag tests.
    /// One static per concern; `FLAG_LOCK` serializes the tests using them.
    static FLAG_LOCK: Mutex<()> = Mutex::new(());
    static mut FLAG_DESC: MaybeUninit<HeapDescriptor> = MaybeUninit::uninit();
    static mut ENSURE_CALLS: usize = 0;

    unsafe extern "C" fn mock_ensure_heap() {
        ENSURE_CALLS += 1;
    }

    unsafe fn mock_default_heap() -> *mut HeapDescriptor {
        // The original reads the global only after the ensure call; assert
        // that ordering here.
        assert!(ENSURE_CALLS > 0, "descriptor read before lazy init");
        core::ptr::addr_of_mut!(FLAG_DESC) as *mut HeapDescriptor
    }

    unsafe fn flag_desc_byte(value: u8) {
        let desc = core::ptr::addr_of_mut!(FLAG_DESC) as *mut HeapDescriptor;
        core::ptr::write_bytes(desc as *mut u8, 0, core::mem::size_of::<HeapDescriptor>());
        (*desc).mutex_state2 = value;
    }

    #[test]
    fn mutex_creating_reads_state2_after_init() {
        let _guard = FLAG_LOCK.lock().unwrap();
        unsafe {
            ENSURE_CALLS = 0;
            flag_desc_byte(0);
            assert_eq!(heap_mutex_creating_with(mock_ensure_heap, mock_default_heap), 0);
            assert_eq!(ENSURE_CALLS, 1, "lazy init runs exactly once per call");
            flag_desc_byte(1);
            assert_eq!(heap_mutex_creating_with(mock_ensure_heap, mock_default_heap), 1);
            assert_eq!(ENSURE_CALLS, 2);
        }
    }

    #[test]
    fn mutex_creating_zero_extends_the_byte() {
        // `ldrb` zero-extends: 0xff must come back as 0x000000ff.
        let _guard = FLAG_LOCK.lock().unwrap();
        unsafe {
            ENSURE_CALLS = 0;
            flag_desc_byte(0xff);
            assert_eq!(
                heap_mutex_creating_with(mock_ensure_heap, mock_default_heap),
                0xff
            );
        }
    }
}
