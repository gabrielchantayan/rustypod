//! Kernel-service heap veneers: the tag-0 entry points into the retailOS
//! heap, used by the RAM-side kernel-object layer.
//!
//! - `os_malloc` — original: `FUN_080769b8` @ 0x080769b8 (8 bytes).
//!   `mov r1, #0; b 0x080eb67c` — a pure tail veneer onto `malloc_wrapper`
//!   (heap/veneers.rs) with caller tag 0. 4 call sites, all in the
//!   kernel-service layer: `sem_create` (0x08056724), the mailbox create
//!   (0x0805675c) and the two-slot kernel-object create (0x080563a0,
//!   twice).
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
//! forwarding is therefore proven through the `os_malloc_with` seam, which
//! takes the wrapper as a parameter; the exported veneer passes the real
//! wrapper.

use crate::heap::veneers::malloc_wrapper;

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

/// os_malloc — original: `FUN_080769b8` @ 0x080769b8 (8 bytes).
///
/// Tag-0 allocation veneer: `malloc_wrapper(size, 0)`.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn os_malloc(size: usize) -> *mut u8 {
    os_malloc_with(malloc_wrapper, size)
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

}
