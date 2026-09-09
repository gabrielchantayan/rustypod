//! `trivial_vector12_destruct` — original: `FUN_0816cc20` @ 0x0816cc20 (72 bytes).
//!
//! Source: `ipod-decomp/decomp/c/015/0816cc20_FUN_0816cc20.c`; raw ARM bytes
//! establish the extent through the `pop {r4, r5, r6, pc}` at 0x0816cc64.
//!
//! Binary-decoding finds 15 direct call sites, all unconditional `bl` and no
//! predicated calls. The destructor walks the half-open `[begin, end)` range
//! in 12-byte increments. Its element destructor was optimized away because
//! the elements are trivial; the walk is nevertheless retained exactly. It
//! signed-divides `capacity - begin` by 12, passes that inert count and zero
//! to `cxx_array_dealloc`, then returns the vector without changing it.
//!
//! # Deviations
//!
//! The opaque `black_box` preserves the original signed capacity division even
//! though retailOS's already-ported `cxx_array_dealloc` ignores it. It has no
//! behavioral effect; LLVM may lower the retained arithmetic differently.

/// Three-word vector descriptor for trivial 12-byte elements.
///
/// On ARMv5 each pointer field is one 32-bit word, matching the retailOS
/// layout at +0, +4, and +8. Host pointers are wider, so tests use these named
/// fields rather than target byte offsets.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TrivialVector12 {
    pub begin: *mut u8,
    pub end: *mut u8,
    pub capacity: *mut u8,
}

type ArrayDealloc = unsafe extern "C" fn(*mut u8, usize, usize);

/// Destroys a vector of trivial 12-byte elements, releases its backing
/// storage, and returns `vector`. `vector` must address a valid descriptor
/// whose end is reachable from begin in 12-byte increments.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.trivial_vector12_destruct")]
#[inline(never)]
pub unsafe extern "C" fn trivial_vector12_destruct(
    vector: *mut TrivialVector12,
) -> *mut TrivialVector12 {
    unsafe { trivial_vector12_destruct_with(vector, crate::heap::veneers::cxx_array_dealloc) }
}

/// Separates the original cleanup call so host tests can observe its complete
/// three-register argument tuple without freeing fixture storage.
#[inline(always)]
unsafe fn trivial_vector12_destruct_with(
    vector: *mut TrivialVector12,
    release: ArrayDealloc,
) -> *mut TrivialVector12 {
    unsafe {
        let begin = core::ptr::addr_of!((*vector).begin).read();
        let end = core::ptr::addr_of!((*vector).end).read();
        let capacity = core::ptr::addr_of!((*vector).capacity).read();

        let mut current = begin;
        while current != end {
            current = current.wrapping_add(12);
        }

        let capacity_bytes = (capacity as usize).wrapping_sub(begin as usize) as i32;
        let element_count = core::hint::black_box((capacity_bytes / 12) as usize);
        release(begin, element_count, 0);
        vector
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};

    static DEALLOC_CALLS: AtomicUsize = AtomicUsize::new(0);
    static DEALLOC_STORAGE: AtomicUsize = AtomicUsize::new(0);
    static DEALLOC_COUNT: AtomicUsize = AtomicUsize::new(0);
    static DEALLOC_ELEMENT_SIZE: AtomicUsize = AtomicUsize::new(usize::MAX);

    unsafe extern "C" fn record_dealloc(storage: *mut u8, count: usize, element_size: usize) {
        DEALLOC_CALLS.fetch_add(1, Ordering::SeqCst);
        DEALLOC_STORAGE.store(storage as usize, Ordering::SeqCst);
        DEALLOC_COUNT.store(count, Ordering::SeqCst);
        DEALLOC_ELEMENT_SIZE.store(element_size, Ordering::SeqCst);
    }

    #[repr(C)]
    struct GuardedVector {
        before: usize,
        vector: TrivialVector12,
        after: usize,
    }

    #[test]
    fn releases_trivial_storage_with_derived_count_and_never_writes_descriptor() {
        let mut allocation = [0u8; 48];

        for (element_count, capacity_count) in [(0usize, 0usize), (1, 1), (2, 3), (3, 4)] {
            let begin = allocation.as_mut_ptr();
            let mut guarded = GuardedVector {
                before: 0x1122_3344_5566_7788,
                vector: TrivialVector12 {
                    begin,
                    end: begin.wrapping_add(element_count * 12),
                    capacity: begin.wrapping_add(capacity_count * 12),
                },
                after: 0x8877_6655_4433_2211,
            };
            let before = guarded.before;
            let descriptor = guarded.vector;
            let after = guarded.after;
            DEALLOC_CALLS.store(0, Ordering::SeqCst);
            DEALLOC_STORAGE.store(0, Ordering::SeqCst);
            DEALLOC_COUNT.store(usize::MAX, Ordering::SeqCst);
            DEALLOC_ELEMENT_SIZE.store(usize::MAX, Ordering::SeqCst);

            let result = unsafe { trivial_vector12_destruct_with(&mut guarded.vector, record_dealloc) };

            assert_eq!(result, core::ptr::addr_of_mut!(guarded.vector));
            assert_eq!(guarded.before, before, "prefix guard for {element_count} elements");
            assert_eq!(guarded.vector.begin, descriptor.begin, "begin");
            assert_eq!(guarded.vector.end, descriptor.end, "end");
            assert_eq!(guarded.vector.capacity, descriptor.capacity, "capacity");
            assert_eq!(guarded.after, after, "suffix guard for {element_count} elements");
            assert_eq!(DEALLOC_CALLS.load(Ordering::SeqCst), 1);
            assert_eq!(DEALLOC_STORAGE.load(Ordering::SeqCst), begin as usize);
            assert_eq!(DEALLOC_COUNT.load(Ordering::SeqCst), capacity_count);
            assert_eq!(DEALLOC_ELEMENT_SIZE.load(Ordering::SeqCst), 0);
        }
    }
}
