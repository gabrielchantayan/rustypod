//! `trivial_byte_vector_destruct` — original: `FUN_083e61f8` @ `0x083e61f8`.
//!
//! Raw `osos.dec` establishes the true 60-byte extent
//! `0x083e61f8..0x083e6234`; the next separately linked function begins at
//! `0x083e6234` with `push {r2,r3,r4,r5,r6,r7,r8,lr}`. The body has one
//! direct unconditional `bl`, to `cxx_array_dealloc` @ `0x08266f2c`, and no
//! predicated `bl` calls. Complete A32 decoding finds two inbound plain `bl`
//! call sites (`0x08104504` and `0x08104510`) and no predicated forms.
//!
//! Algorithm: walk the half-open byte range `[begin, end)` with the retained
//! empty trivial-destructor loop, calculate `end_of_storage - begin`, release
//! the backing allocation, and return the untouched vector descriptor.
//!
//! # Deliberate deviations
//!
//! The original passes the calculated byte capacity and zero element size to
//! the `cxx_array_dealloc` veneer, but that veneer tail-branches to
//! `operator_delete`, which consumes only the allocation pointer. The port
//! retains the calculation while routing the sole live argument through the
//! ported allocator seam.
//!
//! # Safety
//!
//! `vector` must address three consecutive pointer-width fields:
//! `{begin, end, end_of_storage}`. `end` must be reachable from `begin` by
//! byte increments, as in the original loop.

type StorageFree = unsafe extern "C" fn(*mut u8);

#[inline(never)]
unsafe extern "C" fn free_storage(storage: *mut u8) {
    crate::runtime::malloc_rt::free(storage);
}

/// Destroys a vector with trivially destructible byte elements, releases its
/// backing allocation, and returns `vector`.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.trivial_byte_vector_destruct")]
#[inline(never)]
pub unsafe extern "C" fn trivial_byte_vector_destruct(vector: *mut *mut u8) -> *mut *mut u8 {
    unsafe { trivial_byte_vector_destruct_with(vector, free_storage) }
}

#[inline(always)]
unsafe fn trivial_byte_vector_destruct_with(vector: *mut *mut u8, release: StorageFree) -> *mut *mut u8 {
    unsafe {
        let begin = vector.read();
        let end = vector.add(1).read();
        let capacity = vector.add(2).read();

        let mut current = begin;
        while current != end {
            current = current.wrapping_add(1);
            core::hint::black_box(current);
        }

        let capacity_bytes = (capacity as usize).wrapping_sub(begin as usize);
        core::hint::black_box(capacity_bytes);
        release(begin);
        vector
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};

    static FREE_CALLS: AtomicUsize = AtomicUsize::new(0);
    static FREED_STORAGE: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn record_free(storage: *mut u8) {
        FREE_CALLS.fetch_add(1, Ordering::SeqCst);
        FREED_STORAGE.store(storage as usize, Ordering::SeqCst);
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct VectorStorage {
        before: usize,
        begin: *mut u8,
        end: *mut u8,
        capacity: *mut u8,
        after: usize,
    }

    #[test]
    fn releases_nonempty_and_empty_byte_vectors_without_mutating_descriptors() {
        let mut allocation = [0u8; 32];
        let mut vector = VectorStorage {
            before: 0x1122_3344_5566_7788,
            begin: allocation.as_mut_ptr(),
            end: unsafe { allocation.as_mut_ptr().add(17) },
            capacity: unsafe { allocation.as_mut_ptr().add(32) },
            after: 0x8877_6655_4433_2211,
        };
        let before = vector;
        FREE_CALLS.store(0, Ordering::SeqCst);
        FREED_STORAGE.store(0, Ordering::SeqCst);

        let result = unsafe { trivial_byte_vector_destruct_with(&mut vector.begin, record_free) };

        assert_eq!(result, core::ptr::addr_of_mut!(vector.begin));
        assert_eq!(vector.before, before.before, "prefix guard");
        assert_eq!(vector.begin, before.begin, "begin");
        assert_eq!(vector.end, before.end, "end");
        assert_eq!(vector.capacity, before.capacity, "capacity");
        assert_eq!(vector.after, before.after, "suffix guard");
        assert_eq!(FREE_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(FREED_STORAGE.load(Ordering::SeqCst), before.begin as usize);

        let mut empty_allocation = [0u8; 1];
        let mut empty_vector = VectorStorage {
            before: 0x1020_3040_5060_7080,
            begin: empty_allocation.as_mut_ptr(),
            end: empty_allocation.as_mut_ptr(),
            capacity: unsafe { empty_allocation.as_mut_ptr().add(1) },
            after: 0x8070_6050_4030_2010,
        };
        let empty_before = empty_vector;
        FREE_CALLS.store(0, Ordering::SeqCst);
        FREED_STORAGE.store(0, Ordering::SeqCst);

        let empty_result = unsafe { trivial_byte_vector_destruct_with(&mut empty_vector.begin, record_free) };

        assert_eq!(empty_result, core::ptr::addr_of_mut!(empty_vector.begin));
        assert_eq!(empty_vector.before, empty_before.before, "empty prefix guard");
        assert_eq!(empty_vector.begin, empty_before.begin, "empty begin");
        assert_eq!(empty_vector.end, empty_before.end, "empty end");
        assert_eq!(empty_vector.capacity, empty_before.capacity, "empty capacity");
        assert_eq!(empty_vector.after, empty_before.after, "empty suffix guard");
        assert_eq!(FREE_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(FREED_STORAGE.load(Ordering::SeqCst), empty_before.begin as usize);
    }
}
