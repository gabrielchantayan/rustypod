//! `cxx_string_vector_destruct` — original: `FUN_083e5b88` @ 0x083e5b88
//! (48 bytes).
//!
//! Raw ARM establishes the exact extent 0x083e5b88..0x083e5bb8: the next
//! independently linked function starts at 0x083e5bb8. It loads the vector's
//! `begin` and `end`, invokes the range walker at 0x083e5950, computes
//! `(capacity - begin) >> 2`, clears r2, calls `cxx_array_dealloc`, and returns
//! the original descriptor. The range walker releases every four-byte COW
//! string slot in the half-open `[begin, end)` range via `cxx_string_release`.
//! Binary decoding finds ten direct, unconditional `bl` callers and no
//! predicated calls or direct tail branches.
//!
//! # Deliberate deviation
//!
//! `FUN_083e5950` is not separately ported. This port inlines its verified
//! range-walk behavior and calls the existing `cxx_string_release` seam;
//! therefore the unported helper's call boundary is intentionally absent.

use crate::cxx::string::cxx_string_release;
use crate::heap::veneers::cxx_array_dealloc;

/// Three-word `std::vector<basic_string>` descriptor.
///
/// On ARMv5 each field occupies one 32-bit word at +0, +4, and +8. Named
/// fields preserve that layout on target while host tests retain native pointer
/// width without overlapping fields.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CxxStringVector {
    pub begin: *mut *mut u8,
    pub end: *mut *mut u8,
    pub capacity: *mut *mut u8,
}

type StringRelease = unsafe extern "C" fn(*mut *mut u8);
type ArrayDealloc = unsafe extern "C" fn(*mut u8, usize, usize);

/// Releases every COW string in `vector`, frees its backing allocation, and
/// returns `vector`. `end` must be reachable from `begin` in four-byte target
/// string slots.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.cxx_string_vector_destruct")]
#[inline(never)]
pub unsafe extern "C" fn cxx_string_vector_destruct(
    vector: *mut CxxStringVector,
) -> *mut CxxStringVector {
    unsafe { cxx_string_vector_destruct_with(vector, cxx_string_release, cxx_array_dealloc) }
}

/// Separates the two verified callees so host tests can observe the element
/// walk and the complete three-register deallocation tuple without dereferencing
/// synthetic COW-string storage.
#[inline(always)]
unsafe fn cxx_string_vector_destruct_with(
    vector: *mut CxxStringVector,
    release_string: StringRelease,
    release_storage: ArrayDealloc,
) -> *mut CxxStringVector {
    unsafe {
        let begin = (*vector).begin;
        let end = (*vector).end;
        let capacity = (*vector).capacity;

        let mut current = begin;
        while current != end {
            release_string(current);
            current = current.add(1);
        }

        let capacity_slots = capacity.offset_from(begin) as usize;
        core::hint::black_box(capacity_slots);
        release_storage(begin.cast(), capacity_slots, 0);
        vector
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};

    static RELEASE_COUNT: AtomicUsize = AtomicUsize::new(0);
    static RELEASED_SLOTS: [AtomicUsize; 3] = [
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
    ];
    static DEALLOC_PTR: AtomicUsize = AtomicUsize::new(0);
    static DEALLOC_COUNT: AtomicUsize = AtomicUsize::new(0);
    static DEALLOC_ELEMENT_SIZE: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn record_string_release(slot: *mut *mut u8) {
        let index = RELEASE_COUNT.fetch_add(1, Ordering::SeqCst);
        RELEASED_SLOTS[index].store(slot as usize, Ordering::SeqCst);
    }

    unsafe extern "C" fn record_array_dealloc(ptr: *mut u8, count: usize, element_size: usize) {
        DEALLOC_PTR.store(ptr as usize, Ordering::SeqCst);
        DEALLOC_COUNT.store(count, Ordering::SeqCst);
        DEALLOC_ELEMENT_SIZE.store(element_size, Ordering::SeqCst);
    }

    fn reset_observations() {
        RELEASE_COUNT.store(0, Ordering::SeqCst);
        for slot in &RELEASED_SLOTS {
            slot.store(0, Ordering::SeqCst);
        }
        DEALLOC_PTR.store(0, Ordering::SeqCst);
        DEALLOC_COUNT.store(0, Ordering::SeqCst);
        DEALLOC_ELEMENT_SIZE.store(0, Ordering::SeqCst);
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct GuardedVector {
        before: usize,
        vector: CxxStringVector,
        after: usize,
    }

    #[test]
    fn releases_each_string_in_order_then_frees_backing_storage_without_mutation() {
        let mut strings = [
            0x1111usize as *mut u8,
            0x2222usize as *mut u8,
            0x3333usize as *mut u8,
        ];
        let mut guarded = GuardedVector {
            before: 0x1122_3344_5566_7788,
            vector: CxxStringVector {
                begin: strings.as_mut_ptr(),
                end: unsafe { strings.as_mut_ptr().add(3) },
                capacity: unsafe { strings.as_mut_ptr().add(3) },
            },
            after: 0x8877_6655_4433_2211,
        };
        let before = guarded;
        reset_observations();

        let result = unsafe {
            cxx_string_vector_destruct_with(
                &mut guarded.vector,
                record_string_release,
                record_array_dealloc,
            )
        };

        assert_eq!(result, core::ptr::addr_of_mut!(guarded.vector));
        assert_eq!(RELEASE_COUNT.load(Ordering::SeqCst), 3);
        for index in 0..3 {
            assert_eq!(RELEASED_SLOTS[index].load(Ordering::SeqCst), unsafe { strings.as_mut_ptr().add(index) } as usize);
        }
        assert_eq!(DEALLOC_PTR.load(Ordering::SeqCst), strings.as_mut_ptr() as usize);
        assert_eq!(DEALLOC_COUNT.load(Ordering::SeqCst), 3);
        assert_eq!(DEALLOC_ELEMENT_SIZE.load(Ordering::SeqCst), 0);
        assert_eq!(guarded.before, before.before, "prefix guard");
        assert_eq!(guarded.vector.begin, before.vector.begin, "begin");
        assert_eq!(guarded.vector.end, before.vector.end, "end");
        assert_eq!(guarded.vector.capacity, before.vector.capacity, "capacity");
        assert_eq!(guarded.after, before.after, "suffix guard");
    }

    #[test]
    fn empty_vector_skips_string_releases_and_still_frees_begin() {
        let mut storage = [0usize; 1];
        let mut vector = CxxStringVector {
            begin: storage.as_mut_ptr().cast(),
            end: storage.as_mut_ptr().cast(),
            capacity: unsafe { storage.as_mut_ptr().add(1).cast() },
        };
        let before = vector;
        reset_observations();

        let result = unsafe {
            cxx_string_vector_destruct_with(
                &mut vector,
                record_string_release,
                record_array_dealloc,
            )
        };

        assert_eq!(result, core::ptr::addr_of_mut!(vector));
        assert_eq!(RELEASE_COUNT.load(Ordering::SeqCst), 0);
        assert_eq!(DEALLOC_PTR.load(Ordering::SeqCst), storage.as_mut_ptr() as usize);
        assert_eq!(DEALLOC_COUNT.load(Ordering::SeqCst), 1);
        assert_eq!(DEALLOC_ELEMENT_SIZE.load(Ordering::SeqCst), 0);
        assert_eq!(vector.begin, before.begin);
        assert_eq!(vector.end, before.end);
        assert_eq!(vector.capacity, before.capacity);
    }
}
