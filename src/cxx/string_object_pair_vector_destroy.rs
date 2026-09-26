//! `string_object_pair_vector_destroy` — original: `FUN_083e3aa8` @
//! `0x083e3aa8` (48 bytes; `0x083e3aa8..0x083e3ad7`).
//!
//! Raw ARM words establish the true extent: `pop {r4,pc}` returns at
//! `0x083e3ad4`, and the next independent function begins with
//! `push {r2-r8,lr}` at `0x083e3ad8`. Raw A32 decoding finds two plain
//! unconditional body `bl` instructions—`cxx_record_range_destroy_16` at
//! `0x083e38a0` and `cxx_array_dealloc` at `0x08266f2c`—and no predicated
//! body `bl` instructions. A complete-image direct-call scan finds two plain
//! inbound `bl` sites (0x08100b5c and 0x0812bc98), with no predicated forms.
//!
//! Destroys the 16-byte `StringObjectPair` records in `[begin, end)`, releases
//! the backing allocation with `(capacity - begin) >> 4`, and returns the
//! vector header. Deliberate deviation: `u8` pointers preserve the target's
//! four-byte vector fields and sixteen-byte element arithmetic; host tests use
//! a replaceable range-destruction callback because host `StringObjectPair`
//! pointer fields are eight bytes wide.

use crate::cxx::templates::{cxx_record_range_destroy_16, StringObjectPair};
use crate::heap::veneers::cxx_array_dealloc;

/// ARM-layout vector header for 16-byte [`StringObjectPair`] records.
#[repr(C)]
pub struct StringObjectPairVector {
    pub begin: *mut u8,
    pub end: *mut u8,
    pub capacity: *mut u8,
}
type RecordRangeDestroy = unsafe extern "C" fn(*mut u8, *mut StringObjectPair, *mut StringObjectPair);
type ArrayDealloc = unsafe extern "C" fn(*mut u8, usize, usize);

/// Destroys the records and releases their backing allocation.
///
/// # Safety
///
/// `vector` must be non-NULL and contain bounds accepted by
/// [`cxx_record_range_destroy_16].
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn string_object_pair_vector_destroy(
    vector: *mut StringObjectPairVector,
) -> *mut StringObjectPairVector {
    unsafe { string_object_pair_vector_destroy_with(vector, cxx_record_range_destroy_16, cxx_array_dealloc) }
}

#[inline(always)]
unsafe fn string_object_pair_vector_destroy_with(
    vector: *mut StringObjectPairVector,
    range_destroy: RecordRangeDestroy,
    dealloc: ArrayDealloc,
) -> *mut StringObjectPairVector {
    let begin = unsafe { (*vector).begin };
    let end = unsafe { (*vector).end };
    unsafe { range_destroy(vector.cast(), begin.cast::<StringObjectPair>(), end.cast::<StringObjectPair>()) };
    let begin = unsafe { (*vector).begin };
    let capacity = unsafe { (*vector).capacity };
    let count = (capacity as usize).wrapping_sub(begin as usize) >> 4;
    unsafe { dealloc(begin, count, 0) };
    vector
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut RANGE: (*mut u8, *mut StringObjectPair, *mut StringObjectPair) = (
        core::ptr::null_mut(),
        core::ptr::null_mut(),
        core::ptr::null_mut(),
    );
    static mut DEALLOC: (*mut u8, usize, usize) = (core::ptr::null_mut(), 0, 0);

    unsafe extern "C" fn record_range(vector: *mut u8, begin: *mut StringObjectPair, end: *mut StringObjectPair) {
        unsafe { RANGE = (vector, begin, end) };
    }

    unsafe extern "C" fn record_dealloc(ptr: *mut u8, count: usize, element_size: usize) {
        unsafe { DEALLOC = (ptr, count, element_size) };
    }

    #[test]
    fn destroys_empty_range_and_deallocates_capacity_in_16_byte_elements() {
        let _lock = LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut storage = [0u32; 12];
        let begin = storage.as_mut_ptr().cast::<u8>();
        let mut vector = StringObjectPairVector { begin, end: begin, capacity: unsafe { begin.add(48) } };
        unsafe {
            RANGE = (core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut());
            DEALLOC = (core::ptr::null_mut(), 0, 0);
            assert!(core::ptr::eq(string_object_pair_vector_destroy_with(&mut vector, record_range, record_dealloc), &mut vector));
            assert_eq!(RANGE, (core::ptr::addr_of_mut!(vector).cast(), begin.cast(), begin.cast()));
            assert_eq!(DEALLOC, (begin, 3, 0));
        }
    }

    #[test]
    fn destroys_populated_range_but_uses_capacity_not_end_for_deallocation_count() {
        let _lock = LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut storage = [0u32; 16];
        let begin = storage.as_mut_ptr().cast::<u8>();
        let mut vector = StringObjectPairVector { begin, end: unsafe { begin.add(32) }, capacity: unsafe { begin.add(64) } };
        unsafe {
            RANGE = (core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut());
            DEALLOC = (core::ptr::null_mut(), 0, 0);
            string_object_pair_vector_destroy_with(&mut vector, record_range, record_dealloc);
            assert_eq!(RANGE, (core::ptr::addr_of_mut!(vector).cast(), begin.cast(), begin.add(32).cast()));
            assert_eq!(DEALLOC, (begin, 4, 0));
        }
    }
}
