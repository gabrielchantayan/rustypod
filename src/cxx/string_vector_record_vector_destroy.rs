//! `cxx_string_vector_record_vector_destroy` — original: `FUN_083e2558` @
//! 0x083e2558 (76 bytes; `0x083e2558..0x083e25a3`).
//!
//! Raw `osos.dec` words establish the true extent: the next independently
//! linked function starts at 0x083e25a4 with `push {r2,r3,r4,r5,r6,r7,r8,lr}`.
//! The body contains three plain unconditional `bl` instructions—to
//! `cxx_string_vector_destruct` @ 0x083e5b88, `cxx_string_release` @
//! 0x083d8b04, and `cxx_array_dealloc` @ 0x08266f2c—and no predicated `bl`.
//! Ghidra omits the final direct deallocation call. Two direct inbound `bl`
//! call sites are recovered at 0x081348c4 and 0x083c1658.
//!
//! Algorithm: walk the vector's half-open range of sixteen-byte `{COW string,
//! CxxStringVector}` records, destruct each embedded vector and then release
//! its leading COW-string slot. Finally release the backing storage with
//! `(capacity - begin) >> 4` and return the descriptor.
//!
//! # Deliberate deviation
//!
//! The raw body recovers the record slot by subtracting four from the embedded
//! vector destructor's returned pointer. This port preserves that data flow;
//! LLVM may fold it to the equivalent record-base address.

use crate::cxx::string::cxx_string_release;
use crate::cxx::string_vector_destruct::{cxx_string_vector_destruct, CxxStringVector};
use crate::cxx::string_vector_record_destroy::StringVectorRecordVector;
use crate::heap::veneers::cxx_array_dealloc;

type VectorDestruct = unsafe extern "C" fn(*mut CxxStringVector) -> *mut CxxStringVector;
type StringRelease = unsafe extern "C" fn(*mut *mut u8);
type ArrayDealloc = unsafe extern "C" fn(*mut u8, usize, usize);

const RECORD_STRIDE: usize = 0x10;
const RECORD_VECTOR: usize = 4;

/// Destroys the sixteen-byte string/vector records held by `vector`, frees its
/// backing allocation, and returns `vector`.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.cxx_string_vector_record_vector_destroy")]
#[inline(never)]
pub unsafe extern "C" fn cxx_string_vector_record_vector_destroy(
    vector: *mut StringVectorRecordVector,
) -> *mut StringVectorRecordVector {
    unsafe {
        cxx_string_vector_record_vector_destroy_with(
            vector,
            cxx_string_vector_destruct,
            cxx_string_release,
            cxx_array_dealloc,
        )
    }
}

#[inline(always)]
unsafe fn cxx_string_vector_record_vector_destroy_with(
    vector: *mut StringVectorRecordVector,
    destruct_vector: VectorDestruct,
    release_string: StringRelease,
    dealloc: ArrayDealloc,
) -> *mut StringVectorRecordVector {
    unsafe {
        let begin = (*vector).begin;
        let end = (*vector).end;
        let capacity = (*vector).capacity;
        let mut current = begin;
        while current != end {
            let embedded_vector = destruct_vector(current.add(RECORD_VECTOR).cast());
            release_string(embedded_vector.cast::<u8>().sub(RECORD_VECTOR).cast());
            current = current.add(RECORD_STRIDE);
        }
        let capacity_records = capacity.offset_from(begin) as usize >> 4;
        core::hint::black_box(capacity_records);
        dealloc(begin, capacity_records, 0);
        vector
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};

    static VECTOR_CALLS: [AtomicUsize; 2] = [AtomicUsize::new(0), AtomicUsize::new(0)];
    static STRING_CALLS: [AtomicUsize; 2] = [AtomicUsize::new(0), AtomicUsize::new(0)];
    static VECTOR_COUNT: AtomicUsize = AtomicUsize::new(0);
    static STRING_COUNT: AtomicUsize = AtomicUsize::new(0);
    static DEALLOC: [AtomicUsize; 3] = [AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0)];

    unsafe extern "C" fn record_vector_destruct(vector: *mut CxxStringVector) -> *mut CxxStringVector {
        let index = VECTOR_COUNT.fetch_add(1, Ordering::SeqCst);
        VECTOR_CALLS[index].store(vector as usize, Ordering::SeqCst);
        vector
    }

    unsafe extern "C" fn record_string_release(string: *mut *mut u8) {
        let index = STRING_COUNT.fetch_add(1, Ordering::SeqCst);
        STRING_CALLS[index].store(string as usize, Ordering::SeqCst);
    }

    unsafe extern "C" fn record_dealloc(ptr: *mut u8, count: usize, element_size: usize) {
        DEALLOC[0].store(ptr as usize, Ordering::SeqCst);
        DEALLOC[1].store(count, Ordering::SeqCst);
        DEALLOC[2].store(element_size, Ordering::SeqCst);
    }

    fn reset_observations() {
        VECTOR_COUNT.store(0, Ordering::SeqCst);
        STRING_COUNT.store(0, Ordering::SeqCst);
        for call in VECTOR_CALLS.iter().chain(STRING_CALLS.iter()).chain(DEALLOC.iter()) {
            call.store(0, Ordering::SeqCst);
        }
    }

    #[test]
    fn destroys_empty_and_populated_record_vectors_in_order() {
        let mut records = [0u8; RECORD_STRIDE * 3];
        let begin = records.as_mut_ptr();
        let mut vector = StringVectorRecordVector {
            begin,
            end: begin,
            capacity: unsafe { begin.add(RECORD_STRIDE) },
        };
        reset_observations();

        let returned = unsafe {
            cxx_string_vector_record_vector_destroy_with(
                &mut vector,
                record_vector_destruct,
                record_string_release,
                record_dealloc,
            )
        };
        assert!(core::ptr::eq(returned, &mut vector));
        assert_eq!(VECTOR_COUNT.load(Ordering::SeqCst), 0);
        assert_eq!(STRING_COUNT.load(Ordering::SeqCst), 0);
        assert_eq!(DEALLOC[0].load(Ordering::SeqCst), begin as usize);
        assert_eq!(DEALLOC[1].load(Ordering::SeqCst), 1);
        assert_eq!(DEALLOC[2].load(Ordering::SeqCst), 0);

        vector.end = unsafe { begin.add(RECORD_STRIDE * 2) };
        vector.capacity = unsafe { begin.add(RECORD_STRIDE * 3) };
        reset_observations();
        unsafe {
            cxx_string_vector_record_vector_destroy_with(
                &mut vector,
                record_vector_destruct,
                record_string_release,
                record_dealloc,
            );
        }
        assert_eq!(VECTOR_COUNT.load(Ordering::SeqCst), 2);
        assert_eq!(STRING_COUNT.load(Ordering::SeqCst), 2);
        for index in 0..2 {
            let record = unsafe { begin.add(index * RECORD_STRIDE) };
            assert_eq!(VECTOR_CALLS[index].load(Ordering::SeqCst), unsafe { record.add(RECORD_VECTOR) } as usize);
            assert_eq!(STRING_CALLS[index].load(Ordering::SeqCst), record as usize);
        }
        assert_eq!(DEALLOC[0].load(Ordering::SeqCst), begin as usize);
        assert_eq!(DEALLOC[1].load(Ordering::SeqCst), 3);
        assert_eq!(DEALLOC[2].load(Ordering::SeqCst), 0);
    }
}
