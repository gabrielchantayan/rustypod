//! `cxx_string_vector_record_destroy` — original: `FUN_08197c28` @
//! 0x08197c28 (64 bytes).
//!
//! Raw ARM establishes the exact extent 0x08197c28..0x08197c67: sixteen words
//! from `stmdb sp!,{r4,r5,r6,lr}` through `ldmia sp!,{r4,r5,r6,pc}`; the next
//! independently linked function begins at 0x08197c68. Decoding the body finds
//! three plain unconditional `bl` instructions and no predicated `bl` forms:
//! `cxx_string_vector_record_range_destroy` @ 0x083e2230,
//! `cxx_array_dealloc` @ 0x08266f2c, and `cxx_string_release` @ 0x083d8b04.
//!
//! Algorithm: destroy the half-open range of sixteen-byte `{COW string,
//! CxxStringVector}` records held by the vector at +4, deallocate that vector's
//! backing storage with `(capacity - begin) >> 4`, then release this record's
//! leading COW string and return this.
//!
//! # Deliberate deviation
//!
//! The record vector's named fields retain target word order when host pointers
//! widen; the range destroy, deallocation, and string-release call boundaries
//! are preserved.

use crate::cxx::string::cxx_string_release;
use crate::cxx::string_vector_record_range_destroy::cxx_string_vector_record_range_destroy;
use crate::heap::veneers::cxx_array_dealloc;

/// Three-word target vector descriptor for sixteen-byte string/vector records.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct StringVectorRecordVector {
    pub begin: *mut u8,
    pub end: *mut u8,
    pub capacity: *mut u8,
}

/// A COW string followed by a vector of sixteen-byte string/vector records.
#[repr(C)]
pub struct StringVectorRecord {
    pub string: *mut u8,
    pub records: StringVectorRecordVector,
}

type RangeDestroy = unsafe extern "C" fn(*mut u8, *mut u8, *mut u8);
type ArrayDealloc = unsafe extern "C" fn(*mut u8, usize, usize);
type StringRelease = unsafe extern "C" fn(*mut *mut u8);

/// Destroys the record vector, releases `string`, and returns `this`.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.cxx_string_vector_record_destroy")]
#[inline(never)]
pub unsafe extern "C" fn cxx_string_vector_record_destroy(
    this: *mut StringVectorRecord,
) -> *mut StringVectorRecord {
    unsafe {
        cxx_string_vector_record_destroy_with(
            this,
            cxx_string_vector_record_range_destroy,
            cxx_array_dealloc,
            cxx_string_release,
        )
    }
}

#[inline(always)]
unsafe fn cxx_string_vector_record_destroy_with(
    this: *mut StringVectorRecord,
    destroy_range: RangeDestroy,
    dealloc: ArrayDealloc,
    release_string: StringRelease,
) -> *mut StringVectorRecord {
    unsafe {
        let records = core::ptr::addr_of_mut!((*this).records);
        let begin = (*records).begin;
        let end = (*records).end;
        let capacity = (*records).capacity;

        destroy_range(records.cast(), begin, end);
        let capacity_records = capacity.offset_from(begin) as usize >> 4;
        core::hint::black_box(capacity_records);
        dealloc(begin, capacity_records, 0);
        release_string(core::ptr::addr_of_mut!((*this).string));
        this
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static CALL_ORDER: AtomicUsize = AtomicUsize::new(0);
    static RANGE_BEGIN: AtomicUsize = AtomicUsize::new(0);
    static RANGE_END: AtomicUsize = AtomicUsize::new(0);
    static DEALLOC_PTR: AtomicUsize = AtomicUsize::new(0);
    static DEALLOC_COUNT: AtomicUsize = AtomicUsize::new(0);
    static DEALLOC_ELEMENT_SIZE: AtomicUsize = AtomicUsize::new(0);
    static RELEASE_SLOT: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn record_range_destroy(_vector: *mut u8, begin: *mut u8, end: *mut u8) {
        assert_eq!(CALL_ORDER.fetch_add(1, Ordering::SeqCst), 0);
        RANGE_BEGIN.store(begin as usize, Ordering::SeqCst);
        RANGE_END.store(end as usize, Ordering::SeqCst);
    }

    unsafe extern "C" fn record_dealloc(ptr: *mut u8, count: usize, element_size: usize) {
        assert_eq!(CALL_ORDER.fetch_add(1, Ordering::SeqCst), 1);
        DEALLOC_PTR.store(ptr as usize, Ordering::SeqCst);
        DEALLOC_COUNT.store(count, Ordering::SeqCst);
        DEALLOC_ELEMENT_SIZE.store(element_size, Ordering::SeqCst);
    }

    unsafe extern "C" fn record_string_release(slot: *mut *mut u8) {
        assert_eq!(CALL_ORDER.fetch_add(1, Ordering::SeqCst), 2);
        RELEASE_SLOT.store(slot as usize, Ordering::SeqCst);
    }

    fn reset_observations() {
        CALL_ORDER.store(0, Ordering::SeqCst);
        RANGE_BEGIN.store(0, Ordering::SeqCst);
        RANGE_END.store(0, Ordering::SeqCst);
        DEALLOC_PTR.store(0, Ordering::SeqCst);
        DEALLOC_COUNT.store(0, Ordering::SeqCst);
        DEALLOC_ELEMENT_SIZE.store(0, Ordering::SeqCst);
        RELEASE_SLOT.store(0, Ordering::SeqCst);
    }

    #[test]
    fn destroys_range_frees_capacity_and_releases_leading_string_in_order() {
        let _guard = LOCK.lock();
        let mut storage = [0u8; 3 * 16];
        let mut record = StringVectorRecord {
            string: 0x1234usize as *mut u8,
            records: StringVectorRecordVector {
                begin: storage.as_mut_ptr(),
                end: unsafe { storage.as_mut_ptr().add(2 * 16) },
                capacity: unsafe { storage.as_mut_ptr().add(3 * 16) },
            },
        };
        reset_observations();

        let returned = unsafe {
            cxx_string_vector_record_destroy_with(
                &mut record,
                record_range_destroy,
                record_dealloc,
                record_string_release,
            )
        };

        assert!(core::ptr::eq(returned, &mut record));
        assert_eq!(CALL_ORDER.load(Ordering::SeqCst), 3);
        assert_eq!(RANGE_BEGIN.load(Ordering::SeqCst), storage.as_mut_ptr() as usize);
        assert_eq!(RANGE_END.load(Ordering::SeqCst), unsafe { storage.as_mut_ptr().add(32) } as usize);
        assert_eq!(DEALLOC_PTR.load(Ordering::SeqCst), storage.as_mut_ptr() as usize);
        assert_eq!(DEALLOC_COUNT.load(Ordering::SeqCst), 3);
        assert_eq!(DEALLOC_ELEMENT_SIZE.load(Ordering::SeqCst), 0);
        assert_eq!(RELEASE_SLOT.load(Ordering::SeqCst), core::ptr::addr_of_mut!(record.string) as usize);
        assert_eq!(record.string, 0x1234usize as *mut u8);
    }

    #[test]
    fn destroys_empty_range_and_still_frees_reserved_records() {
        let _guard = LOCK.lock();
        let mut storage = [0u8; 16];
        let mut record = StringVectorRecord {
            string: core::ptr::null_mut(),
            records: StringVectorRecordVector {
                begin: storage.as_mut_ptr(),
                end: storage.as_mut_ptr(),
                capacity: unsafe { storage.as_mut_ptr().add(16) },
            },
        };
        reset_observations();

        unsafe {
            cxx_string_vector_record_destroy_with(
                &mut record,
                record_range_destroy,
                record_dealloc,
                record_string_release,
            )
        };

        assert_eq!(RANGE_BEGIN.load(Ordering::SeqCst), RANGE_END.load(Ordering::SeqCst));
        assert_eq!(DEALLOC_COUNT.load(Ordering::SeqCst), 1);
        assert_eq!(RELEASE_SLOT.load(Ordering::SeqCst), core::ptr::addr_of_mut!(record.string) as usize);
    }
}
