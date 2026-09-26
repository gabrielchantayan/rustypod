//! `tagged_value_vector_destroy` — original: `FUN_083e429c` @ `0x083e429c`
//! (48 bytes; `0x083e429c..0x083e42cb`).
//!
//! Raw ARM words establish the exact extent: `pop {r4,pc}` returns at
//! `0x083e42c8`, and the next independent function begins with
//! `push {r2-r8,lr}` at `0x083e42cc`. Raw A32 decoding finds two plain
//! unconditional body `bl` instructions (`tagged_value_range_destroy` at
//! `0x083e41d4` and `cxx_array_dealloc` at `0x08266f2c`) and no predicated
//! body `bl` instructions. A full-image direct-call scan finds two inbound
//! plain `bl` sites (0x0827c844 and 0x0827c894), with no predicated sites.
//!
//! Destroys the 16-byte tagged values in `[begin, end)`, then deallocates the
//! backing allocation with `(capacity - begin) >> 4` and returns the vector.
//!
//! Deliberate deviation: the unported range destructor remains a direct
//! firmware-address call on target and a replaceable host seam in tests.

use crate::heap::veneers::cxx_array_dealloc;

/// ARM-layout representation of a vector of 16-byte tagged values.
#[repr(C)]
pub struct TaggedValueVector {
    pub begin: *mut u8,
    pub end: *mut u8,
    pub capacity: *mut u8,
}

type TaggedValueRangeDestroy = unsafe extern "C" fn(*mut u8, *mut u8);
type ArrayDealloc = unsafe extern "C" fn(*mut u8, usize, usize);

const RETAIL_TAGGED_VALUE_RANGE_DESTROY: usize = 0x083e_41d4;

#[cfg(not(target_os = "none"))]
use core::ptr::addr_of;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_tagged_value_range_destroy(_: *mut u8, _: *mut u8) {
    panic!("install tagged-value range destructor before host use")
}

#[cfg(not(target_os = "none"))]
pub static mut TAGGED_VALUE_VECTOR_DESTROY_OPS: TaggedValueVectorDestroyOps = TaggedValueVectorDestroyOps {
    tagged_value_range_destroy: missing_tagged_value_range_destroy,
};

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct TaggedValueVectorDestroyOps {
    pub tagged_value_range_destroy: TaggedValueRangeDestroy,
}

#[inline(always)]
unsafe fn tagged_value_range_destroy(begin: *mut u8, end: *mut u8) {
    #[cfg(target_os = "none")]
    {
        let destroy: TaggedValueRangeDestroy = unsafe { core::mem::transmute(RETAIL_TAGGED_VALUE_RANGE_DESTROY) };
        unsafe { destroy(begin, end) };
    }

    #[cfg(not(target_os = "none"))]
    {
        let destroy = unsafe {
            core::ptr::read_volatile(addr_of!(TAGGED_VALUE_VECTOR_DESTROY_OPS.tagged_value_range_destroy))
        };
        unsafe { destroy(begin, end) };
    }
}

/// Destroys the tagged values and releases their vector allocation.
///
/// # Safety
///
/// `vector` must be non-NULL and point to a valid `TaggedValueVector`; its
/// bounds must be accepted by the retail tagged-value range destructor.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn tagged_value_vector_destroy(vector: *mut TaggedValueVector) -> *mut TaggedValueVector {
    unsafe { tagged_value_vector_destroy_with(vector, cxx_array_dealloc) }
}

#[inline(always)]
unsafe fn tagged_value_vector_destroy_with(vector: *mut TaggedValueVector, dealloc: ArrayDealloc) -> *mut TaggedValueVector {
    let begin = unsafe { (*vector).begin };
    let end = unsafe { (*vector).end };
    unsafe { tagged_value_range_destroy(begin, end) };
    let capacity = unsafe { (*vector).capacity };
    let count = (capacity as usize).wrapping_sub(begin as usize) >> 4;
    unsafe { dealloc(begin, count, 0) };
    vector
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut RANGE: (*mut u8, *mut u8) = (core::ptr::null_mut(), core::ptr::null_mut());
    static mut DEALLOC: (*mut u8, usize, usize) = (core::ptr::null_mut(), 0, 0);

    unsafe extern "C" fn record_range(begin: *mut u8, end: *mut u8) {
        unsafe { RANGE = (begin, end) };
    }

    unsafe extern "C" fn record_dealloc(ptr: *mut u8, count: usize, element_size: usize) {
        unsafe { DEALLOC = (ptr, count, element_size) };
    }

    #[test]
    fn destroys_empty_range_and_deallocates_capacity_in_16_byte_elements() {
        let _lock = LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut storage = [0u32; 12];
        let begin = storage.as_mut_ptr().cast::<u8>();
        let mut vector = TaggedValueVector { begin, end: begin, capacity: unsafe { begin.add(48) } };
        unsafe {
            let previous = core::ptr::read_volatile(addr_of!(TAGGED_VALUE_VECTOR_DESTROY_OPS));
            core::ptr::write_volatile(addr_of_mut!(TAGGED_VALUE_VECTOR_DESTROY_OPS), TaggedValueVectorDestroyOps { tagged_value_range_destroy: record_range });
            RANGE = (core::ptr::null_mut(), core::ptr::null_mut());
            DEALLOC = (core::ptr::null_mut(), 0, 0);
            assert!(core::ptr::eq(tagged_value_vector_destroy_with(&mut vector, record_dealloc), &mut vector));
            assert_eq!(RANGE, (begin, begin));
            assert_eq!(DEALLOC, (begin, 3, 0));
            core::ptr::write_volatile(addr_of_mut!(TAGGED_VALUE_VECTOR_DESTROY_OPS), previous);
        }
    }

    #[test]
    fn destroys_populated_range_but_uses_capacity_not_end_for_deallocation_count() {
        let _lock = LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut storage = [0u32; 16];
        let begin = storage.as_mut_ptr().cast::<u8>();
        let mut vector = TaggedValueVector { begin, end: unsafe { begin.add(32) }, capacity: unsafe { begin.add(64) } };
        unsafe {
            let previous = core::ptr::read_volatile(addr_of!(TAGGED_VALUE_VECTOR_DESTROY_OPS));
            core::ptr::write_volatile(addr_of_mut!(TAGGED_VALUE_VECTOR_DESTROY_OPS), TaggedValueVectorDestroyOps { tagged_value_range_destroy: record_range });
            RANGE = (core::ptr::null_mut(), core::ptr::null_mut());
            DEALLOC = (core::ptr::null_mut(), 0, 0);
            tagged_value_vector_destroy_with(&mut vector, record_dealloc);
            assert_eq!(RANGE, (begin, begin.add(32)));
            assert_eq!(DEALLOC, (begin, 4, 0));
            core::ptr::write_volatile(addr_of_mut!(TAGGED_VALUE_VECTOR_DESTROY_OPS), previous);
        }
    }
}
