//! `u32_vector_destroy` — original: `FUN_083e5554` @ `0x083e5554`.
//!
//! Raw ARM words establish the exact 64-byte extent `0x083e5554..0x083e5593`:
//! the following `push {r4,r5,r6,r7,lr}` begins the next independent function.
//! Whole-image A32 decoding finds two direct inbound plain `bl` sites
//! (0x082623c0 and 0x082628d4), no predicated inbound `bl` sites, and one
//! unconditional outbound `bl` to `cxx_array_dealloc` @ 0x08266f2c.
//!
//! The three-word object is a vector of trivial four-byte elements. retailOS
//! walks `begin` to `end` in four-byte steps with an empty element destructor,
//! then releases `begin` through `cxx_array_dealloc(begin, (capacity - begin)
//! >> 2, 0)` and returns the vector address. The empty walk still enforces the
//! target's malformed-range behavior.
//!
//! Deliberate deviation: empty inline assembly preserves the otherwise dead
//! trivial destruction walk. Direct Rust field access preserves target member
//! order without relying on host pointer byte offsets.

use crate::heap::veneers::cxx_array_dealloc;

/// ARM-layout representation of `std::vector<u32>`.
#[repr(C)]
pub struct U32Vector {
    pub begin: *mut u32,
    pub end: *mut u32,
    pub capacity: *mut u32,
}

/// Destroys a vector whose elements have trivial four-byte destructors.
///
/// # Safety
///
/// `vector` must be non-NULL and point to a valid `U32Vector`. Its `begin`,
/// `end`, and `capacity` addresses must form the same four-byte-step range the
/// retailOS loop accepts; a non-NULL `begin` must be owned by the C++ heap.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn u32_vector_destroy(vector: *mut U32Vector) -> *mut U32Vector {
    unsafe { u32_vector_destroy_with(vector, cxx_array_dealloc) }
}

#[inline(always)]
unsafe fn u32_vector_destroy_with(
    vector: *mut U32Vector,
    dealloc: unsafe extern "C" fn(*mut u8, usize, usize),
) -> *mut U32Vector {
    let begin = unsafe { (*vector).begin };
    let end = unsafe { (*vector).end };
    let mut element = begin as usize;
    let end_address = end as usize;

    while element != end_address {
        core::arch::asm!("/* {0} */", inout(reg) element, options(nostack, preserves_flags));
        element = element.wrapping_add(core::mem::size_of::<u32>());
    }

    let capacity = unsafe { (*vector).capacity };
    let count = core::hint::black_box((capacity as usize).wrapping_sub(begin as usize) >> 2);
    unsafe { dealloc(begin.cast(), count, 0) };
    vector
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut DEALLOC_CALL: Option<(*mut u8, usize, usize)> = None;

    unsafe extern "C" fn recording_dealloc(ptr: *mut u8, count: usize, element_size: usize) {
        unsafe { DEALLOC_CALL = Some((ptr, count, element_size)) };
    }

    #[test]
    fn destroys_empty_vector_and_returns_its_address() {
        let _lock = LOCK.lock();
        let mut storage = [0u32; 4];
        let mut vector = U32Vector {
            begin: storage.as_mut_ptr(),
            end: storage.as_mut_ptr(),
            capacity: unsafe { storage.as_mut_ptr().add(4) },
        };
        unsafe {
            DEALLOC_CALL = None;
            let returned = u32_vector_destroy_with(&mut vector, recording_dealloc);
            assert!(core::ptr::eq(returned, &mut vector));
            assert_eq!(DEALLOC_CALL, Some((storage.as_mut_ptr().cast(), 4, 0)));
        }
    }

    #[test]
    fn destroys_populated_vector_using_capacity_not_end() {
        let _lock = LOCK.lock();
        let mut storage = [0u32; 5];
        let mut vector = U32Vector {
            begin: storage.as_mut_ptr(),
            end: unsafe { storage.as_mut_ptr().add(3) },
            capacity: unsafe { storage.as_mut_ptr().add(5) },
        };
        unsafe {
            DEALLOC_CALL = None;
            u32_vector_destroy_with(&mut vector, recording_dealloc);
            assert_eq!(DEALLOC_CALL, Some((storage.as_mut_ptr().cast(), 5, 0)));
        }
    }
}
