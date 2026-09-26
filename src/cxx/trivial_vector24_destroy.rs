//! `trivial_vector24_destroy` — original: `FUN_083e1ecc` @ `0x083e1ecc`
//! (72 bytes; `0x083e1ecc..0x083e1f13`).
//!
//! Raw `osos.dec` words establish the true extent: `push {r2,r3,r4,r5,r6,r7,r8,lr}`
//! begins the next independent function at `0x083e1f14`. Raw A32 decoding finds
//! two plain unconditional body `bl` instructions—`__rt_sdiv` @ `0x08031568`
//! and `cxx_array_dealloc` @ `0x08266f2c`—and no predicated body `bl`.
//!
//! The three target-width words are a vector of trivial 24-byte elements.
//! retailOS walks `begin` to `end` in 24-byte steps, then releases `begin`
//! through `cxx_array_dealloc(begin, (capacity - begin) / 24, 0)` and returns
//! the vector address. The divide is signed and truncates toward zero.
//!
//! Deliberate deviation: the empty element destructor is represented by an
//! empty inline-assembly barrier, preserving the otherwise dead target walk
//! and its malformed-range behavior. Target pointers remain `u32` fields so
//! their offsets stay four bytes apart on 64-bit host test builds.

use crate::heap::veneers::cxx_array_dealloc;

/// ARM-layout representation of `std::vector<T>` for a trivial 24-byte `T`.
#[repr(C)]
pub struct TrivialVector24 {
    pub begin: u32,
    pub end: u32,
    pub capacity: u32,
}

/// Destroys and releases a vector of trivial 24-byte elements.
///
/// # Safety
///
/// `vector` must be non-NULL and contain target addresses that form the same
/// 24-byte-step range accepted by retailOS. A nonzero `begin` must belong to
/// the C++ heap.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.trivial_vector24_destroy")]
#[inline(never)]
pub unsafe extern "C" fn trivial_vector24_destroy(vector: *mut TrivialVector24) -> *mut TrivialVector24 {
    unsafe { trivial_vector24_destroy_with(vector, cxx_array_dealloc) }
}

#[inline(always)]
unsafe fn trivial_vector24_destroy_with(
    vector: *mut TrivialVector24,
    dealloc: unsafe extern "C" fn(*mut u8, usize, usize),
) -> *mut TrivialVector24 {
    let begin = unsafe { (*vector).begin };
    let end = unsafe { (*vector).end };
    let mut element = begin;

    while element != end {
        core::arch::asm!("/* {0} */", inout(reg) element, options(nostack, preserves_flags));
        element = element.wrapping_add(24);
    }

    let capacity = unsafe { (*vector).capacity };
    let count = core::hint::black_box((capacity.wrapping_sub(begin) as i32 / 24) as usize);
    unsafe { dealloc(begin as usize as *mut u8, count, 0) };
    vector
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut DEALLOC_CALL: Option<(u32, usize, usize)> = None;

    unsafe extern "C" fn recording_dealloc(ptr: *mut u8, count: usize, element_size: usize) {
        unsafe { DEALLOC_CALL = Some((ptr as usize as u32, count, element_size)) };
    }

    #[test]
    fn releases_empty_and_populated_target_width_vectors() {
        let _lock = LOCK.lock();
        let Some(storage) = try_map_u32_slab(hints::TRIVIAL_VECTOR24_DESTROY, 96) else {
            assert!(note_missing_u32_fixture(module_path!()));
            return;
        };
        let begin = storage as usize as u32;

        let mut empty = TrivialVector24 {
            begin,
            end: begin,
            capacity: begin.wrapping_add(72),
        };
        unsafe {
            DEALLOC_CALL = None;
            assert!(core::ptr::eq(
                trivial_vector24_destroy_with(&mut empty, recording_dealloc),
                &mut empty,
            ));
            assert_eq!(DEALLOC_CALL, Some((begin, 3, 0)));
        }

        let mut populated = TrivialVector24 {
            begin,
            end: begin.wrapping_add(48),
            capacity: begin.wrapping_add(96),
        };
        unsafe {
            DEALLOC_CALL = None;
            trivial_vector24_destroy_with(&mut populated, recording_dealloc);
            assert_eq!(DEALLOC_CALL, Some((begin, 4, 0)));
        }
    }
}
