//! In-place fixed-increment u32 array constructor: `FUN_083d584c` at
//! **0x083d584c**, **96 bytes** (92 instruction bytes and the vtable literal
//! at 0x083d58a8). The next real function starts at 0x083d58ac. Whole-image
//! A32 decoding finds one incoming plain BL at 0x0827bf80 and zero predicated
//! incoming BLs. Body: two plain BLs (header constructor, malloc), one BLEQ
//! to the nonreturning panic entry at 0x080eba5c.
//!
//! Initialize the caller's six-word array, default zero capacity to 16,
//! allocate capacity * 4 bytes with u32 wrapping arithmetic, store the result,
//! panic on NULL, and commit capacity. Only the low byte at +0x10 is cleared;
//! the three padding bytes and the uninitialized element storage are untouched.
//! Return the original object, not a newly allocated object.
//!
//! Deliberate deviations: use the existing target-width array layout and call
//! the ported panic directly rather than its one-instruction entry. A volatile
//! malloc function pointer preserves the allocation boundary; tests replace
//! only that boundary. The opaque base-header store remains a real call.

use super::fixed_increment_u32_array_append::FixedIncrementU32Array;
use super::opaque_header_literal_construct::opaque_header_literal_construct;
use crate::heap::veneers::heap_panic;

#[cfg(not(test))]
static MALLOC_FUNCTION: unsafe extern "C" fn(usize) -> *mut u8 = crate::runtime::malloc_rt::malloc;
#[cfg(test)]
static mut MALLOC_FUNCTION: unsafe extern "C" fn(usize) -> *mut u8 = crate::runtime::malloc_rt::malloc;

/// # Safety
/// `array` must address 24 writable, four-byte-aligned bytes. The allocator
/// must return a target-width pointer or NULL; existing storage is not freed.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn fixed_increment_u32_array_construct(
    array: *mut FixedIncrementU32Array,
    capacity: u32,
) -> *mut FixedIncrementU32Array {
    unsafe {
        opaque_header_literal_construct(array.cast());
        (*array).increment = 16;
        (*array).len = 0;
        (*array).allocated = capacity;
        core::ptr::addr_of_mut!((*array).unknown_10).cast::<u8>().write(0);
        (*array).values = 0;
        (*array).unknown_00 = 0x089a_6690;
        let capacity = if capacity == 0 { (*array).increment } else { capacity };
        let allocate = core::ptr::read_volatile(core::ptr::addr_of!(MALLOC_FUNCTION));
        let values = allocate(capacity.wrapping_shl(2) as usize);
        (*array).values = values as usize as u32;
        if values.is_null() { heap_panic(); }
        (*array).allocated = capacity;
        array
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    extern crate std;
    static mut REQUESTED_BYTES: usize = 0;

    unsafe extern "C" fn allocate(bytes: usize) -> *mut u8 {
        unsafe { REQUESTED_BYTES = bytes; }
        // This function stores the allocation pointer but never dereferences it.
        0x1234_5000usize as *mut u8
    }

    #[test]
    fn defaults_and_wrapping_capacities_preserve_padding_and_object_bounds() {
        let _guard = LOCK.lock();
        unsafe {
            let saved = core::ptr::addr_of!(MALLOC_FUNCTION).read();
            core::ptr::addr_of_mut!(MALLOC_FUNCTION).write(allocate);
            for capacity in [0, 1, 15, 16, 17, 0x4000_0000, 0x8000_0001, u32::MAX] {
                let mut words = [0xa5a5_a5a5u32; 8];
                let array = words.as_mut_ptr().add(1).cast();
                assert_eq!(fixed_increment_u32_array_construct(array, capacity), array);
                let effective = if capacity == 0 { 16 } else { capacity };
                assert_eq!(core::ptr::addr_of!(REQUESTED_BYTES).read(), effective.wrapping_shl(2) as usize);
                assert_eq!(words, [0xa5a5_a5a5, 0x089a_6690, effective, 16, 0,
                    0xa5a5_a500, 0x1234_5000, 0xa5a5_a5a5]);
            }
            core::ptr::addr_of_mut!(MALLOC_FUNCTION).write(saved);
        }
    }

    unsafe extern "C" fn fail_allocation(bytes: usize) -> *mut u8 {
        assert_eq!(bytes, 64);
        core::ptr::null_mut()
    }

    unsafe extern "C" fn null_allocation() -> ! {
        unsafe {
            core::ptr::addr_of_mut!(MALLOC_FUNCTION).write(fail_allocation);
            let mut words = [0xa5a5_a5a5u32; 6];
            fixed_increment_u32_array_construct(words.as_mut_ptr().cast(), 0);
        }
        std::process::exit(91)
    }

    #[test]
    fn allocation_failure_is_fatal() {
        crate::heap::veneers::tests::assert_heap_panic_entry_fatal_path(
            "RUSTYPOD_FIXED_INCREMENT_CONSTRUCT_NULL",
            "cxx::fixed_increment_u32_array_construct::tests::allocation_failure_is_fatal",
            null_allocation,
        );
    }
}
