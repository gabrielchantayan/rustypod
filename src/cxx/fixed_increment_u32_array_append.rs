//! `fixed_increment_u32_array_append` — original: `FUN_083d5784` @
//! **0x083d5784**. The true body is **144 bytes**
//! (`0x083d5784..0x083d5813`); `push {r4, lr}` at `0x083d5814` begins the
//! next function. Raw A32 decoding finds one plain body `bl`, at `0x083d57c8`
//! to the ported ADS `realloc` @ `0x0802edec`, and no predicated body `bl`.
//!
//! Appends the input word to a fixed-increment target-width word array. When
//! `len >= allocated`, doubles `increment` below 0x1000, reallocates to
//! `(allocated + increment) * 4` bytes, and commits the new storage and
//! allocation count only on success. The increment update deliberately occurs
//! before the allocation attempt, exactly as ARM does; allocation failure
//! returns zero without writing the word.
//!
//! Deliberate deviation: Rust uses `u32` target pointers and word indexing, so
//! host pointer width cannot alter the firmware layout. The target path reaches
//! the already ported `realloc` through a volatile function pointer so LLVM
//! retains the allocator boundary.

use crate::runtime::malloc_rt::realloc;

const MAX_INCREMENT: u32 = 0x1000;

#[cfg(not(test))]
static REALLOC_FUNCTION: unsafe extern "C" fn(*mut u8, usize) -> *mut u8 = realloc;

/// Target layout of the six-word fixed-increment array. The first and fifth
/// words are not read by this operation.
#[repr(C)]
pub struct FixedIncrementU32Array {
    pub unknown_00: u32,
    pub allocated: u32,
    pub increment: u32,
    pub len: u32,
    pub unknown_10: u32,
    pub values: u32,
}

#[cfg(test)]
static mut REALLOC_RESULT: *mut u8 = core::ptr::null_mut();
#[cfg(test)]
static mut REALLOC_ARGS: (*mut u8, usize) = (core::ptr::null_mut(), 0);

#[cfg(test)]
unsafe fn resize(values: *mut u8, bytes: usize) -> *mut u8 {
    unsafe { REALLOC_ARGS = (values, bytes); REALLOC_RESULT }
}

#[cfg(not(test))]
unsafe fn resize(values: *mut u8, bytes: usize) -> *mut u8 {
    let resize = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(REALLOC_FUNCTION)) };
    unsafe { resize(values, bytes) }
}

/// Appends `*value` and returns one, or returns zero when growth allocation
/// fails.
///
/// # Safety
///
/// `array` and `value` must be valid. If the array has spare capacity, its
/// target-width `values` pointer must address at least `len + 1` words; if it
/// is full, `realloc` must implement the stock preserving reallocation
/// contract for the requested byte span.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn fixed_increment_u32_array_append(
    array: *mut FixedIncrementU32Array,
    value: *const u32,
) -> u32 {
    unsafe {
        if (*array).allocated <= (*array).len {
            if (*array).increment < MAX_INCREMENT {
                (*array).increment = (*array).increment.wrapping_shl(1);
            }
            let bytes = (*array).allocated.wrapping_add((*array).increment).wrapping_shl(2) as usize;
            let grown = resize((*array).values as usize as *mut u8, bytes);
            if grown.is_null() {
                return 0;
            }
            (*array).values = grown as usize as u32;
            (*array).allocated = (*array).allocated.wrapping_add((*array).increment);
        }
        let index = (*array).len;
        (*array).len = index.wrapping_add(1);
        *((*array).values as usize as *mut u32).add(index as usize) = *value;
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());

    unsafe fn array_at(slab: *mut u8) -> *mut FixedIncrementU32Array {
        slab.cast()
    }

    #[test]
    fn appends_without_growing_when_capacity_remains() {
        let _guard = LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::FIXED_INCREMENT_U32_ARRAY_APPEND, 0x1000) else {
            assert!(note_missing_u32_fixture("fixed_increment_u32_array_append"));
            return;
        };
        unsafe {
            let values = slab.add(0x100).cast::<u32>();
            values.write(0x1111_1111);
            let array = array_at(slab);
            array.write(FixedIncrementU32Array { unknown_00: 0, allocated: 2, increment: 2, len: 1, unknown_10: 0, values: values as usize as u32 });
            REALLOC_ARGS = (core::ptr::null_mut(), 0);
            assert_eq!(fixed_increment_u32_array_append(array, &0x2222_2222), 1);
            assert_eq!((*array).len, 2);
            assert_eq!(values.add(1).read(), 0x2222_2222);
            assert_eq!(REALLOC_ARGS.1, 0);
        }
    }

    #[test]
    fn grows_by_doubled_increment_and_commits_after_success() {
        let _guard = LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::FIXED_INCREMENT_U32_ARRAY_APPEND_GROW, 0x1000) else {
            assert!(note_missing_u32_fixture("fixed_increment_u32_array_append"));
            return;
        };
        unsafe {
            let array = array_at(slab);
            let grown = slab.add(0x200).cast::<u32>();
            array.write(FixedIncrementU32Array { unknown_00: 0, allocated: 3, increment: 3, len: 3, unknown_10: 0, values: slab.add(0x100) as usize as u32 });
            REALLOC_RESULT = grown.cast();
            assert_eq!(fixed_increment_u32_array_append(array, &7), 1);
            assert_eq!(REALLOC_ARGS, (slab.add(0x100), 36));
            assert_eq!(((*array).increment, (*array).allocated, (*array).len), (6, 9, 4));
            assert_eq!(grown.add(3).read(), 7);
        }
    }

    #[test]
    fn failed_growth_keeps_storage_count_and_length_but_not_increment() {
        let _guard = LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::FIXED_INCREMENT_U32_ARRAY_APPEND_FAILURE, 0x1000) else {
            assert!(note_missing_u32_fixture("fixed_increment_u32_array_append"));
            return;
        };
        unsafe {
            let array = array_at(slab);
            array.write(FixedIncrementU32Array { unknown_00: 0, allocated: 1, increment: MAX_INCREMENT, len: 1, unknown_10: 0, values: slab.add(0x100) as usize as u32 });
            REALLOC_RESULT = core::ptr::null_mut();
            assert_eq!(fixed_increment_u32_array_append(array, &9), 0);
            assert_eq!(((*array).increment, (*array).allocated, (*array).len), (MAX_INCREMENT, 1, 1));
            assert_eq!(REALLOC_ARGS, (slab.add(0x100), 0x4004));
        }
    }
}
