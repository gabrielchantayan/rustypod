//! `element_array7_expand` — `FUN_083d4bf4` @ **0x083d4bf4**.
//! True code size: 120 bytes, ending at 0x083d4c6c; 60 bytes of inline
//! strings precede the next real function at 0x083d4ca8.
//! Raw A32 decoding: one inbound BLEQ, no inbound plain BL; three outbound
//! plain BLs (realloc 0x0802edec, IRAM zero veneer 0x08037db8, disabled
//! diagnostic 0x083d4b58), no outbound predicated BL.
//! Multiply capacity by growth with wrapping u32 arithmetic, publish realloc's
//! result even on failure, zero only the new tail, and commit capacity only
//! on success. The verified diagnostic returns its argument without effects.
//! Deliberate deviation: native pointer-width header/slot strides on hosts,
//! matching element_table; target retains four-byte strides and byte wrapping.

const WORD: usize = core::mem::size_of::<*mut u8>();

unsafe fn expand_with_realloc(
    array: *mut u8,
    reallocate: unsafe extern "C" fn(*mut u8, usize) -> *mut u8,
) {
    let capacity = array.add(WORD).cast::<u32>();
    let expanded = array.add(4 * WORD).cast::<u32>().read().wrapping_mul(capacity.read());
    let bytes = expanded.wrapping_mul(4) as usize * (WORD / 4);
    let storage = reallocate(array.cast::<*mut u8>().read(), bytes);
    array.cast::<*mut u8>().write(storage);
    if !storage.is_null() {
        let old = capacity.read();
        let zero = core::ptr::read_volatile(
            &(crate::libc::memzero::memzero_aligned as unsafe extern "C" fn(*mut u8, usize) -> *mut u8),
        );
        zero(
            (storage as usize).wrapping_add(old.wrapping_mul(4) as usize * (WORD / 4)) as *mut u8,
            expanded.wrapping_sub(old).wrapping_mul(4) as usize * (WORD / 4),
        );
        capacity.write(expanded);
    }
    let _ = crate::cxx::element_array7_tracker_diagnostic_no_op::element_array7_tracker_diagnostic_no_op(array.cast());
}

/// Expands a six-word element-array-7 header and its pointer-slot storage.
///
/// # Safety
/// Header fields must be valid and aligned; successful realloc storage must
/// accommodate the wrapped capacity and tail byte range.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn element_array7_expand(array: *mut u8) {
    let reallocate = core::ptr::read_volatile(
        &(crate::runtime::malloc_rt::realloc as unsafe extern "C" fn(*mut u8, usize) -> *mut u8),
    );
    expand_with_realloc(array, reallocate);
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;
    static LOCK: Mutex<()> = Mutex::new(());
    static mut RESULT: *mut u8 = core::ptr::null_mut();
    static mut REQUEST: usize = 0;
    unsafe extern "C" fn resize(_: *mut u8, bytes: usize) -> *mut u8 {
        REQUEST = bytes;
        RESULT
    }


    #[test]
    fn relocated_growth_preserves_prefix_and_clears_only_tail() {
        let _lock = LOCK.lock();
        unsafe {
            for (old, factor) in [(0u32, 3u32), (2, 1), (2, 3), (7, 2)] {
                let mut storage = [usize::MAX; 16];
                let mut header = [0x1234usize, old as usize, 1, 0x55, factor as usize, 0x66];
                RESULT = storage.as_mut_ptr().cast();
                expand_with_realloc(header.as_mut_ptr().cast(), resize);
                let count = old * factor;
                assert_eq!(header, [storage.as_mut_ptr() as usize, count as usize, 1, 0x55, factor as usize, 0x66]);
                for i in 0..16 {
                    assert_eq!(storage[i], if i >= old as usize && i < count as usize { 0 } else { usize::MAX });
                }
            }
        }
    }

    #[test]
    fn failure_publishes_null_without_committing_capacity_and_wraps_size() {
        let _lock = LOCK.lock();
        unsafe {
            for (old, factor, bytes) in [(2u32, 3u32, 24usize), (0x4000_0001, 4, 16), (u32::MAX, 2, 0xffff_fff8)] {
                let mut header = [0x1234usize, old as usize, 7, 8, factor as usize, 9];
                RESULT = core::ptr::null_mut();
                expand_with_realloc(header.as_mut_ptr().cast(), resize);
                assert_eq!(header, [0, old as usize, 7, 8, factor as usize, 9]);
                assert_eq!(REQUEST, bytes * (WORD / 4));
            }
        }
    }
}
