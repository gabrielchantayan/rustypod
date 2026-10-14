//! `element_array8_expand` — `FUN_083d44b4` @ **0x083d44b4**.
//! True code size: 120 bytes (`0x083d44b4..0x083d452c`); 60 bytes of
//! diagnostic strings precede the next real function at 0x083d4568.
//! Raw A32 decoding: zero inbound plain BLs, one inbound BLEQ at 0x083d4464;
//! three outbound plain BLs (realloc 0x0802edec, IRAM zero-fill veneer
//! 0x08037db8, diagnostic 0x083d4418), zero outbound predicated BLs.
//! Multiply capacity by growth modulo 2^32, publish realloc's result even
//! on failure, clear the added slots on success, then commit capacity.
//! Deviations: native pointer-width header/slot strides on hosts, matching
//! element_table; omit unused diagnostic arguments to the verified bx lr.

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
    let _ = crate::app::tracker_array_diagnostic_noop::tracker_array_diagnostic_noop(array.cast());
}

/// Expands a six-word array-8 header and its pointer-slot storage.
///
/// # Safety
/// Header fields must be valid and aligned; successful realloc storage must
/// accommodate the wrapped capacity and tail byte range.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn element_array8_expand(array: *mut u8) {
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
    unsafe extern "C" fn resize(_: *mut u8, _: usize) -> *mut u8 { RESULT }
    unsafe extern "C" fn fail(_: *mut u8, bytes: usize) -> *mut u8 {
        assert_eq!(bytes, 16 * (WORD / 4));
        core::ptr::null_mut()
    }

    #[test]
    fn relocated_growth_preserves_prefix_header_and_tail_bounds() {
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
    fn allocation_failure_publishes_null_preserves_header_and_wraps_byte_count() {
        let mut header = [0x1234usize, 0x4000_0001, 7, 8, 4, 9];
        unsafe { expand_with_realloc(header.as_mut_ptr().cast(), fail); }
        assert_eq!(header, [0, 0x4000_0001, 7, 8, 4, 9]);
    }

    #[test]
    fn grown_slots_are_available_to_array8_insertion() {
        let _lock = LOCK.lock();
        unsafe {
            let mut storage = [0x1111usize, 0x2222, usize::MAX, usize::MAX, 0xaaaa];
            let mut header = [0x1234usize, 2, 2, 0, 2, 0];
            RESULT = storage.as_mut_ptr().cast();
            expand_with_realloc(header.as_mut_ptr().cast(), resize);
            assert_eq!(crate::app::element_table::element_array8_insert_unique(header.as_mut_ptr().cast(), 0x3333 as *mut u8), 2);
            assert_eq!(storage, [0x1111, 0x2222, 0x3333, 0, 0xaaaa]);
            assert_eq!(header[2], 3);
            assert_eq!(crate::app::element_table::element_array8_insert_unique(header.as_mut_ptr().cast(), core::ptr::null_mut()), -1);
            assert_eq!(header[2], 3);
        }
    }
}
