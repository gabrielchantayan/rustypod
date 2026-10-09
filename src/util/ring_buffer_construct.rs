//! Owned ring-buffer constructor — retailOS `FUN_080fe9ec`.
//!
//! Load address 0x080fe9ec; true extent 88 bytes: 84 bytes of A32 code
//! followed by `nil\0` at 0x080fea40. The next real function starts at
//! 0x080fea44 (`str r2,[r0,#4]`). Raw branch-word decoding finds two inbound
//! plain BLs (0x08103b3c, 0x08103b48), zero predicated inbound BLs; outbound
//! calls are one BL to malloc_wrapper and one BLEQ to the failure reporter.
//! Allocates capacity bytes with tag 23, publishes the payload, reports NULL
//! with code 4 and nil, then sets ownership, capacity, capacity-minus-one
//! mask, and zero read/write cursors. Returns the original record. Capacity
//! is not validated, including zero and non-powers of two.
//!
//! Deviations: calls the ported allocator and existing allocation-failure
//! ops seam (whose reporter default remains unported/inert), as heap_string
//! does. Uses target word indices, not host-width pointers; no payload access.

/// # Safety
/// `ring` must be aligned and writable for six target words. Allocation and
/// diagnostic seams must be installed; a returning reporter may mutate the
/// record, but it must remain writable. Bytes 1..3 are preserved.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ring_buffer_construct(ring: *mut u32, capacity: u32) -> *mut u32 {
    let payload = crate::heap::veneers::malloc_wrapper(capacity as usize, 23);
    ring.add(1).write_volatile(payload as usize as u32);
    if payload.is_null() {
        let ops = core::ptr::read_volatile(core::ptr::addr_of!(
            crate::heap::new_handler::ALLOCATION_CONSTRUCT_GUARD_OPS
        ));
        (ops.report_allocation_failure)(4, b"nil\0".as_ptr());
    }
    (ring as *mut u8).write_volatile(1);
    ring.add(2).write_volatile(capacity);
    ring.add(5).write_volatile(capacity.wrapping_sub(1));
    ring.add(3).write_volatile(0);
    ring.add(4).write_volatile(0);
    ring
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heap::veneers::tests::{mock_heap, set_alloc_ret};
    static mut FAILED_RING: *mut u32 = core::ptr::null_mut();
    static mut REPORTS: usize = 0;

    unsafe extern "C" fn repair_payload(code: usize, descriptor: *const u8) {
        assert_eq!(code, 4);
        assert_eq!(core::slice::from_raw_parts(descriptor, 4), b"nil\0");
        assert_eq!((*FAILED_RING.add(0)), 0xa5a5_a5a5);
        assert_eq!((*FAILED_RING.add(1)), 0);
        assert_eq!((*FAILED_RING.add(2)), 0xa5a5_a5a5);
        FAILED_RING.add(1).write(0x1234_0000);
        FAILED_RING.add(3).write(99);
        REPORTS += 1;
    }

    #[test]
    fn initializes_target_words_without_touching_padding_or_neighbors() {
        let _heap = mock_heap();
        set_alloc_ret(0x1234_0000usize as *mut u8);
        for capacity in [0, 1, 3, 256, 0x8000_0000, u32::MAX] {
            let mut words = [0xa5a5_a5a5; 8];
            let ring = unsafe { words.as_mut_ptr().add(1) };
            assert_eq!(unsafe { ring_buffer_construct(ring, capacity) }, ring);
            assert_eq!(words, [0xa5a5_a5a5, 0xa5a5_a501, 0x1234_0000,
                capacity, 0, 0, capacity.wrapping_sub(1), 0xa5a5_a5a5]);
        }
    }

    #[test]
    fn failure_is_published_before_report_and_returning_reporter_is_not_retried() {
        let _diagnostic = crate::heap::new_handler::tests::LOCK.lock().unwrap();
        let _heap = mock_heap();
        set_alloc_ret(core::ptr::null_mut());
        unsafe {
            let saved = crate::heap::new_handler::ALLOCATION_CONSTRUCT_GUARD_OPS;
            crate::heap::new_handler::ALLOCATION_CONSTRUCT_GUARD_OPS.report_allocation_failure = repair_payload;
            let mut words = [0xa5a5_a5a5; 6];
            FAILED_RING = words.as_mut_ptr();
            REPORTS = 0;
            assert_eq!(ring_buffer_construct(FAILED_RING, 0), FAILED_RING);
            assert_eq!(words, [0xa5a5_a501, 0x1234_0000, 0, 0, 0, u32::MAX]);
            assert_eq!(REPORTS, 1);
            crate::heap::new_handler::ALLOCATION_CONSTRUCT_GUARD_OPS = saved;
            FAILED_RING = core::ptr::null_mut();
        }
    }
}
