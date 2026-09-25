//! refcounted_ptr_range_assign — retailOS `FUN_083e9ba4` @ 0x083e9ba4.
//!
//! **56 bytes**, true extent `0x083e9ba4..0x083e9bdc`, bounded by the next
//! independently linked function at 0x083e9bdc. Raw A32 decoding finds two
//! inbound plain `bl` call sites and no predicated forms. It walks the
//! half-open range of four-byte refcounted-handle slots, assigning each source
//! slot into the corresponding output slot through
//! [`refcounted_ptr_copy_assign`](crate::cxx::handle::refcounted_ptr_copy_assign),
//! then returns the advanced output cursor.
//!
//! Deliberate deviation: none. The port calls the existing semantic callee;
//! LLVM may choose a different prologue or loop shape while preserving the
//! source-order assignment and four-byte cursor advances.

#[cfg(not(test))]
unsafe fn assign_refcounted_ptr(destination: *mut *mut crate::cxx::handle::RefcountedBody, source: *const *mut crate::cxx::handle::RefcountedBody) {
    crate::cxx::handle::refcounted_ptr_copy_assign(destination, source);
}

#[cfg(test)]
unsafe fn assign_refcounted_ptr(destination: *mut *mut crate::cxx::handle::RefcountedBody, source: *const *mut crate::cxx::handle::RefcountedBody) {
    unsafe { CALLS[CALL_COUNT] = (destination as usize, source as usize) };
    unsafe { CALL_COUNT += 1 };
}

/// Assigns every refcounted-handle slot in `first..last` into `output`.
///
/// # Safety
///
/// `first..last` must delimit readable, four-byte target-layout handle slots.
/// `output` must provide writable slots for the same number of entries; each
/// source and destination slot must meet `refcounted_ptr_copy_assign`'s safety
/// requirements.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn refcounted_ptr_range_assign(
    mut first: *const *mut crate::cxx::handle::RefcountedBody,
    last: *const *mut crate::cxx::handle::RefcountedBody,
    mut output: *mut *mut crate::cxx::handle::RefcountedBody,
) -> *mut *mut crate::cxx::handle::RefcountedBody {
    while first != last {
        assign_refcounted_ptr(output, first);
        first = unsafe { first.add(1) };
        output = unsafe { output.add(1) };
    }
    output
}

#[cfg(test)]
static TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
#[cfg(test)]
static mut CALLS: [(usize, usize); 8] = [(0, 0); 8];
#[cfg(test)]
static mut CALL_COUNT: usize = 0;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_range_returns_output_without_assignment() {
        let _guard = TEST_LOCK.lock();
        unsafe { CALL_COUNT = 0 };
        let slots = [core::ptr::null_mut(); 1];
        let output = slots.as_ptr() as *mut *mut crate::cxx::handle::RefcountedBody;
        let returned = unsafe { refcounted_ptr_range_assign(slots.as_ptr(), slots.as_ptr(), output) };
        assert_eq!(returned, output);
        assert_eq!(unsafe { CALL_COUNT }, 0);
    }

    #[test]
    fn assigns_each_slot_in_source_order_and_returns_end() {
        let _guard = TEST_LOCK.lock();
        unsafe { CALL_COUNT = 0 };
        let source = [core::ptr::null_mut(); 3];
        let mut output = [core::ptr::null_mut(); 3];
        let returned = unsafe {
            refcounted_ptr_range_assign(source.as_ptr(), source.as_ptr().add(3), output.as_mut_ptr())
        };
        assert_eq!(returned, unsafe { output.as_mut_ptr().add(3) });
        assert_eq!(unsafe { CALL_COUNT }, 3);
        for index in 0..3 {
            assert_eq!(unsafe { CALLS[index] }, (unsafe { output.as_mut_ptr().add(index) } as usize, unsafe { source.as_ptr().add(index) } as usize));
        }
    }
}
