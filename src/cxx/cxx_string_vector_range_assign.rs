//! cxx_string_vector_range_assign — retailOS `FUN_083e9c3c` @ 0x083e9c3c.
//!
//! **68 bytes**, true extent `0x083e9c3c..0x083e9c80`, bounded by the next
//! independently linked helper at 0x083e9c80. Whole-image A32 decoding finds
//! two inbound plain `bl` call sites and zero predicated forms. For every
//! 16-byte record in `[first, last)`, raw ARM assigns the COW string at +0x00,
//! assigns the COW-string vector at +0x04, and returns the advanced output
//! cursor. The vector assignment remains a deliberate fixed-firmware seam at
//! 0x083e5bb8 because it is not yet ported; the original makes that same call.

#[cfg(not(test))]
unsafe fn assign_string_word(destination: *mut u8, source: *const u8) {
    crate::cxx::string::cxx_string_assign(destination.cast(), source.cast());
}

#[cfg(test)]
unsafe fn assign_string_word(destination: *mut u8, source: *const u8) {
    test_assign_string_word(destination, source);
}

#[cfg(not(test))]
unsafe fn assign_string_vector(destination: *mut u8, source: *const u8) {
    type CxxStringVectorAssign = unsafe extern "C" fn(*mut u8, *const u8, u32, u32) -> *mut u8;
    let assign: CxxStringVectorAssign = unsafe { core::mem::transmute(0x083e_5bb8usize) };
    unsafe { assign(destination, source, 0, 0) };
}

#[cfg(test)]
unsafe fn assign_string_vector(destination: *mut u8, source: *const u8) {
    test_assign_string_vector(destination, source);
}

/// Assigns the COW string and embedded COW-string vector in every target-layout
/// record in `first..last` into `output`.
///
/// # Safety
///
/// `first..last` must delimit readable 16-byte target-layout records. `output`
/// must provide writable records for the same range; each string and vector
/// field must be valid for its respective assignment operation.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cxx_string_vector_range_assign(
    mut first: *const u8,
    last: *const u8,
    mut output: *mut u8,
) -> *mut u8 {
    while first != last {
        unsafe {
            assign_string_word(output, first);
            assign_string_vector(output.add(4), first.add(4));
        }
        first = unsafe { first.add(16) };
        output = unsafe { output.add(16) };
    }
    output
}

#[cfg(test)]
static TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
#[cfg(test)]
static mut STRING_CALLS: [(usize, usize); 8] = [(0, 0); 8];
#[cfg(test)]
static mut VECTOR_CALLS: [(usize, usize); 8] = [(0, 0); 8];
#[cfg(test)]
static mut CALL_COUNT: usize = 0;

#[cfg(test)]
unsafe fn test_assign_string_word(destination: *mut u8, source: *const u8) {
    unsafe { STRING_CALLS[CALL_COUNT] = (destination as usize, source as usize) };
}

#[cfg(test)]
unsafe fn test_assign_string_vector(destination: *mut u8, source: *const u8) {
    unsafe {
        VECTOR_CALLS[CALL_COUNT] = (destination as usize, source as usize);
        CALL_COUNT += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    #[test]
    fn cxx_string_vector_range_assigns_fields_in_record_order_and_returns_end() {
        let _guard = TEST_LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::CXX_STRING_VECTOR_RANGE_ASSIGN, 0x1000) else {
            assert!(note_missing_u32_fixture("cxx/cxx_string_vector_range_assign"));
            return;
        };
        unsafe {
            slab.write_bytes(0, 0x1000);
            let source = slab.add(0x100);
            let output = source.add(0x200);
            CALL_COUNT = 0;

            let returned = cxx_string_vector_range_assign(source, source.add(32), output);

            assert_eq!(returned, output.add(32));
            assert_eq!(CALL_COUNT, 2);
            assert_eq!(STRING_CALLS[0], (output as usize, source as usize));
            assert_eq!(VECTOR_CALLS[0], (output.add(4) as usize, source.add(4) as usize));
            assert_eq!(STRING_CALLS[1], (output.add(16) as usize, source.add(16) as usize));
            assert_eq!(VECTOR_CALLS[1], (output.add(20) as usize, source.add(20) as usize));
        }
    }

    #[test]
    fn cxx_string_vector_range_assign_empty_preserves_output_without_calls() {
        let _guard = TEST_LOCK.lock();
        unsafe {
            CALL_COUNT = 0;
            let output = 0x2000usize as *mut u8;
            assert_eq!(cxx_string_vector_range_assign(core::ptr::null(), core::ptr::null(), output), output);
            assert_eq!(CALL_COUNT, 0);
        }
    }
}
