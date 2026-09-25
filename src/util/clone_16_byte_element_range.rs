//! `clone_16_byte_element_range` — original: `FUN_083e9dc8` @ **0x083e9dc8**
//! (**56 bytes**, `0x083e9dc8..0x083e9e00`; the next separately linked
//! function starts with `push {r4,r5,r6,lr}` at `0x083e9e00`).
//!
//! Raw whole-image A32 decoding finds **2 inbound plain `bl` call sites**
//! (`0x083e43c8`, `0x083e4410`) and **0 predicated `bl` forms**. The body has
//! one unconditional direct `bl`, to the unnamed 16-byte element clone at
//! `0x0827c1ec`.
//!
//! Algorithm: advance source and destination in 16-byte units over
//! `[source, end)`, cloning each opaque element through the verified retail
//! callee, then return the advanced destination. Deliberate deviations: the
//! unported callee remains an address seam on target; host tests inject it.

const RETAIL_CLONE_16_BYTE_ELEMENT: usize = 0x0827_c1ec;
type Clone16ByteElement = unsafe extern "C" fn(*mut u8, *const u8);

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn retail_clone_16_byte_element(destination: *mut u8, source: *const u8) {
    let clone: Clone16ByteElement = unsafe { core::mem::transmute(RETAIL_CLONE_16_BYTE_ELEMENT) };
    unsafe { clone(destination, source); }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_clone_16_byte_element(_: *mut u8, _: *const u8) {
    panic!("clone_16_byte_element_range requires a 0x0827c1ec host fixture")
}

#[cfg(not(target_os = "none"))]
pub static mut CLONE_16_BYTE_ELEMENT: Clone16ByteElement = missing_clone_16_byte_element;

/// Clones opaque 16-byte elements from `[source, end)` into `destination`.
///
/// # Safety
///
/// `source` and `end` must delimit 16-byte elements, and `destination` must
/// provide space for their cloned representations.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn clone_16_byte_element_range(
    mut source: *const u8,
    end: *const u8,
    mut destination: *mut u8,
) -> *mut u8 {
    while source != end {
        #[cfg(target_os = "none")]
        unsafe { retail_clone_16_byte_element(destination, source); }
        #[cfg(not(target_os = "none"))]
        unsafe { CLONE_16_BYTE_ELEMENT(destination, source); }
        source = unsafe { source.add(16) };
        destination = unsafe { destination.add(16) };
    }
    destination
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr;
    use std::sync::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: usize = 0;

    unsafe extern "C" fn clone_fixture(destination: *mut u8, source: *const u8) {
        unsafe {
            CALLS += 1;
            ptr::copy_nonoverlapping(source, destination, 16);
        }
    }

    #[test]
    fn clones_each_complete_element_and_returns_advanced_destination() {
        let _lock = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let source = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
            0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
            0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        ];
        let mut destination = [0xff; 64];
        unsafe {
            CALLS = 0;
            CLONE_16_BYTE_ELEMENT = clone_fixture;
            let result = clone_16_byte_element_range(source.as_ptr(), source.as_ptr().add(48), destination.as_mut_ptr());
            assert_eq!(result, destination.as_mut_ptr().add(48));
            assert_eq!(CALLS, 3);
        }
        assert_eq!(&destination[..48], &source);
        assert_eq!(&destination[48..], &[0xff; 16]);
    }

    #[test]
    fn empty_range_does_not_invoke_clone() {
        let _lock = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let source = [0x5a; 16];
        let mut destination = [0xa5; 16];
        unsafe {
            CALLS = 0;
            CLONE_16_BYTE_ELEMENT = clone_fixture;
            let result = clone_16_byte_element_range(source.as_ptr(), source.as_ptr(), destination.as_mut_ptr());
            assert_eq!(result, destination.as_mut_ptr());
            assert_eq!(CALLS, 0);
        }
        assert_eq!(destination, [0xa5; 16]);
    }
}
