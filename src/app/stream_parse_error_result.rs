//! `stream_parse_error_result` — original: `FUN_081d1704` @ `0x081d1704`
//! (124 bytes; 31 ARM instructions).
//!
//! # Verified calls and algorithm
//!
//! Raw `osos.dec` words from `0x081d1704` through the next entry at
//! `0x081d1780` establish seven outbound plain `bl` calls and no predicated
//! `bl`: stream classification (`0x080aa848`), `operator_new` (`0x082aadd4`)
//! twice, the object constructors (`0x0815faec`, `0x081b9f30`),
//! and the result owner assignment (`0x083e74f0`). Three inbound plain `bl`
//! sites call this entry; there are no predicated inbound `bl` sites.
//!
//! The classifier result is stored through `status_out`. Status 4 allocates
//! 20 bytes and constructs the first error object with mode 0; status 5 does
//! the same with mode 1. Every other status allocates 16 bytes and constructs
//! the alternate error object. The resulting owned pointer is assigned to a
//! fresh local owner and returned.
//!
//! # Deliberate deviations
//!
//! The classifier, first constructor, and owner assignment use verified
//! retailOS addresses on target and narrow host seams. The alternate
//! constructor uses its Rust port. The port returns after assignment rather
//! than reproducing the stack-local owner object.

use crate::heap::veneers::operator_new;
use crate::cxx::alternate_error_object_construct::alternate_error_object_construct;

pub type StreamStatusClassify = unsafe extern "C" fn(*mut u8) -> u32;
pub type ErrorObjectConstruct = unsafe extern "C" fn(*mut u8, *mut u8, u32) -> *mut u8;
pub type ErrorObjectAssign = unsafe extern "C" fn(*mut *mut u8, *mut u8);
pub type ErrorObjectAllocate = unsafe extern "C" fn(usize) -> *mut u8;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_classify(_: *mut u8) -> u32 { 0 }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_construct(object: *mut u8, _: *mut u8, _: u32) -> *mut u8 { object }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_assign(slot: *mut *mut u8, object: *mut u8) { slot.write(object) }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_operator_new(size: usize) -> *mut u8 { operator_new(size) }

/// Host seams for the verified retailOS calls.
#[cfg(not(target_os = "none"))]
pub static mut STREAM_STATUS_CLASSIFY: StreamStatusClassify = missing_classify;
#[cfg(not(target_os = "none"))]
pub static mut ERROR_OBJECT_CONSTRUCT: ErrorObjectConstruct = missing_construct;
#[cfg(not(target_os = "none"))]
pub static mut ERROR_OBJECT_ASSIGN: ErrorObjectAssign = missing_assign;
#[cfg(not(target_os = "none"))]
pub static mut ERROR_OBJECT_ALLOCATE: ErrorObjectAllocate = host_operator_new;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn stream_status_classify() -> StreamStatusClassify { core::mem::transmute(0x080a_a848usize) }
#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn error_object_construct() -> ErrorObjectConstruct { core::mem::transmute(0x0815_faecusize) }
#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn error_object_assign() -> ErrorObjectAssign { core::mem::transmute(0x083e_74f0usize) }

/// Classifies a stream parse condition, constructs its owned error object, and
/// returns that object after storing the status through `status_out`.
///
/// # Safety
/// `status_out` must be writable. `stream` and every object returned by the
/// allocator must satisfy the selected retailOS callback's requirements.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn stream_parse_error_result(stream: *mut u8, status_out: *mut u32) -> *mut u8 {
    #[cfg(target_os = "none")]
    let status = unsafe { stream_status_classify()(stream) };
    #[cfg(not(target_os = "none"))]
    let status = unsafe { STREAM_STATUS_CLASSIFY(stream) };
    unsafe { status_out.write(status) };

    let object = if status == 4 || status == 5 {
        #[cfg(target_os = "none")]
        let object = unsafe { operator_new(20) };
        #[cfg(not(target_os = "none"))]
        let object = unsafe { ERROR_OBJECT_ALLOCATE(20) };
        #[cfg(target_os = "none")]
        { unsafe { error_object_construct()(object, stream, status - 4) } }
        #[cfg(not(target_os = "none"))]
        { unsafe { ERROR_OBJECT_CONSTRUCT(object, stream, status - 4) } }
    } else {
        #[cfg(target_os = "none")]
        let object = unsafe { operator_new(16) };
        #[cfg(not(target_os = "none"))]
        let object = unsafe { ERROR_OBJECT_ALLOCATE(16) };
        unsafe { alternate_error_object_construct(object, stream as usize as u32) }
    };

    let mut result = core::ptr::null_mut();
    #[cfg(target_os = "none")]
    unsafe { error_object_assign()(&mut result, object) };
    #[cfg(not(target_os = "none"))]
    unsafe { ERROR_OBJECT_ASSIGN(&mut result, object) };
    result
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;
    static TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    static mut STATUS: u32 = 0;
    static mut ALLOCATION_SIZE: usize = 0;
    static mut CONSTRUCT_ARGS: (*mut u8, *mut u8, u32) = (core::ptr::null_mut(), core::ptr::null_mut(), 0);
    static mut ASSIGNED: *mut u8 = core::ptr::null_mut();
    static mut OBJECT: [u32; 5] = [0; 5];
    unsafe extern "C" fn assign(slot: *mut *mut u8, object: *mut u8) {
        unsafe {
            slot.write(object);
            ASSIGNED = object;
        }
    }

    unsafe extern "C" fn classify(_: *mut u8) -> u32 { unsafe { STATUS } }
    unsafe extern "C" fn allocate(size: usize) -> *mut u8 { unsafe { ALLOCATION_SIZE = size; OBJECT.as_mut_ptr().cast() } }
    unsafe extern "C" fn construct(object: *mut u8, stream: *mut u8, mode: u32) -> *mut u8 {
        unsafe { CONSTRUCT_ARGS = (object, stream, mode) };
        object
    }

    #[test]
    fn status_four_and_five_select_twenty_byte_constructor_modes() {
        let _guard = TEST_LOCK.lock();
        unsafe {
            STREAM_STATUS_CLASSIFY = classify;
            ERROR_OBJECT_ALLOCATE = allocate;
            ERROR_OBJECT_CONSTRUCT = construct;
            ERROR_OBJECT_ASSIGN = assign;
            for (status, mode) in [(4, 0), (5, 1)] {
                STATUS = status;
                ALLOCATION_SIZE = 0;
                CONSTRUCT_ARGS = (core::ptr::null_mut(), core::ptr::null_mut(), 9);
                let mut out = 0;
                let stream = 0x1234usize as *mut u8;
                assert_eq!(stream_parse_error_result(stream, &mut out), OBJECT.as_mut_ptr().cast());
                assert_eq!(out, status);
                assert_eq!(ALLOCATION_SIZE, 20);
                assert_eq!(CONSTRUCT_ARGS, (OBJECT.as_mut_ptr().cast(), stream, mode));
                assert_eq!(ASSIGNED, OBJECT.as_mut_ptr().cast());
            }
        }
    }

    #[test]
    fn other_status_selects_sixteen_byte_alternate_constructor() {
        let _guard = TEST_LOCK.lock();
        unsafe {
            STREAM_STATUS_CLASSIFY = classify;
            ERROR_OBJECT_ALLOCATE = allocate;
            ERROR_OBJECT_ASSIGN = assign;
            STATUS = 10;
            ALLOCATION_SIZE = 0;
            let mut out = 0;
            let stream = 0x5678usize as *mut u8;
            assert_eq!(stream_parse_error_result(stream, &mut out), OBJECT.as_mut_ptr().cast());
            assert_eq!(out, 10);
            assert_eq!(ALLOCATION_SIZE, 16);
            assert_eq!(OBJECT, [crate::cxx::alternate_error_object_construct::ALTERNATE_ERROR_OBJECT_VTABLE,
                0, 0, 0x5678, 0]);
            assert_eq!(ASSIGNED, OBJECT.as_mut_ptr().cast());
        }
    }
}
