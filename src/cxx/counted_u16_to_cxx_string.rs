//! Rebuild a COW C++ string from a counted UTF-16 buffer.
//!
//! `counted_u16_to_cxx_string` — retailOS `FUN_082596f4` @ `0x082596f4`
//! (72 bytes, `0x082596f4..0x0825973c`). Raw ARM decoding finds **3 inbound
//! plain `bl` call sites** (`0x082a19e0`, `0x082a1a28`, `0x082a1a64`) and no
//! predicated calls. Its body has five unconditional calls: construct the
//! temporary StringObject from the counted UTF-16 units, normalize it through
//! the unported `FUN_08276db4` boundary, obtain its C string, assign that to
//! the output COW string, then release the temporary payload.
//!
//! The input begins with a u16 unit count followed immediately by that many
//! UTF-16 units. The count is passed unchanged, including zero.
//!
//! # Deliberate deviations
//!
//! The existing modeled StringObject vtable replaces the retail literal
//! `0x089a6044`. Direct Rust calls replace the four already-ported callee
//! boundaries; the unported normalizer remains the shared volatile seam.

use core::mem::MaybeUninit;
use core::ptr;

use super::path_escape_record::STRING_OBJECT_TEXT_NORMALIZE;
use super::string::{cxx_string_assign_cstr};
use super::string_object::{
    string_object_c_str, string_object_construct_from_utf16,
    string_object_release_payload, StringObject, STRING_OBJECT_VTABLE,
};

type ConstructFromUtf16 = unsafe extern "C" fn(*mut StringObject, *const u16, i32) -> *mut StringObject;
type Normalize = unsafe extern "C" fn(*mut StringObject);
type CStr = unsafe extern "C" fn(*const StringObject) -> *const u8;
type AssignCStr = unsafe extern "C" fn(*mut *mut u8, *const u8) -> *mut *mut u8;
type ReleasePayload = unsafe extern "C" fn(*mut StringObject);

#[inline(always)]
unsafe fn text_normalize_op() -> Normalize {
    unsafe { ptr::read_volatile(ptr::addr_of!(STRING_OBJECT_TEXT_NORMALIZE)) }
}

/// Converts `counted`'s UTF-16 units into the COW string at `output`.
///
/// # Safety
///
/// `counted` must point to its count word followed by that many readable
/// UTF-16 units. `output` must be a valid retail COW string object.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn counted_u16_to_cxx_string(counted: *const u16, output: *mut *mut u8) {
    unsafe {
        counted_u16_to_cxx_string_with(
            counted,
            output,
            string_object_construct_from_utf16,
            text_normalize_op(),
            string_object_c_str,
            cxx_string_assign_cstr,
            string_object_release_payload,
        );
    }
}

#[inline(always)]
unsafe fn counted_u16_to_cxx_string_with(
    counted: *const u16,
    output: *mut *mut u8,
    construct: ConstructFromUtf16,
    normalize: Normalize,
    c_str: CStr,
    assign: AssignCStr,
    release_payload: ReleasePayload,
) {
    let mut temporary = MaybeUninit::<StringObject>::uninit();
    let temporary = temporary.as_mut_ptr();
    unsafe {
        construct(temporary, counted.add(1), counted.read() as i32);
        normalize(temporary);
        assign(output, c_str(temporary));
        (*temporary).vtable = ptr::addr_of!(STRING_OBJECT_VTABLE);
        release_payload(temporary);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: [u8; 5] = [0; 5];
    static mut CALL_COUNT: usize = 0;
    static mut CONSTRUCT_ARGS: (*const u16, i32) = (ptr::null(), -1);
    static mut ASSIGN_ARGS: (*mut *mut u8, *const u8) = (ptr::null_mut(), ptr::null());
    static mut RELEASED: *mut StringObject = ptr::null_mut();
    static CSTR: [u8; 2] = [b'x', 0];

    unsafe fn record(call: u8) {
        unsafe {
            CALLS[CALL_COUNT] = call;
            CALL_COUNT += 1;
        }
    }

    unsafe extern "C" fn construct(temporary: *mut StringObject, source: *const u16, count: i32) -> *mut StringObject {
        unsafe {
            record(1);
            CONSTRUCT_ARGS = (source, count);
            (*temporary).vtable = ptr::null();
            (*temporary).payload = ptr::null_mut();
        }
        temporary
    }

    unsafe extern "C" fn normalize(_: *mut StringObject) { unsafe { record(2) } }
    unsafe extern "C" fn c_str(_: *const StringObject) -> *const u8 {
        unsafe { record(3) }
        CSTR.as_ptr()
    }
    unsafe extern "C" fn assign(output: *mut *mut u8, source: *const u8) -> *mut *mut u8 {
        unsafe {
            record(4);
            ASSIGN_ARGS = (output, source);
        }
        output
    }
    unsafe extern "C" fn release(temporary: *mut StringObject) {
        unsafe {
            record(5);
            RELEASED = temporary;
        }
    }

    #[test]
    fn passes_units_and_count_then_normalizes_assigns_and_releases() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let counted = [2u16, 0x0041, 0x03a9];
        let mut output = ptr::null_mut();
        unsafe {
            CALLS = [0; 5];
            CALL_COUNT = 0;
            CONSTRUCT_ARGS = (ptr::null(), -1);
            ASSIGN_ARGS = (ptr::null_mut(), ptr::null());
            RELEASED = ptr::null_mut();
            counted_u16_to_cxx_string_with(counted.as_ptr(), ptr::addr_of_mut!(output), construct, normalize, c_str, assign, release);
            assert_eq!(CALLS, [1, 2, 3, 4, 5]);
            assert_eq!(CONSTRUCT_ARGS, (counted.as_ptr().add(1), 2));
            assert_eq!(ASSIGN_ARGS, (ptr::addr_of_mut!(output), CSTR.as_ptr()));
            assert!(!RELEASED.is_null());
        }
    }

    #[test]
    fn zero_count_still_constructs_normalizes_assigns_and_releases() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let counted = [0u16];
        let mut output = ptr::null_mut();
        unsafe {
            CALLS = [0; 5];
            CALL_COUNT = 0;
            counted_u16_to_cxx_string_with(counted.as_ptr(), ptr::addr_of_mut!(output), construct, normalize, c_str, assign, release);
            assert_eq!(CALLS, [1, 2, 3, 4, 5]);
            assert_eq!(CONSTRUCT_ARGS, (counted.as_ptr().add(1), 0));
        }
    }
}
