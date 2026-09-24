//! `validated_file_tell` — retailOS `FUN_0805b73c` @ **0x0805b73c**.
//!
//! Raw `osos.dec` establishes the true **40-byte** A32 extent
//! `0x0805b73c..0x0805b763`: `pop {r4-r6,pc}` ends it and
//! `0x0805b764` starts the next independently entered function. Ghidra's
//! 104-byte extent incorrectly absorbs that sibling. A whole-image A32 decode
//! finds three inbound plain `bl` calls (0x08042e20, 0x08042ea4, and
//! 0x08043244) and no predicated inbound calls. The body issues one plain `bl`
//! to the opaque validator at 0x08087974, no predicated `bl` calls, then tail
//! branches to the still-retail cursor-query wrapper at 0x0805a5f4.
//!
//! It validates the outer handle, then forwards the word at +0x04 and the
//! caller's 64-bit output pair to the cursor-query wrapper. Deliberate
//! deviation: Rust performs an ordinary call-and-return instead of the ARM
//! tail branch; device builds retain both verified fixed-address boundaries
//! and host tests install narrow recording seams.

use core::ptr::{addr_of, read_volatile};

/// Firmware load address of the opaque outer-handle validator.
pub const HANDLE_VALIDATE_ADDRESS: usize = 0x0808_7974;
/// Firmware load address of the still-retail cursor-query wrapper.
pub const CURSOR_QUERY_ADDRESS: usize = 0x0805_a5f4;

/// Verified ABI only; its broader semantic identity remains unrecovered.
pub type HandleValidate = unsafe extern "C" fn(*const u8) -> i32;
/// Verified ABI of the still-retail cursor-query wrapper.
pub type CursorQuery = unsafe extern "C" fn(u32, *mut u32) -> i32;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_handle_validate(handle: *const u8) -> i32 {
    let validate: HandleValidate = unsafe { core::mem::transmute(HANDLE_VALIDATE_ADDRESS) };
    unsafe { validate(handle) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_handle_validate(_: *const u8) -> i32 {
    panic!("validated_file_tell requires retail validator 0x08087974")
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_cursor_query(handle: u32, position: *mut u32) -> i32 {
    let query: CursorQuery = unsafe { core::mem::transmute(CURSOR_QUERY_ADDRESS) };
    unsafe { query(handle, position) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_cursor_query(_: u32, _: *mut u32) -> i32 {
    panic!("validated_file_tell requires retail cursor query 0x0805a5f4")
}

#[cfg(target_os = "none")]
pub static mut HANDLE_VALIDATE: HandleValidate = firmware_handle_validate;
#[cfg(not(target_os = "none"))]
pub static mut HANDLE_VALIDATE: HandleValidate = missing_handle_validate;
#[cfg(target_os = "none")]
pub static mut CURSOR_QUERY: CursorQuery = firmware_cursor_query;
#[cfg(not(target_os = "none"))]
pub static mut CURSOR_QUERY: CursorQuery = missing_cursor_query;

/// Validates `handle`, then queries the associated cursor into `position`.
///
/// # Safety
/// `handle` must satisfy the installed validator's contract. On success it
/// must be readable through +0x07; `position` must satisfy the query's
/// two-word output contract.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn validated_file_tell(handle: *const u8, position: *mut u32) -> i32 {
    unsafe {
        let validate = read_volatile(addr_of!(HANDLE_VALIDATE));
        let status = validate(handle);
        if status != 0 {
            return status;
        }
        let query = read_volatile(addr_of!(CURSOR_QUERY));
        query(read_volatile(handle.add(4).cast::<u32>()), position)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr::{addr_of, addr_of_mut, read_volatile, write_volatile};

    static mut VALIDATE_STATUS: i32 = 0;
    static mut VALIDATED: *const u8 = core::ptr::null();
    static mut QUERY_CALL: (u32, *mut u32) = (0, core::ptr::null_mut());

    unsafe extern "C" fn record_validate(handle: *const u8) -> i32 {
        unsafe {
            write_volatile(addr_of_mut!(VALIDATED), handle);
            read_volatile(addr_of!(VALIDATE_STATUS))
        }
    }

    unsafe extern "C" fn record_query(handle: u32, position: *mut u32) -> i32 {
        unsafe {
            write_volatile(addr_of_mut!(QUERY_CALL), (handle, position));
            position.write(0x89ab_cdef);
            position.add(1).write(0x0123_4567);
        }
        0
    }

    #[test]
    fn rejects_invalid_handles_and_forwards_valid_handle_cursor_word() {
        unsafe {
            HANDLE_VALIDATE = record_validate;
            CURSOR_QUERY = record_query;
            let mut handle = [0u32; 2];
            handle[1] = 0x7654_3210;
            let mut position = [0xa5a5_a5a5; 2];

            VALIDATE_STATUS = -50;
            QUERY_CALL = (0, core::ptr::null_mut());
            assert_eq!(validated_file_tell(handle.as_ptr().cast(), position.as_mut_ptr()), -50);
            assert_eq!(read_volatile(addr_of!(VALIDATED)), handle.as_ptr().cast());
            assert_eq!(read_volatile(addr_of!(QUERY_CALL)).0, 0);
            assert_eq!(position, [0xa5a5_a5a5; 2]);

            VALIDATE_STATUS = 0;
            assert_eq!(validated_file_tell(handle.as_ptr().cast(), position.as_mut_ptr()), 0);
            assert_eq!(read_volatile(addr_of!(QUERY_CALL)), (0x7654_3210, position.as_mut_ptr()));
            assert_eq!(position, [0x89ab_cdef, 0x0123_4567]);
        }
    }
}
