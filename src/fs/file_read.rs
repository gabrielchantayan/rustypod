//! `retail_file_read` — original: `FUN_082784b8` @ `0x082784b8`
//! (28 bytes; 38 verified direct `bl` call sites).
//!
//! # Algorithm
//!
//! The ARM wrapper preserves its fourth incoming word, writes zero into the
//! stack slot for the fifth argument of `0x082784d4`, restores the fourth word
//! to `r3`, and returns that body's status unchanged. It has no null, length,
//! or buffer guard: even `(null, 0, null, transferred)` reaches the body.
//!
//! `0x082784d4` is a distinct 740-byte function whose deeper identity is not
//! recovered. Target builds call its resident retailOS address; host tests
//! replace that boundary to prove the complete five-word ABI. The host default
//! returns the file-layer error `2`, preserving the former fail-closed model.

/// ABI of the unrecovered read body at retailOS address `0x082784d4`.
///
/// The final control word is always zero in [`retail_file_read`]. Its semantic
/// meaning belongs to the unrecovered body and is intentionally not inferred.
pub type RetailFileReadBody = unsafe extern "C" fn(
    handle: *mut core::ffi::c_void,
    count: u32,
    buffer: *mut u8,
    transferred: *mut u32,
    control: u32,
) -> i32;

/// RetailOS load address of the body reached by this wrapper.
pub const RETAIL_FILE_READ_BODY_ADDRESS: usize = 0x0827_84d4;

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_file_read_body(
    handle: *mut core::ffi::c_void,
    count: u32,
    buffer: *mut u8,
    transferred: *mut u32,
    control: u32,
) -> i32 {
    let body: RetailFileReadBody = core::mem::transmute(RETAIL_FILE_READ_BODY_ADDRESS);
    body(handle, count, buffer, transferred, control)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_retail_file_read_body(
    _handle: *mut core::ffi::c_void,
    _count: u32,
    _buffer: *mut u8,
    _transferred: *mut u32,
    _control: u32,
) -> i32 {
    2
}

/// Active boundary for the unrecovered `0x082784d4` read body.
///
/// Target builds call the resident retailOS function. Host tests may install a
/// recorder; the normal host default fails closed with status `2`.
#[cfg(target_os = "none")]
pub static mut RETAIL_FILE_READ_BODY: RetailFileReadBody = retail_file_read_body;

/// Active host boundary for the unrecovered `0x082784d4` read body.
#[cfg(not(target_os = "none"))]
pub static mut RETAIL_FILE_READ_BODY: RetailFileReadBody = missing_retail_file_read_body;

#[inline(always)]
unsafe fn retail_file_read_body_entry() -> RetailFileReadBody {
    core::ptr::addr_of!(RETAIL_FILE_READ_BODY).read_volatile()
}

/// `retail_file_read` — original: `FUN_082784b8` @ `0x082784b8` (28 bytes;
/// 38 verified direct `bl` call sites, all unconditional).
///
/// Calls `0x082784d4` as `(handle, count, buffer, transferred, 0)` and returns
/// its status unchanged. Deliberate deviation: Rust reaches the fixed resident
/// target through a volatile typed boundary rather than emitting the stock
/// direct branch; this preserves the ABI while permitting host verification.
///
/// # Safety
///
/// All five values must satisfy the unrecovered body's ABI. This wrapper does
/// not dereference any of them itself.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn retail_file_read(
    handle: *mut core::ffi::c_void,
    count: u32,
    buffer: *mut u8,
    transferred: *mut u32,
) -> i32 {
    retail_file_read_body_entry()(handle, count, buffer, transferred, 0)
}

#[cfg(test)]
pub(crate) unsafe fn reset_retail_file_read_body() {
    core::ptr::addr_of_mut!(RETAIL_FILE_READ_BODY).write_volatile(missing_retail_file_read_body);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    static mut RECEIVED: [usize; 5] = [0; 5];
    static mut RETURN_STATUS: i32 = 0;
    static mut CALLS: u32 = 0;

    unsafe extern "C" fn recording_body(
        handle: *mut core::ffi::c_void,
        count: u32,
        buffer: *mut u8,
        transferred: *mut u32,
        control: u32,
    ) -> i32 {
        RECEIVED = [handle as usize, count as usize, buffer as usize, transferred as usize, control as usize];
        CALLS += 1;
        RETURN_STATUS
    }

    struct Reset;

    impl Drop for Reset {
        fn drop(&mut self) {
            unsafe {
                reset_retail_file_read_body();
                RECEIVED = [0; 5];
                RETURN_STATUS = 0;
                CALLS = 0;
            }
        }
    }

    #[test]
    fn forwards_every_input_word_and_returns_the_body_status() {
        let _guard = crate::ft::system::TEST_OPS_LOCK.lock().expect("test lock poisoned");
        let _reset = Reset;
        let mut transferred = 0;
        unsafe {
            RETURN_STATUS = -37;
            core::ptr::addr_of_mut!(RETAIL_FILE_READ_BODY).write_volatile(recording_body);
            assert_eq!(
                retail_file_read(
                    0x1234_5678usize as *mut core::ffi::c_void,
                    u32::MAX,
                    0x8765_4321usize as *mut u8,
                    &mut transferred,
                ),
                -37,
            );
            assert_eq!(CALLS, 1);
            assert_eq!(
                RECEIVED,
                [
                    0x1234_5678,
                    u32::MAX as usize,
                    0x8765_4321,
                    (&mut transferred as *mut u32) as usize,
                    0,
                ],
            );
        }
    }

    #[test]
    fn forwards_null_and_zero_without_a_wrapper_guard() {
        let _guard = crate::ft::system::TEST_OPS_LOCK.lock().expect("test lock poisoned");
        let _reset = Reset;
        unsafe {
            RETURN_STATUS = 5;
            core::ptr::addr_of_mut!(RETAIL_FILE_READ_BODY).write_volatile(recording_body);
            assert_eq!(retail_file_read(core::ptr::null_mut(), 0, core::ptr::null_mut(), core::ptr::null_mut()), 5);
            assert_eq!(CALLS, 1);
            assert_eq!(RECEIVED, [0, 0, 0, 0, 0]);
        }
    }
}
