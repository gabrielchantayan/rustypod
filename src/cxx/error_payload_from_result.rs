//! `error_payload_from_result` — original: `FUN_0827024c` @ `0x0827024c`
//! (108 bytes, including the 12-byte literal pool at `0x082702ac..0x082702b8`).
//!
//! Raw ARM contains three plain `bl` instructions and no predicated `bl`:
//! `cxa_guard_acquire`, the default-payload initializer, and
//! `cxa_guard_release`. It reads the result payload word at `source + 8`.
//! A nonzero payload builds an owning error record in `destination`; otherwise
//! it initializes the guarded default record once and copies its flag and two
//! payload words. The default initializer is inlined deliberately: its 20-byte
//! body only stores the verified vtable word and clears the flag.

use core::ptr;

use crate::runtime::cxa_guard::{cxa_guard_acquire, cxa_guard_release};

const DEFAULT_ERROR_VTABLE: u32 = 0x089a_76fc;
const DEFAULT_ERROR_ADDRESS: usize = 0x08a1_26bc;
const DEFAULT_ERROR_GUARD_ADDRESS: usize = 0x089c_a624;

#[repr(C)]
pub struct ErrorPayload {
    vtable: u32,
    flag: u8,
    _padding: [u8; 3],
    value: u32,
    detail: u32,
}

#[cfg(not(target_os = "none"))]
static mut DEFAULT_ERROR: ErrorPayload = ErrorPayload {
    vtable: 0,
    flag: 0,
    _padding: [0; 3],
    value: 0,
    detail: 0,
};

#[cfg(not(target_os = "none"))]
static mut DEFAULT_ERROR_GUARD: u32 = 0;

#[inline(always)]
unsafe fn default_error_state() -> (*mut ErrorPayload, *mut u32) {
    #[cfg(target_os = "none")]
    {
        (DEFAULT_ERROR_ADDRESS as *mut ErrorPayload, DEFAULT_ERROR_GUARD_ADDRESS as *mut u32)
    }
    #[cfg(not(target_os = "none"))]
    {
        (ptr::addr_of_mut!(DEFAULT_ERROR), ptr::addr_of_mut!(DEFAULT_ERROR_GUARD))
    }
}

/// Builds the error payload corresponding to a result object.
///
/// The source is only required to contain the word at byte offset eight. Its
/// value is copied verbatim; it is not dereferenced.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn error_payload_from_result(destination: *mut ErrorPayload, source: *const u8) {
    let payload = ptr::read_volatile(source.add(8).cast::<u32>());
    if payload != 0 {
        ptr::write_volatile(ptr::addr_of_mut!((*destination).vtable), DEFAULT_ERROR_VTABLE);
        ptr::write_volatile(ptr::addr_of_mut!((*destination).flag), 1);
        ptr::write_volatile(ptr::addr_of_mut!((*destination).value), payload);
        ptr::write_volatile(ptr::addr_of_mut!((*destination).detail), 0);
        return;
    }

    let (default_error, guard) = default_error_state();
    if ptr::read_volatile(guard) & 1 == 0 && cxa_guard_acquire(guard) != 0 {
        ptr::write_volatile(ptr::addr_of_mut!((*default_error).vtable), DEFAULT_ERROR_VTABLE);
        ptr::write_volatile(ptr::addr_of_mut!((*default_error).flag), 0);
        cxa_guard_release(guard);
    }
    ptr::write_volatile(ptr::addr_of_mut!((*destination).vtable), DEFAULT_ERROR_VTABLE);
    ptr::write_volatile(ptr::addr_of_mut!((*destination).flag), ptr::read_volatile(ptr::addr_of!((*default_error).flag)));
    ptr::write_volatile(ptr::addr_of_mut!((*destination).value), ptr::read_volatile(ptr::addr_of!((*default_error).value)));
    ptr::write_volatile(ptr::addr_of_mut!((*destination).detail), ptr::read_volatile(ptr::addr_of!((*default_error).detail)));
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn nonzero_result_becomes_owning_payload() {
        let _lock = TEST_LOCK.lock();
        let source = [0u32, 0, 0xdead_beef];
        let mut destination = ErrorPayload { vtable: 0, flag: 0, _padding: [0; 3], value: 0, detail: 9 };
        unsafe { error_payload_from_result(&mut destination, source.as_ptr().cast()) };
        assert_eq!(destination.vtable, DEFAULT_ERROR_VTABLE);
        assert_eq!(destination.flag, 1);
        assert_eq!(destination.value, 0xdead_beef);
        assert_eq!(destination.detail, 0);
    }

    #[test]
    fn zero_result_copies_guarded_default_payload() {
        let _lock = TEST_LOCK.lock();
        unsafe {
            DEFAULT_ERROR = ErrorPayload { vtable: 0, flag: 7, _padding: [0; 3], value: 0x1122_3344, detail: 0x5566_7788 };
            DEFAULT_ERROR_GUARD = 0;
        }
        let source = [0u32; 3];
        let mut destination = ErrorPayload { vtable: 0, flag: 0, _padding: [0; 3], value: 0, detail: 0 };
        unsafe { error_payload_from_result(&mut destination, source.as_ptr().cast()) };
        assert_eq!(destination.vtable, DEFAULT_ERROR_VTABLE);
        assert_eq!(destination.flag, 0);
        assert_eq!(destination.value, 0x1122_3344);
        assert_eq!(destination.detail, 0x5566_7788);
    }
}
