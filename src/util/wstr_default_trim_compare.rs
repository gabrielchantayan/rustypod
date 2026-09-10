//! `wstr_default_trim_compare` — original: `FUN_0804544c` @ `0x0804544c`
//! (60 bytes; `0x0804544c..0x08045487`, followed by its literal-pool word at
//! `0x08045488`; the separately linked `FUN_0804548c` begins at
//! `0x0804548c`). Decoding every ARM B/BL immediate in `osos.dec` finds 12
//! direct call sites, all unconditional `bl`; there are no predicated calls.
//!
//! The wrapper lazily initializes the live default collation word at
//! `0x089cb1a4` to 29 only when it is zero, then forwards its opaque context,
//! two UTF-16 buffers, their `u32` lengths, and that word to
//! `FUN_0804548c`. It does not inspect or guard any caller argument, and
//! returns the helper's tri-state result unchanged. The separately linked
//! helper trims leading `u16` values `<= 0x20` and calls the unported counted
//! collation compare at `0x0804529c`.
//!
//! Deliberate deviation: `FUN_0804548c` is not ported, so this wrapper uses a
//! volatile dispatch seam. Target builds call its retail address; host tests
//! install a recorder. The host-only collation word models the live target
//! word so initialization behavior remains testable.

use core::ffi::c_void;
use core::ptr;

/// ABI of the separately linked, still-unported trim-and-compare helper at
/// `0x0804548c`.
pub type WstrDefaultTrimCompareFn = unsafe extern "C" fn(
    *mut c_void,
    *const u16,
    u32,
    *const u16,
    u32,
    u32,
) -> i32;

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_wstr_default_trim_compare(
    context: *mut c_void,
    left: *const u16,
    left_len: u32,
    right: *const u16,
    right_len: u32,
    flags: u32,
) -> i32 {
    let compare: WstrDefaultTrimCompareFn = core::mem::transmute(0x0804_548cusize);
    compare(context, left, left_len, right, right_len, flags)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_wstr_default_trim_compare(
    _context: *mut c_void,
    _left: *const u16,
    _left_len: u32,
    _right: *const u16,
    _right_len: u32,
    _flags: u32,
) -> i32 {
    panic!("wstr_default_trim_compare requires a helper seam on host")
}

#[cfg(target_os = "none")]
pub static mut WSTR_DEFAULT_TRIM_COMPARE: WstrDefaultTrimCompareFn = retail_wstr_default_trim_compare;

#[cfg(not(target_os = "none"))]
pub static mut WSTR_DEFAULT_TRIM_COMPARE: WstrDefaultTrimCompareFn = missing_wstr_default_trim_compare;

#[cfg(not(target_os = "none"))]
static mut HOST_DEFAULT_COLLATION_FLAGS: u32 = 0;

#[inline(always)]
unsafe fn default_collation_flags() -> u32 {
    #[cfg(target_os = "none")]
    {
        let flags_ptr = 0x089c_b1a4usize as *mut u32;
        let flags = ptr::read_volatile(flags_ptr);
        if flags == 0 {
            ptr::write_volatile(flags_ptr, 29);
            29
        } else {
            flags
        }
    }

    #[cfg(not(target_os = "none"))]
    {
        let flags_ptr = ptr::addr_of_mut!(HOST_DEFAULT_COLLATION_FLAGS);
        let flags = ptr::read_volatile(flags_ptr);
        if flags == 0 {
            ptr::write_volatile(flags_ptr, 29);
            29
        } else {
            flags
        }
    }
}

#[inline(always)]
unsafe fn trim_compare_fn() -> WstrDefaultTrimCompareFn {
    ptr::read_volatile(ptr::addr_of!(WSTR_DEFAULT_TRIM_COMPARE))
}

/// `wstr_default_trim_compare` — original: `FUN_0804544c` @ `0x0804544c`
/// (60 bytes; 12 binary-verified unconditional `bl` call sites).
///
/// Initializes the live default flags word to 29 iff it is zero, then returns
/// the result of the retail trim-and-compare helper. `context` and both input
/// ranges are forwarded unchanged; this wrapper performs no input reads.
///
/// # Safety
/// The target helper dereferences `left` and `right` according to their
/// lengths. `context` must meet that helper's opaque ABI requirements.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.wstr_default_trim_compare")]
#[inline(never)]
pub unsafe extern "C" fn wstr_default_trim_compare(
    context: *mut c_void,
    left: *const u16,
    left_len: u32,
    right: *const u16,
    right_len: u32,
) -> i32 {
    let flags = default_collation_flags();
    trim_compare_fn()(context, left, left_len, right, right_len, flags)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::Mutex;
    use std::vec::Vec;

    static COMPARE_LOCK: Mutex<()> = Mutex::new(());

    struct Call {
        context: *mut c_void,
        left: *const u16,
        left_len: u32,
        right: *const u16,
        right_len: u32,
        flags: u32,
    }

    static mut CALLS: Vec<Call> = Vec::new();
    static mut RESULT: i32 = 0;

    unsafe extern "C" fn record_compare(
        context: *mut c_void,
        left: *const u16,
        left_len: u32,
        right: *const u16,
        right_len: u32,
        flags: u32,
    ) -> i32 {
        CALLS.push(Call { context, left, left_len, right, right_len, flags });
        RESULT
    }

    struct SeamGuard(WstrDefaultTrimCompareFn);

    impl Drop for SeamGuard {
        fn drop(&mut self) {
            unsafe { WSTR_DEFAULT_TRIM_COMPARE = self.0 };
        }
    }

    struct FlagsGuard(u32);

    impl Drop for FlagsGuard {
        fn drop(&mut self) {
            unsafe { ptr::write_volatile(ptr::addr_of_mut!(HOST_DEFAULT_COLLATION_FLAGS), self.0) };
        }
    }

    unsafe fn install_recorder(result: i32, flags: u32) -> (SeamGuard, FlagsGuard) {
        let previous_seam = WSTR_DEFAULT_TRIM_COMPARE;
        let previous_flags = ptr::read_volatile(ptr::addr_of!(HOST_DEFAULT_COLLATION_FLAGS));
        WSTR_DEFAULT_TRIM_COMPARE = record_compare;
        ptr::write_volatile(ptr::addr_of_mut!(HOST_DEFAULT_COLLATION_FLAGS), flags);
        CALLS.clear();
        RESULT = result;
        (SeamGuard(previous_seam), FlagsGuard(previous_flags))
    }

    #[test]
    fn initializes_zero_flags_and_forwards_every_argument() {
        let _lock = COMPARE_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let context = 0x1234usize as *mut c_void;
        let left = [0x20u16, 0x61];
        let right = [0x20u16, 0x62];
        unsafe {
            let (_seam, _flags) = install_recorder(-1, 0);
            assert_eq!(
                wstr_default_trim_compare(context, left.as_ptr(), 2, right.as_ptr(), 2),
                -1
            );
            assert_eq!(CALLS.len(), 1);
            let call = &CALLS[0];
            assert_eq!(call.context, context);
            assert_eq!(call.left, left.as_ptr());
            assert_eq!(call.left_len, 2);
            assert_eq!(call.right, right.as_ptr());
            assert_eq!(call.right_len, 2);
            assert_eq!(call.flags, 29);
            assert_eq!(HOST_DEFAULT_COLLATION_FLAGS, 29);
        }
    }

    #[test]
    fn preserves_nonzero_flags_and_unreadable_empty_inputs() {
        let _lock = COMPARE_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            let (_seam, _flags) = install_recorder(i32::MIN, 0xfeed_cafe);
            assert_eq!(
                wstr_default_trim_compare(ptr::null_mut(), ptr::null(), 0, ptr::null(), u32::MAX),
                i32::MIN
            );
            let call = &CALLS[0];
            assert!(call.context.is_null());
            assert!(call.left.is_null());
            assert_eq!(call.left_len, 0);
            assert!(call.right.is_null());
            assert_eq!(call.right_len, u32::MAX);
            assert_eq!(call.flags, 0xfeed_cafe);
            assert_eq!(HOST_DEFAULT_COLLATION_FLAGS, 0xfeed_cafe);
        }
    }
}
