//! `status_bit_4b_is_set_if_context_exists` — original: `FUN_080aa7c0` @
//! `0x080aa7c0` (44 bytes, `0x080aa7c0..0x080aa7eb`).
//! Raw A32 establishes the 44-byte instruction body through `0x080aa7eb`;
//! the context-pointer literal at `0x080aa7ec` is outside the body and
//! `0x080aa7f0` begins the next function.
//! Full-image decoding finds three inbound plain `bl` calls (`0x080fd0cc`,
//! `0x080fd0e8`, and `0x081500a4`) and no predicated inbound `bl` calls. The
//! body has one plain `bl`, to the unported status helper `0x081c08cc`, and no
//! predicated calls.
//!
//! Algorithm: return zero unless the context-pointer word at `0x089cda20` is
//! nonzero. Otherwise call `0x081c08cc` and normalize its nonzero result to
//! one. That helper obtains status property `0x4b` and tests bit two.
//!
//! Deliberate deviations: the context global and helper have no names.yaml
//! identities beyond their observed behavior. Target builds use their verified
//! retail addresses; host tests install narrow volatile seams instead.

#[cfg(not(target_os = "none"))]
use core::ptr::addr_of;

const RETAIL_CONTEXT_POINTER: *const u32 = 0x089c_da20 as *const u32;
const RETAIL_STATUS_BIT_4B: usize = 0x081c_08cc;

/// ABI of the unrecovered helper that returns whether status property `0x4b`
/// has bit two set.
pub type StatusBit4bIsSet = unsafe extern "C" fn() -> u32;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_status_bit_4b() -> u32 {
    panic!("install status-bit-4b host seams before calling this predicate")
}

/// Host seams for the context-pointer word and unrecovered status helper.
#[cfg(not(target_os = "none"))]
pub static mut STATUS_CONTEXT_POINTER: u32 = 0;
#[cfg(not(target_os = "none"))]
pub static mut STATUS_BIT_4B_IS_SET: StatusBit4bIsSet = missing_status_bit_4b;

#[inline(always)]
unsafe fn context_exists() -> bool {
    #[cfg(target_os = "none")]
    {
        unsafe { core::ptr::read_volatile(RETAIL_CONTEXT_POINTER) != 0 }
    }
    #[cfg(not(target_os = "none"))]
    {
        unsafe { core::ptr::read_volatile(addr_of!(STATUS_CONTEXT_POINTER)) != 0 }
    }
}

#[inline(always)]
unsafe fn status_bit_4b_is_set() -> u32 {
    #[cfg(target_os = "none")]
    {
        let helper: StatusBit4bIsSet = unsafe { core::mem::transmute(RETAIL_STATUS_BIT_4B) };
        unsafe { helper() }
    }
    #[cfg(not(target_os = "none"))]
    {
        let helper = unsafe { core::ptr::read_volatile(addr_of!(STATUS_BIT_4B_IS_SET)) };
        unsafe { helper() }
    }
}

/// Tests status property `0x4b` bit two only while its required context exists.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn status_bit_4b_is_set_if_context_exists() -> u32 {
    if !unsafe { context_exists() } {
        return 0;
    }
    (unsafe { status_bit_4b_is_set() } != 0) as u32
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr::addr_of_mut;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: u32 = 0;
    static mut HELPER_RESULT: u32 = 0;

    unsafe extern "C" fn status_helper() -> u32 {
        unsafe { CALLS += 1; HELPER_RESULT }
    }

    fn install() {
        unsafe {
            STATUS_CONTEXT_POINTER = 0;
            STATUS_BIT_4B_IS_SET = status_helper;
            CALLS = 0;
            HELPER_RESULT = 0;
        }
    }

    #[test]
    fn absent_context_skips_the_helper() {
        let _guard = LOCK.lock();
        install();
        unsafe { HELPER_RESULT = 1 };

        assert_eq!(unsafe { status_bit_4b_is_set_if_context_exists() }, 0);
        assert_eq!(unsafe { addr_of_mut!(CALLS).read() }, 0);
    }

    #[test]
    fn present_context_normalizes_helper_results() {
        let _guard = LOCK.lock();
        install();
        unsafe { STATUS_CONTEXT_POINTER = 0x1234_5678 };

        for (result, expected) in [(0, 0), (1, 1), (2, 1), (u32::MAX, 1)] {
            unsafe { HELPER_RESULT = result; CALLS = 0 };
            assert_eq!(unsafe { status_bit_4b_is_set_if_context_exists() }, expected);
            assert_eq!(unsafe { addr_of_mut!(CALLS).read() }, 1, "helper result {result:#x}");
        }
    }
}
