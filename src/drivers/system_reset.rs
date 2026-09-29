//! System-reset request.
//!
//! `system_reset` — original: `FUN_08367f00` @ `0x08367f00` (44 bytes,
//! `0x08367f00..0x08367f2b`; the literal `0x00000aa5` at `0x08367f2c` is part
//! of the body and the next real function begins at `0x08367f30`). Raw ARM
//! words establish two plain inbound `bl` call sites and zero predicated `bl`
//! call sites.
//!
//! Clears the watchdog control word, writes the `0x0aa5` reset-request key, and
//! then spins forever. Deliberate deviations: volatile writes preserve MMIO
//! semantics; stock uses ordinary `str` instructions.

use core::ptr;

const WATCHDOG_CONTROL: *mut u32 = 0x3c80_0000 as *mut u32;
const RESET_REQUEST: *mut u32 = 0x3c50_0050 as *mut u32;
const RESET_REQUEST_KEY: u32 = 0x0aa5;

#[inline(always)]
unsafe fn request_system_reset(watchdog_control: *mut u32, reset_request: *mut u32) {
    unsafe {
        ptr::write_volatile(watchdog_control, 0);
        ptr::write_volatile(reset_request, RESET_REQUEST_KEY);
    }
}

/// Requests a hardware reset and waits for it to take effect.
///
/// # Safety
///
/// Must run on the S5L8702 with both fixed MMIO registers accessible.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn system_reset() -> ! {
    unsafe { request_system_reset(WATCHDOG_CONTROL, RESET_REQUEST) };
    loop {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clears_watchdog_and_writes_reset_key() {
        let mut watchdog_control = 0xa5a5_5a5a;
        let mut reset_request = 0xdead_beef;

        unsafe { request_system_reset(&mut watchdog_control, &mut reset_request) };

        assert_eq!(watchdog_control, 0);
        assert_eq!(reset_request, RESET_REQUEST_KEY);
    }

    #[test]
    fn reset_request_does_not_modify_adjacent_words() {
        let mut watchdog = [0x1357_9bdf, 0xa5a5_5a5a, 0x2468_ace0];
        let mut request = [0xfedc_ba98, 0xdead_beef, 0x89ab_cdef];

        unsafe { request_system_reset(&mut watchdog[1], &mut request[1]) };

        assert_eq!(watchdog, [0x1357_9bdf, 0, 0x2468_ace0]);
        assert_eq!(request, [0xfedc_ba98, RESET_REQUEST_KEY, 0x89ab_cdef]);
    }
}
