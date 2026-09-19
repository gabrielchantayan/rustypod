//! `validate_standard_request` — original: `FUN_080278d8` @ 0x080278d8
//! (56 bytes; one unconditional outgoing `bl` and no predicated `bl` forms;
//! four incoming plain `bl` call sites — verified from `osos.dec`).
//!
//! Supplies the literal `"STANDARD\0"`, zero mode, and no optional argument
//! to the shared request validator at 0x080276f0. The returned status passes
//! through unchanged.
//!
//! # Deviation
//!
//! The shared validator is unported and has no established semantic identity.
//! Target builds call its verified address; host builds use a replacement seam.

const STANDARD_REQUEST_TYPE: &[u8; 9] = b"STANDARD\0";
const STANDARD_REQUEST_VALIDATOR_ADDR: usize = 0x0802_76f0;

type StandardRequestValidator = unsafe extern "C" fn(
    u32,
    *const u8,
    u32,
    u32,
    *const u8,
    u32,
) -> u32;

#[cfg(not(target_os = "none"))]
static mut STANDARD_REQUEST_VALIDATOR: Option<StandardRequestValidator> = None;

#[inline(always)]
unsafe fn standard_request_validator() -> StandardRequestValidator {
    #[cfg(target_os = "none")]
    {
        core::mem::transmute(STANDARD_REQUEST_VALIDATOR_ADDR)
    }
    #[cfg(not(target_os = "none"))]
    {
        match core::ptr::read_volatile(core::ptr::addr_of!(STANDARD_REQUEST_VALIDATOR)) {
            Some(validator) => validator,
            None => panic!("validate_standard_request requires validator 0x080276f0"),
        }
    }
}

/// Validates a request against the retail `STANDARD` request type.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn validate_standard_request(
    request: u32,
    request_name: *const u8,
    request_kind: u32,
) -> u32 {
    standard_request_validator()(request, request_name, request_kind, 0, STANDARD_REQUEST_TYPE.as_ptr(), 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr::{addr_of, addr_of_mut};
    use parking_lot::Mutex;

    static VALIDATOR_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: u32 = 0;
    static mut ARGS: (u32, usize, u32, u32, usize, u32) = (0, 0, 0, 0, 0, 0);
    static mut RESULT: u32 = 0;

    unsafe extern "C" fn record_validator(
        request: u32,
        request_name: *const u8,
        request_kind: u32,
        mode: u32,
        request_type: *const u8,
        optional: u32,
    ) -> u32 {
        let calls = addr_of_mut!(CALLS);
        calls.write_volatile(calls.read_volatile() + 1);
        addr_of_mut!(ARGS).write_volatile((request, request_name as usize, request_kind, mode, request_type as usize, optional));
        addr_of!(RESULT).read_volatile()
    }

    #[test]
    fn forwards_arguments_and_retail_standard_defaults() {
        let _lock = VALIDATOR_LOCK.lock();
        let name = b"client\0";
        unsafe {
            addr_of_mut!(STANDARD_REQUEST_VALIDATOR).write_volatile(Some(record_validator));
            addr_of_mut!(CALLS).write_volatile(0);
            addr_of_mut!(RESULT).write_volatile(0x0b);
            assert_eq!(validate_standard_request(0x1234_5678, name.as_ptr(), 7), 0x0b);
            assert_eq!(addr_of!(CALLS).read_volatile(), 1);
            assert_eq!(addr_of!(ARGS).read_volatile(), (0x1234_5678, name.as_ptr() as usize, 7, 0, STANDARD_REQUEST_TYPE.as_ptr() as usize, 0));
            assert_eq!(core::slice::from_raw_parts(STANDARD_REQUEST_TYPE.as_ptr(), 9), b"STANDARD\0");
        }
    }

    #[test]
    fn returns_validator_failure_unchanged() {
        let _lock = VALIDATOR_LOCK.lock();
        unsafe {
            addr_of_mut!(STANDARD_REQUEST_VALIDATOR).write_volatile(Some(record_validator));
            addr_of_mut!(CALLS).write_volatile(0);
            addr_of_mut!(RESULT).write_volatile(9);
            assert_eq!(validate_standard_request(0, core::ptr::null(), u32::MAX), 9);
            assert_eq!(addr_of!(CALLS).read_volatile(), 1);
        }
    }
}
