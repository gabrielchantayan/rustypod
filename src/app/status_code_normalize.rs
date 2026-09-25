//! `status_code_normalize` — original: `FUN_08051de0` @ `0x08051de0` (44
//! bytes, `0x08051de0..0x08051e08`; the next real function begins at
//! `0x08051e0c`).
//!
//! Raw A32 words establish one plain outbound `bl` to the still-unidentified
//! byte-returning helper at `0x0809b644`, with no predicated `bl` form.
//! Whole-image A32 decoding finds three inbound plain `bl` calls
//! (`0x08114e10`, `0x08116a84`, and `0x081e60f8`) and no predicated forms.
//!
//! # Algorithm
//!
//! Query retail status with argument zero. Preserve status 1, translate status
//! 2 to 3, and return zero for every other result.
//!
//! # Deliberate deviations
//!
//! The retail helper remains unidentified. Target builds call its verified
//! address; host builds use the existing recording seam.

use super::object_byte_0x450_initialize::retail_byte_initializer;

#[inline(always)]
const fn normalize_status_code(raw_status: u8) -> u32 {
    match raw_status {
        1 => 1,
        2 => 3,
        _ => 0,
    }
}

/// Maps the retail status helper's byte result into the caller-visible code.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn status_code_normalize() -> u32 {
    normalize_status_code(unsafe { retail_byte_initializer() })
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::object_byte_0x450_initialize::{
        OBJECT_BYTE_0X450_INITIALIZER, RETAIL_BYTE_INITIALIZER_TEST_LOCK,
    };
    use core::ptr::addr_of_mut;

    static mut STATUS: u8 = 0;

    unsafe extern "C" fn status_query(argument: u32) -> u8 {
        assert_eq!(argument, 0);
        unsafe { STATUS }
    }

    fn install_status_query(status: u8) {
        unsafe {
            addr_of_mut!(OBJECT_BYTE_0X450_INITIALIZER).write(status_query);
            STATUS = status;
        }
    }

    #[test]
    fn maps_every_observed_and_boundary_status_through_the_retail_call() {
        let _guard = RETAIL_BYTE_INITIALIZER_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

        for (raw_status, expected) in [(0, 0), (1, 1), (2, 3), (3, 0), (0x7f, 0), (0x80, 0), (u8::MAX, 0)] {
            install_status_query(raw_status);
            assert_eq!(unsafe { status_code_normalize() }, expected);
        }
    }
}
