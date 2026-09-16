//! `object_validation_status` — original: `FUN_0839020c` @ `0x0839020c`.
//!
//! True extent: 64 bytes (`0x0839020c..0x0839024c`), ending at `pop {r4,pc}`;
//! the next distinct function starts with `push {r4,lr}` at `0x0839024c`.
//! Raw `osos.dec` decoding finds four incoming plain `bl` calls
//! (`0x082ccf70`, `0x082dc060`, `0x082dc07c`, and `0x08390580`) and no incoming
//! predicated `bl` calls. Its one outgoing plain `bl` calls the unported
//! validator at `0x08382c18`.
//!
//! A null object, an object rejected by that validator, or an object whose
//! byte at `+0x1e` is nonzero returns the status value 7. A rejected non-null
//! object instead returns 21. For an accepted object with a zero `+0x1e` byte,
//! the result is the bitwise AND of its aligned words at `+0x14` and `+0x18`.
//! Deliberate deviations: the validator remains a target-address seam; host
//! tests replace it because retailOS code is not host-mapped.

const VALIDATOR_ADDRESS: usize = 0x0838_2c18;
const STATUS_DEFAULT: u32 = 7;
const STATUS_VALIDATION_FAILED: u32 = 21;
const STATUS_MASK_A_OFFSET: usize = 0x14;
const STATUS_MASK_B_OFFSET: usize = 0x18;
const STATUS_BYTE_OFFSET: usize = 0x1e;

type ObjectValidator = unsafe extern "C" fn(*const u8) -> u32;

#[cfg(target_arch = "arm")]
#[inline(always)]
unsafe fn retail_object_validator(object: *const u8) -> u32 {
    let validator: ObjectValidator = core::mem::transmute(VALIDATOR_ADDRESS);
    validator(object)
}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn unavailable_object_validator(_object: *const u8) -> u32 {
    0
}

#[cfg(not(target_arch = "arm"))]
static mut OBJECT_VALIDATOR: ObjectValidator = unavailable_object_validator;

#[inline(always)]
unsafe fn object_validator(object: *const u8) -> u32 {
    #[cfg(target_arch = "arm")]
    {
        retail_object_validator(object)
    }
    #[cfg(not(target_arch = "arm"))]
    {
        OBJECT_VALIDATOR(object)
    }
}

/// Returns the object's validation status using its retailOS field layout.
///
/// # Safety
///
/// When `object` is non-null, it must be valid for the validator and for reads
/// of bytes through `+0x1f`; the two mask words must be aligned `u32`s.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn object_validation_status(object: *const u8) -> u32 {
    if object.is_null() {
        return STATUS_DEFAULT;
    }
    if object_validator(object) == 0 {
        return STATUS_VALIDATION_FAILED;
    }
    if object.add(STATUS_BYTE_OFFSET).read() != 0 {
        return STATUS_DEFAULT;
    }
    (object.add(STATUS_MASK_A_OFFSET) as *const u32).read()
        & (object.add(STATUS_MASK_B_OFFSET) as *const u32).read()
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;
    static VALIDATOR_TEST_LOCK: Mutex<()> = Mutex::new(());

    static mut VALIDATOR_RESULT: u32 = 0;

    unsafe extern "C" fn test_validator(_object: *const u8) -> u32 {
        VALIDATOR_RESULT
    }

    unsafe fn with_validator_result(result: u32, test: impl FnOnce()) {
        let _lock = VALIDATOR_TEST_LOCK.lock();
        let previous_validator = OBJECT_VALIDATOR;
        let previous_result = VALIDATOR_RESULT;
        OBJECT_VALIDATOR = test_validator;
        VALIDATOR_RESULT = result;
        test();
        OBJECT_VALIDATOR = previous_validator;
        VALIDATOR_RESULT = previous_result;
    }

    #[test]
    fn null_object_returns_default_without_validation() {
        unsafe {
            with_validator_result(1, || {
                assert_eq!(object_validation_status(core::ptr::null()), STATUS_DEFAULT);
            });
        }
    }

    #[test]
    fn rejected_object_returns_validation_failure() {
        let object = [0u32; 8];
        unsafe {
            with_validator_result(0, || {
                assert_eq!(object_validation_status(object.as_ptr().cast()), STATUS_VALIDATION_FAILED);
            });
        }
    }

    #[test]
    fn accepted_active_object_returns_default() {
        let mut object = [0u32; 8];
        unsafe {
            (object.as_mut_ptr().cast::<u8>().add(STATUS_BYTE_OFFSET)).write(1);
            with_validator_result(1, || {
                assert_eq!(object_validation_status(object.as_ptr().cast()), STATUS_DEFAULT);
            });
        }
    }

    #[test]
    fn accepted_inactive_object_ands_status_masks() {
        let mut object = [0u32; 8];
        object[STATUS_MASK_A_OFFSET / 4] = 0xa5a5_0f0f;
        object[STATUS_MASK_B_OFFSET / 4] = 0x3c3c_f0f0;
        unsafe {
            with_validator_result(1, || {
                assert_eq!(object_validation_status(object.as_ptr().cast()), 0x2424_0000);
            });
        }
    }
}
