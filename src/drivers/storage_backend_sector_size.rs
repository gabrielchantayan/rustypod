//! Storage-backend sector-size query.
//!
//! `storage_backend_sector_size` — retailOS `FUN_080e7064` at load address
//! **0x080e7064**. Raw ARM runs from `push {r3,r4,r5,lr}` through
//! `pop {r3,r4,r5,pc}` at `0x080e70ac`: **76 bytes** (19 words). The word at
//! `0x080e70c0` is its literal pool; the next independently entered function
//! begins at `0x080e70c4`.
//!
//! Decoding every ARM `BL` word in the body finds exactly **three** direct,
//! plain unconditional calls (`0x082bc7c4`, `0x08369da8`, and `0x0836bf28`)
//! and no predicated `BL` calls.
//!
//! # Algorithm
//!
//! Query the storage-backend status. Status 2 validates the state object's
//! backend at +8 with `0x0836bf28`; status 3 uses `0x08369da8`. On another
//! status, clear `output` and return 0x13. On validation success, return the
//! validated object's unsigned halfword at +0x10 through `output`; otherwise
//! propagate the validation error.
//!
//! # Deliberate deviation
//!
//! The two validation targets are not ported. Firmware builds call their
//! verified retail addresses. Host builds use replaceable callbacks and a
//! target-word state model, because narrowed target pointers cannot be safely
//! dereferenced on the host.

#[cfg(not(target_os = "none"))]
use core::ptr;

#[cfg(target_os = "none")]
const RETAIL_STORAGE_BACKEND_STATE: *const u32 = 0x089c_aae4 as *const u32;
#[cfg(target_os = "none")]
const RETAIL_STORAGE_BACKEND_STATUS: usize = 0x082b_c7c4;
#[cfg(target_os = "none")]
const RETAIL_STORAGE_BACKEND_VALIDATE_STATUS_2: usize = 0x0836_bf28;
#[cfg(target_os = "none")]
const RETAIL_STORAGE_BACKEND_VALIDATE_STATUS_3: usize = 0x0836_9da8;

#[cfg(not(target_os = "none"))]
static mut STORAGE_BACKEND_STATE: [u32; 3] = [0; 3];

/// ABI shared by the status selector and its two backend validators.
#[cfg(not(target_os = "none"))]
pub type StorageBackendSectorSizeStatus = unsafe extern "C" fn() -> u32;
#[cfg(not(target_os = "none"))]
pub type StorageBackendValidator = unsafe extern "C" fn(u32, *mut u32) -> u32;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_storage_backend_sector_size_status() -> u32 {
    panic!("storage backend status selector is unported")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_storage_backend_validator(_: u32, _: *mut u32) -> u32 {
    panic!("storage backend validator is unported")
}

/// Host replacements for the retail targets called by this function.
#[cfg(not(target_os = "none"))]
pub static mut STORAGE_BACKEND_SECTOR_SIZE_STATUS: StorageBackendSectorSizeStatus = missing_storage_backend_sector_size_status;
#[cfg(not(target_os = "none"))]
pub static mut STORAGE_BACKEND_VALIDATE_STATUS_2: StorageBackendValidator = missing_storage_backend_validator;
#[cfg(not(target_os = "none"))]
pub static mut STORAGE_BACKEND_VALIDATE_STATUS_3: StorageBackendValidator = missing_storage_backend_validator;

#[inline(always)]
unsafe fn storage_backend_state() -> *const u32 {
    #[cfg(target_os = "none")]
    { RETAIL_STORAGE_BACKEND_STATE }
    #[cfg(not(target_os = "none"))]
    { ptr::addr_of!(STORAGE_BACKEND_STATE).cast() }
}

#[inline(always)]
unsafe fn storage_backend_status() -> u32 {
    #[cfg(target_os = "none")]
    {
        let status: unsafe extern "C" fn() -> u32 = core::mem::transmute(RETAIL_STORAGE_BACKEND_STATUS);
        status()
    }
    #[cfg(not(target_os = "none"))]
    { ptr::read_volatile(ptr::addr_of!(STORAGE_BACKEND_SECTOR_SIZE_STATUS))() }
}

#[inline(always)]
unsafe fn validate_storage_backend(status: u32, backend: u32, validated: *mut u32) -> u32 {
    #[cfg(target_os = "none")]
    {
        let address = if status == 2 { RETAIL_STORAGE_BACKEND_VALIDATE_STATUS_2 } else { RETAIL_STORAGE_BACKEND_VALIDATE_STATUS_3 };
        let validate: unsafe extern "C" fn(u32, *mut u32) -> u32 = core::mem::transmute(address);
        validate(backend, validated)
    }
    #[cfg(not(target_os = "none"))]
    {
        if status == 2 {
            ptr::read_volatile(ptr::addr_of!(STORAGE_BACKEND_VALIDATE_STATUS_2))(backend, validated)
        } else {
            ptr::read_volatile(ptr::addr_of!(STORAGE_BACKEND_VALIDATE_STATUS_3))(backend, validated)
        }
    }
}

/// Reads the selected storage backend's sector-size halfword — retailOS
/// `FUN_080e7064` at `0x080e7064` (76 bytes; three plain direct `BL` calls).
///
/// # Safety
/// Firmware builds read the fixed state object and trust the retail validators
/// to return a valid backend pointer on success. `output` must be writable.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.storage_backend_sector_size")]
pub unsafe extern "C" fn storage_backend_sector_size(output: *mut u32) -> u32 {
    let status = storage_backend_status();
    if status != 2 && status != 3 {
        output.write_volatile(0);
        return 0x13;
    }

    let mut backend = 0;
    let result = validate_storage_backend(status, storage_backend_state().add(2).read_volatile(), &mut backend);
    if result == 0 {
        output.write_volatile((backend as *const u16).add(8).read_volatile() as u32);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut STATUS: u32 = 0;
    static mut STATUS_2_CALLS: u32 = 0;
    static mut STATUS_3_CALLS: u32 = 0;
    static mut VALIDATION_RESULT: u32 = 0;
    static mut VALIDATED_BACKEND: u32 = 0;

    unsafe extern "C" fn status() -> u32 { STATUS }
    unsafe extern "C" fn validate_status_2(backend: u32, validated: *mut u32) -> u32 {
        STATUS_2_CALLS += 1;
        assert_eq!(backend, STORAGE_BACKEND_STATE[2]);
        validated.write(VALIDATED_BACKEND);
        VALIDATION_RESULT
    }
    unsafe extern "C" fn validate_status_3(backend: u32, validated: *mut u32) -> u32 {
        STATUS_3_CALLS += 1;
        assert_eq!(backend, STORAGE_BACKEND_STATE[2]);
        validated.write(VALIDATED_BACKEND);
        VALIDATION_RESULT
    }

    unsafe fn reset() {
        STORAGE_BACKEND_SECTOR_SIZE_STATUS = status;
        STORAGE_BACKEND_VALIDATE_STATUS_2 = validate_status_2;
        STORAGE_BACKEND_VALIDATE_STATUS_3 = validate_status_3;
        STORAGE_BACKEND_STATE = [0xa5a5_a5a5, 0x5a5a_5a5a, 0x1234_5678];
        STATUS = 0;
        STATUS_2_CALLS = 0;
        STATUS_3_CALLS = 0;
        VALIDATION_RESULT = 0;
        VALIDATED_BACKEND = 0;
    }

    #[test]
    fn unsupported_status_clears_output_without_validating() {
        let _lock = TEST_LOCK.lock();
        unsafe {
            reset();
            let mut output = 0xdead_beef;
            assert_eq!(storage_backend_sector_size(&mut output), 0x13);
            assert_eq!(output, 0);
            assert_eq!((STATUS_2_CALLS, STATUS_3_CALLS), (0, 0));
        }
    }

    #[test]
    fn status_two_reads_validated_sector_size() {
        let _lock = TEST_LOCK.lock();
        unsafe {
            reset();
            STATUS = 2;
            let Some(object) = crate::testing::try_map_u32_slab(
                crate::testing::hints::STORAGE_BACKEND_SECTOR_SIZE,
                0x1000,
            ) else {
                return;
            };
            (object as *mut u16).add(8).write(0xbeef);
            VALIDATED_BACKEND = object as usize as u32;
            let mut output = 0;
            assert_eq!(storage_backend_sector_size(&mut output), 0);
            assert_eq!(output, 0xbeef);
            assert_eq!((STATUS_2_CALLS, STATUS_3_CALLS), (1, 0));
        }
    }

    #[test]
    fn status_three_propagates_validation_error_without_writing_output() {
        let _lock = TEST_LOCK.lock();
        unsafe {
            reset();
            STATUS = 3;
            VALIDATION_RESULT = 7;
            let mut output = 0xdead_beef;
            assert_eq!(storage_backend_sector_size(&mut output), 7);
            assert_eq!(output, 0xdead_beef);
            assert_eq!((STATUS_2_CALLS, STATUS_3_CALLS), (0, 1));
        }
    }
}
