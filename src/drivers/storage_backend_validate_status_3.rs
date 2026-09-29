//! `storage_backend_validate_status_3` — retailOS `FUN_08369da8` at load
//! address `0x08369da8`.
//!
//! True extent: 64 bytes (`0x08369da8..0x08369de7`), ending at `bx lr`; the
//! `"Ide1"` literal pool is at `0x08369de8`, and the next independently entered
//! function begins at `0x08369dec`. Raw decoding finds no outgoing `BL` calls,
//! two incoming plain unconditional `BL` calls (`0x080e70b8`, `0x082bcbfc`),
//! and no incoming predicated `BL` calls.
//!
//! A non-null backend with the `"Ide1"` tag at +0 and a nonzero word at +0x44
//! is accepted: when requested, its +8 payload address is written to
//! `validated`, and the function returns zero. All other backends return 7.
//! Deliberate deviations: a firmware-only `mov r12, r12` keeps this separately
//! exported BL target from folding into the identical status-2 validator; host
//! builds retain the target ABI's `u32` output pointer value, truncating the
//! host address because firmware pointers are 32-bit.

const IDE1_TAG: u32 = 0x3165_6449;
const PAYLOAD_OFFSET: usize = 8;
const READY_OFFSET: usize = 0x44;
const STATUS_INVALID: u32 = 7;

/// Validates a ready `Ide1` storage backend and optionally returns its payload.
///
/// # Safety
///
/// A non-null `backend` must be readable through its aligned word at `+0x44`.
/// A non-null `validated` must be writable as one target-width word.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn storage_backend_validate_status_3(
    backend: *const u8,
    validated: *mut u32,
) -> u32 {
    #[cfg(target_os = "none")]
    core::arch::asm!("mov r12, r12", options(nostack, preserves_flags));

    if backend.is_null()
        || (backend as *const u32).read() != IDE1_TAG
        || (backend.add(READY_OFFSET) as *const u32).read() == 0
    {
        return STATUS_INVALID;
    }

    if !validated.is_null() {
        validated.write(backend.add(PAYLOAD_OFFSET) as usize as u32);
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_backend_is_invalid_without_writing_output() {
        let mut validated = 0xdead_beef;
        unsafe {
            assert_eq!(storage_backend_validate_status_3(core::ptr::null(), &mut validated), STATUS_INVALID);
        }
        assert_eq!(validated, 0xdead_beef);
    }

    #[test]
    fn wrong_tag_or_unready_backend_is_invalid() {
        let mut backend = [0u32; 18];
        let mut validated = 0xdead_beef;
        backend[READY_OFFSET / 4] = 1;
        unsafe {
            assert_eq!(storage_backend_validate_status_3(backend.as_ptr().cast(), &mut validated), STATUS_INVALID);
        }
        assert_eq!(validated, 0xdead_beef);

        backend[0] = IDE1_TAG;
        backend[READY_OFFSET / 4] = 0;
        unsafe {
            assert_eq!(storage_backend_validate_status_3(backend.as_ptr().cast(), &mut validated), STATUS_INVALID);
        }
        assert_eq!(validated, 0xdead_beef);
    }

    #[test]
    fn ready_tagged_backend_returns_payload_address() {
        let mut backend = [0u32; 18];
        backend[0] = IDE1_TAG;
        backend[READY_OFFSET / 4] = 1;
        let mut validated = 0;
        unsafe {
            assert_eq!(storage_backend_validate_status_3(backend.as_ptr().cast(), &mut validated), 0);
        }
        assert_eq!(validated, backend.as_ptr().cast::<u8>().wrapping_add(PAYLOAD_OFFSET) as usize as u32);
    }

    #[test]
    fn ready_tagged_backend_accepts_null_output() {
        let mut backend = [0u32; 18];
        backend[0] = IDE1_TAG;
        backend[READY_OFFSET / 4] = 1;
        unsafe {
            assert_eq!(storage_backend_validate_status_3(backend.as_ptr().cast(), core::ptr::null_mut()), 0);
        }
    }
}
