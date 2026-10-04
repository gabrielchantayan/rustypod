//! Optional backend request with boolean result normalization.
//!
//! `optional_backend_request` — `FUN_081fcf98` @ `0x081fcf98`.
//! True extent: 48 bytes [0x081fcf98, 0x081fcfc8); the next function
//! begins with push. Raw A32 decoding: two inbound plain BLs at 0x082085ec
//! and 0x0822c19c, no predicated inbound BLs; one outbound plain BL at
//! 0x081fcfb4 to 0x081f1244, no predicated outbound BLs.
//! Read backend at +0x10, succeed if absent, otherwise forward request and
//! mode plus two 0xffffffff arguments and normalize the helper result.
//! Raw helper words verify five inputs: it dispatches through backend +0x48,
//! vtable +0x18, with an output-byte pointer inserted before mode, and may
//! notify via 0x081f0888. Ghidra omitted the wrapper's r1/r2 inputs.
//! No target behavioral deviations. Host builds widen only the backend
//! pointer; the request helper is the ported lifecycle request dispatcher.

use super::signed_backend_adjust::BackendAdjustmentState;

use super::context_lifecycle_request::context_lifecycle_request;

/// # Safety
/// `state` must be readable; its non-null backend and request arguments must
/// satisfy the firmware helper's object and virtual-dispatch contracts.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn optional_backend_request(state: *const BackendAdjustmentState, request: u32, mode: u32) -> u32 {
    let backend = (*state).backend;
    if backend.is_null() {
        return 1;
    }
    (context_lifecycle_request(backend, request, mode, u32::MAX, u32::MAX) != 0) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_backend_succeeds_but_absent_lifecycle_object_fails() {
        let absent = BackendAdjustmentState { prefix: [u32::MAX; 4], backend: core::ptr::null_mut() };
        assert_eq!(unsafe { optional_backend_request(&absent, u32::MAX, u32::MAX) }, 1);
        let mut context = [0u64; 16];
        let state = BackendAdjustmentState { prefix: [0; 4], backend: context.as_mut_ptr().cast() };
        assert_eq!(unsafe { optional_backend_request(&state, 0, 1) }, 0);
    }
}
