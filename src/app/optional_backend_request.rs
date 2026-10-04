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
//! pointer and substitute the verified, unported firmware helper.

use super::signed_backend_adjust::BackendAdjustmentState;

pub type BackendRequest = unsafe extern "C" fn(*mut u8, u32, u32, u32, u32) -> u32;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_backend_request(_: *mut u8, _: u32, _: u32, _: u32, _: u32) -> u32 {
    panic!("install optional backend request host seam")
}

#[cfg(not(target_os = "none"))]
pub static mut OPTIONAL_BACKEND_REQUEST: BackendRequest = missing_backend_request;

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
    #[cfg(target_os = "none")]
    let dispatch: BackendRequest = core::mem::transmute(0x081f_1244usize);
    #[cfg(not(target_os = "none"))]
    let dispatch = core::ptr::addr_of!(OPTIONAL_BACKEND_REQUEST).read_volatile();
    (dispatch(backend, request, mode, u32::MAX, u32::MAX) != 0) as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    struct Selection { selected: u32, limit: u32, success: u32 }

    unsafe extern "C" fn select(backend: *mut u8, request: u32, mode: u32, lower: u32, upper: u32) -> u32 {
        let selection = &mut *backend.cast::<Selection>();
        if mode != 1 || lower != u32::MAX || upper != u32::MAX || request > selection.limit {
            return 0;
        }
        selection.selected = request;
        selection.success
    }

    struct Restore(BackendRequest);
    impl Drop for Restore {
        fn drop(&mut self) { unsafe { OPTIONAL_BACKEND_REQUEST = self.0; } }
    }

    #[test]
    fn absent_backend_succeeds_and_present_backend_normalizes_results() {
        let _lock = LOCK.lock();
        let _restore = unsafe { let old = OPTIONAL_BACKEND_REQUEST; OPTIONAL_BACKEND_REQUEST = select; Restore(old) };
        let absent = BackendAdjustmentState { prefix: [u32::MAX; 4], backend: core::ptr::null_mut() };
        assert_eq!(unsafe { optional_backend_request(&absent, u32::MAX, u32::MAX) }, 1);
        for success in [0, 1, 7, 0x8000_0000, u32::MAX] {
            for limit in [0, 17, u32::MAX] {
                for request in [0, 17, 18, 0x8000_0000, u32::MAX] {
                    for mode in [0, 1, 2, u32::MAX] {
                        let mut selection = Selection { selected: 9, limit, success };
                        let state = BackendAdjustmentState { prefix: [0; 4], backend: (&mut selection as *mut Selection).cast() };
                        let accepted = mode == 1 && request <= limit;
                        assert_eq!(unsafe { optional_backend_request(&state, request, mode) }, (accepted && success != 0) as u32);
                        assert_eq!(selection.selected, if accepted { request } else { 9 });
                    }
                }
            }
        }
    }
}
