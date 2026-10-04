//! Signed adjustment of an optional backend.
//!
//! `signed_backend_adjust` — original `FUN_081fcfc8` @ `0x081fcfc8`.
//! Raw extent: 64 bytes, [0x081fcfc8, 0x081fd008), where the next push
//! starts another function. Whole-image A32 word decoding finds two incoming
//! plain BLs (0x082085fc, 0x0822c1ac), zero predicated incoming BLs; one
//! outgoing plain BL (0x081fcff4 -> 0x081f134c), zero predicated outgoing BLs.
//!
//! Read the optional backend at +0x10. If absent, return one. Otherwise pass
//! direction zero for a negative adjustment, one otherwise, its wrapping
//! unsigned magnitude, and 0xffffffff to the backend; return whether its
//! result is nonzero. The verified unported helper at 0x081f134c forwards
//! direction/magnitude to its +0x48 object's vtable slot +0x1c, supplying an
//! output-byte pointer and the fourth argument on the stack. Its Ghidra
//! one-argument signature is wrong. No target behavioral deviations; host
//! builds widen the backend pointer and replace the firmware call with a seam.

#[repr(C)]
pub struct BackendAdjustmentState {
    pub prefix: [u32; 4],
    pub backend: *mut u8,
}

pub type BackendAdjust = unsafe extern "C" fn(*mut u8, u32, u32, u32) -> u32;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_backend_adjust(_: *mut u8, _: u32, _: u32, _: u32) -> u32 {
    panic!("install signed backend adjustment host seam")
}

#[cfg(not(target_os = "none"))]
pub static mut SIGNED_BACKEND_ADJUST: BackendAdjust = missing_backend_adjust;

/// # Safety
/// `state` must be readable, and its non-null backend must satisfy the
/// firmware helper's object and virtual-dispatch contracts.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn signed_backend_adjust(state: *const BackendAdjustmentState, adjustment: i32) -> u32 {
    let backend = (*state).backend;
    if backend.is_null() {
        return 1;
    }
    let direction = (adjustment >= 0) as u32;
    let magnitude = adjustment.wrapping_abs() as u32;
    #[cfg(target_os = "none")]
    let adjust: BackendAdjust = core::mem::transmute(0x081f_134cusize);
    #[cfg(not(target_os = "none"))]
    let adjust = core::ptr::addr_of!(SIGNED_BACKEND_ADJUST).read_volatile();
    (adjust(backend, direction, magnitude, u32::MAX) != 0) as u32
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());

    struct Position { value: u32, limit: u32, success: u32 }

    unsafe extern "C" fn bounded_adjust(backend: *mut u8, direction: u32, magnitude: u32, _: u32) -> u32 {
        let position = &mut *backend.cast::<Position>();
        let next = if direction == 0 {
            position.value.checked_sub(magnitude)
        } else {
            position.value.checked_add(magnitude)
        };
        match next {
            Some(next) if next <= position.limit => {
                position.value = next;
                position.success
            }
            _ => 0,
        }
    }

    struct Restore(BackendAdjust);
    impl Drop for Restore {
        fn drop(&mut self) { unsafe { SIGNED_BACKEND_ADJUST = self.0; } }
    }

    #[test]
    fn signed_adjustments_preserve_boundaries_and_normalize_success() {
        let _lock = LOCK.lock();
        let _restore = unsafe { let old = SIGNED_BACKEND_ADJUST; SIGNED_BACKEND_ADJUST = bounded_adjust; Restore(old) };
        for success in [1, 7, 0x8000_0000, u32::MAX] {
            for initial in [0, 1, 0x7fff_ffff, 0x8000_0000, u32::MAX] {
                for adjustment in [i32::MIN, -i32::MAX, -1, 0, 1, i32::MAX] {
                    let mut position = Position { value: initial, limit: u32::MAX, success };
                    let state = BackendAdjustmentState { prefix: [0; 4], backend: (&mut position as *mut Position).cast() };
                    let expected = initial as i64 + adjustment as i64;
                    let valid = (0..=u32::MAX as i64).contains(&expected);
                    assert_eq!(unsafe { signed_backend_adjust(&state, adjustment) }, valid as u32);
                    assert_eq!(position.value, if valid { expected as u32 } else { initial });
                }
            }
        }
        let state = BackendAdjustmentState { prefix: [u32::MAX; 4], backend: core::ptr::null_mut() };
        for adjustment in [i32::MIN, -1, 0, 1, i32::MAX] {
            assert_eq!(unsafe { signed_backend_adjust(&state, adjustment) }, 1);
        }
        assert_eq!(core::mem::offset_of!(BackendAdjustmentState, backend), 0x10);
    }
}
