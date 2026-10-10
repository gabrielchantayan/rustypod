//! Wheel-change pending notification for the retail wheel input service.

#[cfg(target_os = "none")]
const WHEEL_CHANGE_PENDING: *mut u8 = 0x089c_a550 as *mut u8;

#[cfg(not(target_os = "none"))]
static mut WHEEL_CHANGE_PENDING: *mut u8 = core::ptr::null_mut();

#[cfg(not(target_os = "none"))]
static mut WHEEL_CHANGE_DISPATCH: Option<unsafe extern "C" fn()> = None;

/// wheel_change_notify — original `FUN_08087830` @ 0x08087830.
/// True extent: 20 bytes [0x08087830,0x08087844): 16 instruction bytes
/// plus the pending-byte literal at 0x08087840. Whole-image aligned A32
/// decoding verifies zero plain BL callers and two predicated BLEQ callers
/// (0x0809e5e0, 0x0809e610); the body contains no BL, only a tail B.
///
/// Unconditionally set the wheel-change pending byte to 1, then invoke
/// the existing wheel input dispatch at 0x080618d0. That routine either
/// latches wheel samples when [0x089ca864+2] is zero or enqueues a
/// `Weel` message with two zero payload words otherwise. It remains an
/// unported firmware dependency;
/// this function does not duplicate its implementation or infer arguments
/// from Ghidra's incorrectly expanded decompilation. Callers use no return.
/// Deliberate deviations: volatile byte store preserves publication before
/// dispatch; host builds inject the pending-byte pointer and dispatch.
///
/// # Safety
/// Firmware wheel globals and the dispatch service must be initialized.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn wheel_change_notify() {
    unsafe { WHEEL_CHANGE_PENDING.write_volatile(1) };
    #[cfg(target_os = "none")]
    {
        let dispatch: unsafe extern "C" fn() = unsafe { core::mem::transmute(0x0806_18d0usize) };
        unsafe { dispatch() };
    }
    #[cfg(not(target_os = "none"))]
    unsafe { WHEEL_CHANGE_DISPATCH.expect("install wheel input dispatch 0x080618d0")() };
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn consume_pending() {
        assert_eq!(unsafe { WHEEL_CHANGE_PENDING.read_volatile() }, 1);
        unsafe { WHEEL_CHANGE_PENDING.write_volatile(0) };
    }

    #[test]
    fn publishes_exactly_one_byte_before_consumption_for_every_prior_value() {
        let mut state = [0xa5, 0, 0x5a];
        unsafe {
            WHEEL_CHANGE_PENDING = state.as_mut_ptr().add(1);
            WHEEL_CHANGE_DISPATCH = Some(consume_pending);
            for previous in 0..=u8::MAX {
                state[1] = previous;
                wheel_change_notify();
                assert_eq!(state, [0xa5, 0, 0x5a]);
                // A consumer clearing the byte must not suppress the next publication.
                wheel_change_notify();
                assert_eq!(state, [0xa5, 0, 0x5a]);
            }
            WHEEL_CHANGE_PENDING = core::ptr::null_mut();
            WHEEL_CHANGE_DISPATCH = None;
        }
    }
}
