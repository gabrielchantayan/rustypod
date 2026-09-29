//! Apply the control profile mode — original: `FUN_0836e400` @ 0x0836e400.
//!
//! Raw `osos.dec` establishes the exact 28-byte A32 extent
//! `0x0836e400..0x0836e41c`; `0x0836e41c` begins the next wrapper. It has one
//! plain `bl` and no predicated `bl` instructions. The function writes `0x80`
//! to selector 1, then tail-calls the adjacent retail helper at `0x0836e460`
//! with `(0, 3, 2)`.
//!
//! Deliberate deviation: neither retail callee is ported, so the target calls
//! their verified addresses directly; host tests install equivalent operations.
#[derive(Clone, Copy)]

#[cfg(not(target_os = "none"))]
pub struct ControlProfileModeOperations {
    pub write_selector: unsafe extern "C" fn(u32, u32),
    pub apply_mode: unsafe extern "C" fn(u32, u32, u32),
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_write_selector(_: u32, _: u32) {
    panic!("install control profile mode fixture");
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_apply_mode(_: u32, _: u32, _: u32) {
    panic!("install control profile mode fixture");
}

#[cfg(not(target_os = "none"))]
pub static mut CONTROL_PROFILE_MODE_OPERATIONS: ControlProfileModeOperations = ControlProfileModeOperations {
    write_selector: missing_write_selector,
    apply_mode: missing_apply_mode,
};

#[cfg(target_os = "none")]
unsafe fn retail_write_selector(selector: u32, value: u32) {
    unsafe { core::mem::transmute::<usize, unsafe extern "C" fn(u32, u32)>(0x0836_e3c8)(selector, value) };
}

#[cfg(target_os = "none")]
unsafe fn retail_apply_mode(first: u32, second: u32, third: u32) {
    unsafe { core::mem::transmute::<usize, unsafe extern "C" fn(u32, u32, u32)>(0x0836_e460)(first, second, third) };
}

/// Writes the mode flag, then invokes the retail mode-application tail helper.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn control_profile_mode_apply() {
    #[cfg(target_os = "none")]
    unsafe {
        retail_write_selector(1, 0x80);
        retail_apply_mode(0, 3, 2);
    }
    #[cfg(not(target_os = "none"))]
    unsafe {
        let operations = CONTROL_PROFILE_MODE_OPERATIONS;
        (operations.write_selector)(1, 0x80);
        (operations.apply_mode)(0, 3, 2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: [(u32, u32, u32); 2] = [(0, 0, 0); 2];
    static mut CALL_COUNT: usize = 0;

    unsafe fn record(first: u32, second: u32, third: u32) {
        unsafe { CALLS[CALL_COUNT] = (first, second, third); CALL_COUNT += 1; }
    }

    unsafe extern "C" fn write_selector(selector: u32, value: u32) {
        unsafe { record(selector, value, 0); }
    }

    unsafe extern "C" fn apply_mode(first: u32, second: u32, third: u32) {
        unsafe { record(first, second, third); }
    }

    #[test]
    fn writes_mode_flag_before_invoking_fixed_tail_helper_arguments() {
        let _lock = LOCK.lock();
        unsafe {
            CALLS = [(0, 0, 0); 2];
            CALL_COUNT = 0;
            CONTROL_PROFILE_MODE_OPERATIONS = ControlProfileModeOperations { write_selector, apply_mode };
            control_profile_mode_apply();
            assert_eq!(CALL_COUNT, 2);
            assert_eq!(CALLS, [(1, 0x80, 0), (0, 3, 2)]);
        }
    }
}
