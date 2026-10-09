//! Object-based I2S enable/disable wrapper.
//!
//! Original: `FUN_080f8160` @ 0x080f8160, 8 bytes, ending at the next
//! function's push at 0x080f8168. Full-image A32 decoding verifies two
//! inbound plain BLs (0x081f4830, 0x081f4888), zero predicated BLs.
//! Loads the unsigned controller byte at object + 0x1d and tail-calls
//! 0x08038028, whose raw veneer resolves to IRAM 0x2200881c (the relocated
//! 0x0800881c I2S enable/disable routine). Preserves r1 and returns r0.
//! Deliberate deviation: host builds inject the hardware boundary; target
//! builds call the original IRAM routine. No controller validation is added.

pub type I2sEnableCore = unsafe extern "C" fn(u32, u32) -> u32;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_i2s_enable_core(_controller: u32, _enable: u32) -> u32 {
    panic!("i2s_object_set_enabled requires retailOS IRAM core 0x2200881c")
}

#[cfg(not(target_os = "none"))]
pub static mut I2S_ENABLE_CORE: I2sEnableCore = missing_i2s_enable_core;

/// Set the selected object's I2S controller state; zero disables, nonzero enables.
///
/// # Safety
/// `object + 0x1d` must be readable. The controller must satisfy the original
/// hardware routine's requirements; host callers must install its boundary.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn i2s_object_set_enabled(object: *const u8, enable: u32) -> u32 {
    let controller = object.add(0x1d).read() as u32;
    #[cfg(target_os = "none")]
    let core: I2sEnableCore = core::mem::transmute(0x2200_881cusize);
    #[cfg(not(target_os = "none"))]
    let core = I2S_ENABLE_CORE;
    core(controller, enable)
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn reference_boundary(controller: u32, enable: u32) -> u32 {
        // Distinguish unsigned byte extraction, unmodified r1, and returned r0.
        controller.rotate_left(24) ^ enable
    }

    #[test]
    fn unsigned_controller_and_full_width_enable_match_raw_wrapper() {
        unsafe {
            let saved = I2S_ENABLE_CORE;
            I2S_ENABLE_CORE = reference_boundary;
            for alignment in 0..4 {
                let mut object = [0xa5u8; 34];
                for controller in [0u8, 1, 2, 0x7f, 0x80, 0xff] {
                    object[alignment + 0x1d] = controller;
                    for enable in [0, 1, 2, 0x8000_0000, u32::MAX] {
                        let expected = (controller as u32).rotate_left(24) ^ enable;
                        assert_eq!(i2s_object_set_enabled(object.as_ptr().add(alignment), enable), expected);
                    }
                }
            }
            I2S_ENABLE_CORE = saved;
        }
    }
}
