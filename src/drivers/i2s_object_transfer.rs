//! Object-based I2S transfer endpoint selection.
//!
//! Original: `FUN_080f8130` @ 0x080f8130, 48 bytes; next real function
//! starts at 0x080f8160. Raw A32 decoding finds two incoming plain BLs
//! (0x081f480c, 0x081f4864), no predicated incoming BLs, and zero outgoing
//! BLs. Mode byte +0x1e selects (endpoint, controller) for mode 0 or
//! (controller, endpoint) for mode 1, then tail-branches to 0x080f7dd4
//! with the transfer word in r3. Other modes return the unchanged r0.
//! Deliberate deviation: host builds inject the existing configuration
//! boundary; target builds retain the original routine. Ghidra incorrectly
//! includes that routine's stores and hardware call in this selector.

pub type I2sTransferConfigure = unsafe extern "C" fn(*mut u8, u32, u32, u32) -> usize;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_transfer_configure(_: *mut u8, _: u32, _: u32, _: u32) -> usize {
    panic!("i2s_object_select_transfer requires retailOS routine 0x080f7dd4")
}

#[cfg(not(target_os = "none"))]
pub static mut I2S_TRANSFER_CONFIGURE: I2sTransferConfigure = missing_transfer_configure;

/// Select transfer endpoints and configure the object's I2S transfer.
///
/// # Safety
/// `object + 0x1e` must be readable. For modes 0 and 1, the object must be
/// word-aligned and writable through +0x0c, with readable configuration
/// bytes at +0x0f, +0x10 and +0x1c, and valid hardware transfer arguments.
/// Host callers must install the configuration boundary.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn i2s_object_select_transfer(object: *mut u8, transfer: u32, endpoint: u32) -> usize {
    let mode = object.add(0x1e).read();
    if mode > 1 {
        return object as usize;
    }
    let controller = object.add(0x1c).read() as u32;
    let (first, second) = if mode == 0 { (endpoint, controller) } else { (controller, endpoint) };
    #[cfg(target_os = "none")]
    let configure: I2sTransferConfigure = core::mem::transmute(0x080f_7dd4usize);
    #[cfg(not(target_os = "none"))]
    let configure = I2S_TRANSFER_CONFIGURE;
    configure(object, first, second, transfer)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Model the verified state transition of 0x080f7dd4, leaving hardware
    // access outside the host test. The selector itself must not clear state
    // before this routine sees it.
    unsafe extern "C" fn configure_reference(object: *mut u8, first: u32, second: u32, transfer: u32) -> usize {
        assert_eq!(object.add(12).read(), 0xa5);
        let words = object.cast::<u32>();
        words.write(first);
        words.add(1).write(second);
        words.add(2).write(transfer);
        object.add(12).write(0);
        0
    }

    #[test]
    fn selection_and_invalid_modes_preserve_original_state_transition() {
        unsafe {
            let saved = I2S_TRANSFER_CONFIGURE;
            I2S_TRANSFER_CONFIGURE = configure_reference;
            for mode in 0..=255u8 {
                for controller in [0u8, 1, 0x80, 0xff] {
                    for endpoint in [0, 0x8000_0000, u32::MAX] {
                        let mut words = [0xa5a5_a5a5u32; 8];
                        let object = words.as_mut_ptr().cast::<u8>();
                        object.add(28).write(controller);
                        object.add(30).write(mode);
                        let before = words;
                        let result = i2s_object_select_transfer(object, 0xdead_beef, endpoint);
                        if mode > 1 {
                            assert_eq!(result, object as usize);
                            assert_eq!(words, before);
                        } else {
                            let mut expected = before;
                            expected[0] = if mode == 0 { endpoint } else { controller as u32 };
                            expected[1] = if mode == 0 { controller as u32 } else { endpoint };
                            expected[2] = 0xdead_beef;
                            expected[3] &= 0xffff_ff00;
                            assert_eq!(words, expected);
                            assert_eq!(result, 0);
                        }
                    }
                }
            }
            I2S_TRANSFER_CONFIGURE = saved;
        }
    }
}
