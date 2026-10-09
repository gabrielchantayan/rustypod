//! UI binding transfer parameter application — thunk_FUN_080f7d4c @ 0x080f80b0.
//!
//! True extent: 4 bytes, 0x080f80b0..0x080f80b4; the next function starts
//! at 0x080f80b4. Whole-image A32 decoding finds two plain inbound BLs
//! (0x081f4824, 0x081f487c), zero predicated inbound BLs, and no outbound
//! BLs. The sole word eaffff25 branches to 0x080f7d4c, which loads the
//! unsigned controller at binding+0x0f and signed channel at binding+0x10,
//! then tail-dispatches with the unchanged parameter through 0x08038000.
//! That veneer contains e51ff004 and literal 0x220086c4: the IRAM mirror
//! of osos 0x080086c4, not mask ROM. The backend selects the I2S transfer
//! handle and returns 0x11 for an empty slot, otherwise 0 or 0x1f.
//! Deliberate deviations: inline the register/byte adapter and call the
//! verified IRAM target directly. Preserve its u32 status despite Ghidra's
//! void signature. No identity or units are asserted for the parameter.

pub type BindingTransferParameterCore = unsafe extern "C" fn(u32, i32, u32) -> u32;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_core(controller: u32, channel: i32, parameter: u32) -> u32 {
    let apply: BindingTransferParameterCore = core::mem::transmute(0x2200_86c4usize);
    apply(controller, channel, parameter)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_core(_controller: u32, _channel: i32, _parameter: u32) -> u32 {
    panic!("binding_transfer_parameter_apply requires retailOS core 0x220086c4")
}

/// Verified raw backend ABI; host callers must install an implementation.
pub static mut BINDING_TRANSFER_PARAMETER_CORE: BindingTransferParameterCore = firmware_core;

/// Apply a parameter to the transfer selected by the binding's byte fields.
///
/// # Safety
/// `binding` must be readable through byte +0x10. Its controller/channel must
/// select a valid firmware table cell, and the installed backend must obey
/// the observed ABI. Concurrent mutation of the backend is not permitted.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn binding_transfer_parameter_apply(binding: *const u8, parameter: u32) -> u32 {
    let channel = binding.add(0x10).cast::<i8>().read() as i32;
    let controller = binding.add(0x0f).read() as u32;
    BINDING_TRANSFER_PARAMETER_CORE(controller, channel, parameter)
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn reference_backend(controller: u32, channel: i32, parameter: u32) -> u32 {
        // A small bounded transfer table makes sign/zero extension observable
        // through selection and error handling, rather than callback echoes.
        if controller != 255 || channel < -128 || channel > -126 {
            return 0x11;
        }
        let handles = [0u32, 0x1234, 0x5678];
        let handle = handles[(channel + 128) as usize];
        if handle == 0 { 0x11 } else if parameter == u32::MAX { 0x1f } else { 0 }
    }

    #[test]
    fn signed_channel_unsigned_controller_and_backend_status() {
        unsafe {
            let saved = BINDING_TRANSFER_PARAMETER_CORE;
            BINDING_TRANSFER_PARAMETER_CORE = reference_backend;
            let mut binding = [0xa5u8; 17];
            binding[15] = 255;
            for (channel, parameter, expected) in [
                (0x80, 0, 0x11), (0x81, 0, 0), (0x82, u32::MAX, 0x1f),
                (0x7f, 200, 0x11), (0xff, 200, 0x11),
            ] {
                binding[16] = channel;
                let before = binding;
                assert_eq!(binding_transfer_parameter_apply(binding.as_ptr(), parameter), expected);
                assert_eq!(binding, before);
            }
            binding[15] = 0;
            binding[16] = 0x81;
            assert_eq!(binding_transfer_parameter_apply(binding.as_ptr(), 0), 0x11);
            BINDING_TRANSFER_PARAMETER_CORE = saved;
        }
    }
}
