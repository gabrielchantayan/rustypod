//! Disk-I/O drive-readiness argument adapter.
//!
//! `FUN_082c3174` at load address `0x082c3174`, exactly 12 bytes through
//! `0x082c317c`; the independent shared-counter function starts at `0x082c3180`.
//! Whole-image aligned A32 decoding finds two inbound plain BL calls at
//! `0x082c626c` and `0x082c6318`, no predicated BL calls, and no outbound BL.
//! Raw words are `e1a02001 e3a01000 eaffffbc`: preserve the device in r0,
//! move the caller's readiness flags from r1 to r2, set r1 to zero, and
//! tail-transfer to the shared readiness body at `0x082c3074`.
//!
//! Deliberate deviations: Rust expresses the transfer as a C-ABI call to the
//! verified resident body, which remains unported. LLVM may use an indirect
//! call rather than the retail tail branch. Host builds inject that body;
//! they do not emulate its private firmware state. No flags or return values
//! are normalized and no device-range check is added.

#[cfg(not(target_os = "none"))]
type ReadinessBody = unsafe extern "C" fn(u32, u32, u32) -> u32;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_body(_device: u32, _mode: u32, _flags: u32) -> u32 {
    panic!("drive readiness body called without a host seam")
}

#[cfg(not(target_os = "none"))]
static mut HOST_BODY: ReadinessBody = unavailable_body;

/// Checks disk-I/O readiness through the resident shared body.
///
/// # Safety
/// The device index and firmware drive-table state must satisfy the resident
/// body's contract; like retailOS, this adapter does not validate the index.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn disk_drive_ready(device: u32, flags: u32) -> u32 {
    #[cfg(target_os = "none")]
    let body: unsafe extern "C" fn(u32, u32, u32) -> u32 =
        core::mem::transmute(0x082c_3074usize);
    #[cfg(not(target_os = "none"))]
    let body = core::ptr::read_volatile(core::ptr::addr_of!(HOST_BODY));
    body(device, 0, flags)
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut CALL: (u32, u32, u32) = (0, 0, 0);
    static mut RESULT: u32 = 0;

    unsafe extern "C" fn resident_body(device: u32, mode: u32, flags: u32) -> u32 {
        CALL = (device, mode, flags);
        RESULT
    }

    struct Reset(ReadinessBody);
    impl Drop for Reset {
        fn drop(&mut self) {
            unsafe { HOST_BODY = self.0; }
        }
    }

    #[test]
    fn preserves_full_width_flags_indices_and_resident_results() {
        let _lock = LOCK.lock();
        unsafe {
            let _reset = Reset(HOST_BODY);
            HOST_BODY = resident_body;
            for device in [0, 3, 4, u32::MAX] {
                for flags in [0, 1, 0x8000_0000, u32::MAX] {
                    for result in [0, 1, 0x8000_0000, u32::MAX] {
                        RESULT = result;
                        assert_eq!(disk_drive_ready(device, flags), result);
                        let call = core::ptr::read(core::ptr::addr_of!(CALL));
                        assert_eq!(call, (device, 0, flags));
                    }
                }
            }
        }
    }
}
