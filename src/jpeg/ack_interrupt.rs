//! JPEG interrupt acknowledgement — `FUN_080aabe0` @ 0x080aabe0.
//!
//! True extent: 32 bytes, [0x080aabe0, 0x080aac00): six A32
//! instructions (24 bytes), then literals 0x08a0a79c and 0x39660000.
//! The next real function starts at 0x080aac00. Full-image word decoding
//! finds one plain inbound BL at 0x0807d0d8 and one predicated BLNE at
//! 0x0807d098; zero outgoing plain or predicated BLs. Both callers pass 2.
//! Set decoder state byte +2 to 1, then acknowledge the supplied interrupt
//! mask at 0x39660000. Volatile writes retain the firmware's store order.
//! No algorithmic deviations; hosts substitute storage for the fixed RAM
//! byte and MMIO word. The exact event meaning of state byte +2 is unknown.

#[cfg(not(target_os = "none"))]
pub static mut HOST_INTERRUPT_STATE: [u8; 4] = [0; 4];
#[cfg(not(target_os = "none"))]
pub static mut HOST_INTERRUPT_ACK: u32 = 0;

/// Mark the decoder interrupt observed, then acknowledge `mask` unchanged.
///
/// # Safety
/// The firmware RAM and MMIO locations must be writable. Host callers must
/// serialize access to the stand-in state and acknowledgement register.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn jpeg_ack_interrupt(mask: u32) {
    #[cfg(target_os = "none")]
    let (observed, ack) = (0x08a0_a79e as *mut u8, 0x3966_0000 as *mut u32);
    #[cfg(not(target_os = "none"))]
    let (observed, ack) = (
        core::ptr::addr_of_mut!(HOST_INTERRUPT_STATE).cast::<u8>().add(2),
        core::ptr::addr_of_mut!(HOST_INTERRUPT_ACK),
    );
    core::ptr::write_volatile(observed, 1);
    core::ptr::write_volatile(ack, mask);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_flag_and_mask_without_touching_neighboring_bytes() {
        unsafe {
            for prior in 0..=255u8 {
                for mask in [0, 1, 2, 0x8000_0000, 0x1234_5678, u32::MAX] {
                    HOST_INTERRUPT_STATE = [0xa5, 0x5a, prior, 0xc3];
                    HOST_INTERRUPT_ACK = !mask;
                    jpeg_ack_interrupt(mask);
                    let state = core::ptr::read_volatile(
                        core::ptr::addr_of!(HOST_INTERRUPT_STATE));
                    let ack = core::ptr::read_volatile(
                        core::ptr::addr_of!(HOST_INTERRUPT_ACK));
                    assert_eq!(state, [0xa5, 0x5a, 1, 0xc3]);
                    assert_eq!(ack, mask);
                    jpeg_ack_interrupt(mask);
                    assert_eq!(core::ptr::read_volatile(
                        core::ptr::addr_of!(HOST_INTERRUPT_STATE)), state);
                    assert_eq!(core::ptr::read_volatile(
                        core::ptr::addr_of!(HOST_INTERRUPT_ACK)), mask);
                }
            }
        }
    }
}
