//! Query bit 21 of a selected audio output channel register.
//!
//! Original: `FUN_08107364` @ 0x08107364, true size 40 bytes, ending
//! at the next function's LDR at 0x0810738c. Raw aligned A32 decoding
//! verifies two plain inbound BLs (0x082930a4, 0x08293c8c), zero predicated
//! inbound BLs, and zero outbound calls.
//!
//! Selector bit 7 chooses bank 0x900 when set, 0xb00 otherwise. Bits 0..6
//! select a 0x20-byte channel stride; higher bits are ignored. Read the
//! aligned word at 0x38400000 + bank + stride and return bit 21 as 0 or 1.
//! The output object in r0 is unused; the hardware bit's meaning is unknown.
//!
//! Deliberate deviations: volatile MMIO read; host builds substitute an
//! isolated register array covering the complete masked selector range.

use core::ptr;

#[cfg(not(target_os = "none"))]
static mut HOST_REGISTERS: [u32; 0x1b00 / 4] = [0; 0x1b00 / 4];

#[inline(always)]
fn registers() -> *mut u32 {
    #[cfg(target_os = "none")]
    { 0x3840_0000 as *mut u32 }
    #[cfg(not(target_os = "none"))]
    { ptr::addr_of_mut!(HOST_REGISTERS).cast::<u32>() }
}

/// Returns channel register bit 21, normalized to zero or one.
///
/// # Safety
/// The selected peripheral register must be readable. `output` is ignored
/// and need not point to a valid object. Host callers must serialize access.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn audio_output_channel_status_bit21(_output: *mut u8, selector: u32) -> u32 {
    let bank = if selector & 0x80 == 0 { 0xb00 } else { 0x900 };
    let offset = bank + ((selector & 0x7f) << 5);
    (ptr::read_volatile(registers().add(offset as usize / 4)) >> 21) & 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_selector_selects_banks_and_normalizes_only_bit21() {
        unsafe {
            for selector in 0..256u32 {
                // Independent byte-selector reference, including both extreme channels.
                let offset = if selector < 128 { 0xb00 + selector * 32 }
                             else { 0x900 + (selector - 128) * 32 };
                for value in [0, 1 << 20, 1 << 21, 1 << 22, u32::MAX, !(1 << 21)] {
                    for word in 0..0x1b00 / 4 {
                        ptr::write(registers().add(word), !value);
                    }
                    ptr::write(registers().add(offset as usize / 4), value);
                    for high in [0, 0x100, 0x8000_0000, 0xffff_ff00] {
                        for output in [ptr::null_mut(), usize::MAX as *mut u8] {
                            assert_eq!(audio_output_channel_status_bit21(output, selector | high),
                                       u32::from(value & 0x20_0000 != 0),
                                       "selector {:#x}, value {:#x}", selector | high, value);
                        }
                    }
                    for word in 0..0x1b00 / 4 {
                        let expected = if word == offset as usize / 4 { value } else { !value };
                        assert_eq!(ptr::read(registers().add(word)), expected);
                    }
                }
            }
        }
    }
}
