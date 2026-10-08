//! Audio output controller register initialization.
//!
//! Original: `FUN_081083b8` @ `0x081083b8`, true size 76 bytes:
//! 72 instruction bytes plus the `0x00010001` literal at `0x08108400`.
//! Next function starts at `0x08108404` with `tst r1,#0x80`.
//! Raw A32 scan verifies two plain inbound BLs, zero predicated inbound
//! BLs, and zero outgoing BLs of either kind.
//!
//! Writes all ones to ten controller words, then 9 to offsets 0x810 and
//! 0x814, and 0x00010001 to offset 0x81c, in retail order. Callers pass an
//! output object, but the body overwrites r0 before using it.
//! Individual register bit meanings remain unidentified.
//!
//! Deliberate deviations: volatile stores model MMIO; host builds substitute
//! an isolated word array for the hardware register block.

use core::ptr;

#[cfg(not(target_os = "none"))]
static mut HOST_REGISTERS: [u32; 0xc00 / 4] = [0; 0xc00 / 4];

#[inline(always)]
fn registers() -> *mut u32 {
    #[cfg(target_os = "none")]
    { 0x3840_0000 as *mut u32 }
    #[cfg(not(target_os = "none"))]
    { ptr::addr_of_mut!(HOST_REGISTERS).cast::<u32>() }
}

/// Initializes the fixed audio output controller register sequence.
///
/// # Safety
/// On target, the controller must be accessible and writes must be serialized
/// with other users of this peripheral. `output` is never dereferenced.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn audio_output_registers_initialize(_output: *mut u8) {
    let base = registers();
    ptr::write_volatile(base.add(0x908 / 4), u32::MAX);
    ptr::write_volatile(base.add(0xb08 / 4), u32::MAX);
    ptr::write_volatile(base.add(0x928 / 4), u32::MAX);
    ptr::write_volatile(base.add(0xb48 / 4), u32::MAX);
    ptr::write_volatile(base.add(0x968 / 4), u32::MAX);
    ptr::write_volatile(base.add(0xb88 / 4), u32::MAX);
    ptr::write_volatile(base.add(0x9a8 / 4), u32::MAX);
    ptr::write_volatile(base.add(0xba8 / 4), u32::MAX);
    ptr::write_volatile(base.add(0x9c8 / 4), u32::MAX);
    ptr::write_volatile(base.add(0xbc8 / 4), u32::MAX);
    ptr::write_volatile(base.add(0x810 / 4), 9);
    ptr::write_volatile(base.add(0x814 / 4), 9);
    ptr::write_volatile(base.add(0x81c / 4), 0x0001_0001);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_only_selected_words_and_ignores_output_pointer() {
        unsafe {
            for initial in [0, u32::MAX, 0xa55a_1234] {
                for output in [ptr::null_mut(), 1usize as *mut u8] {
                    HOST_REGISTERS = [initial; 0xc00 / 4];
                    audio_output_registers_initialize(output);
                    let base = registers();
                    for word in 0..0xc00 / 4 {
                        let expected = match word * 4 {
                            0x908 | 0xb08 | 0x928 | 0xb48 | 0x968 | 0xb88 |
                            0x9a8 | 0xba8 | 0x9c8 | 0xbc8 => u32::MAX,
                            0x810 | 0x814 => 9,
                            0x81c => 0x0001_0001,
                            _ => initial,
                        };
                        assert_eq!(ptr::read_volatile(base.add(word)), expected,
                                   "register offset {:#x}", word * 4);
                    }
                }
            }
        }
    }
}
