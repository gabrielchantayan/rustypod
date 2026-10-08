//! Controller configuration restore and enable.
//!
//! Original: `FUN_08107d00` @ `0x08107d00`, true size 60 bytes: 56 bytes
//! of instructions and literal `0xa01c1806` at `0x08107d38`; the next real
//! function starts at `0x08107d3c` with `push {r4, lr}`.
//! Raw A32 decoding verifies two plain inbound BLs (0x08107878, 0x08108250),
//! zero predicated inbound BLs, and zero outgoing BLs of either kind.
//!
//! Defaults the object's configuration word at +0x8c when zero, writes it
//! to controller offset 0x18, rereads that register and writes the default
//! if it reads zero, then sets control bit 0 at offset 0x08. The register
//! bit meanings remain unidentified. Deliberate deviations: volatile MMIO
//! accesses preserve readback and ordering; host uses isolated registers.

use core::ptr;

const DEFAULT_CONFIGURATION: u32 = 0xa01c_1806;
const CONFIGURATION_WORD: usize = 0x8c / 4;

#[cfg(not(target_os = "none"))]
static mut HOST_REGISTERS: [u32; 7] = [0; 7];

#[inline(always)]
fn registers() -> *mut u32 {
    #[cfg(target_os = "none")]
    { 0x3840_0000 as *mut u32 }
    #[cfg(not(target_os = "none"))]
    { ptr::addr_of_mut!(HOST_REGISTERS).cast::<u32>() }
}

#[inline(always)]
unsafe fn restore_configuration(output: *mut u32, base: *mut u32) {
    let configuration = output.add(CONFIGURATION_WORD);
    if ptr::read(configuration) == 0 {
        ptr::write(configuration, DEFAULT_CONFIGURATION);
    }
    ptr::write_volatile(base.add(0x18 / 4), ptr::read(configuration));
    if ptr::read_volatile(base.add(0x18 / 4)) == 0 {
        ptr::write_volatile(base.add(0x18 / 4), DEFAULT_CONFIGURATION);
    }
    let control = base.add(0x08 / 4);
    ptr::write_volatile(control, ptr::read_volatile(control) | 1);
}

/// Restores the saved controller configuration and sets control bit zero.
///
/// # Safety
/// `output` must be word-aligned and readable/writable through offset 0x8f.
/// Controller register access must be valid and serialized on target; host
/// callers must likewise serialize access to this module's register fixture.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn controller_configuration_enable(output: *mut u32) {
    restore_configuration(output, registers());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_zero_and_preserves_saved_values_and_other_words() {
        for saved in [0, 1, 0x8000_0000, u32::MAX, 0x1357_2468] {
            for control in [0, 1, 0x8000_0000, u32::MAX, 0xa55a_1234] {
                let mut output = [0xdead_beef; CONFIGURATION_WORD + 2];
                output[CONFIGURATION_WORD] = saved;
                let mut base = [0x2468_1357; 8];
                base[2] = control;
                let mut expected_output = output;
                let expected_configuration = if saved == 0 {
                    DEFAULT_CONFIGURATION
                } else {
                    saved
                };
                expected_output[CONFIGURATION_WORD] = expected_configuration;
                let mut expected_base = base;
                expected_base[2] = control | 1;
                expected_base[6] = expected_configuration;
                unsafe { restore_configuration(output.as_mut_ptr(), base.as_mut_ptr()) };
                assert_eq!(output, expected_output);
                assert_eq!(base, expected_base);
                // Re-enabling must not reset a nonzero saved configuration.
                unsafe { restore_configuration(output.as_mut_ptr(), base.as_mut_ptr()) };
                assert_eq!(output, expected_output);
                assert_eq!(base, expected_base);
            }
        }
    }
}
