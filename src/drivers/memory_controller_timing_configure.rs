//! Memory controller timing register setup.
//!
//! Original: `FUN_08002420` @ `0x08002420`, true size 44 bytes, ending
//! with BX LR at 0x08002448 before the next PUSH at 0x0800244c.
//! Raw aligned A32 scan: two plain inbound BLs (0x08002194, 0x0800249c),
//! zero predicated inbound BLs; zero outgoing BLs of either kind.
//!
//! Clears controller offset 0xf0, writes 0x41000 plus the low 32 bits of
//! frequency * 64000 shifted logically right by 13 to offset 8, then
//! writes 0x1fb621 to offset 0x10. Literals at 0x080025e8/0x080025ec
//! establish the fixed base 0x38100000 and final register value.
//! Callers supply a clock ratio via the division veneer at 0x08003510;
//! individual register bit meanings remain unidentified.
//!
//! Deliberate deviations: volatile stores model MMIO; host builds use an
//! isolated register array. No range checks or wider multiplication.

use core::ptr;

#[cfg(not(target_os = "none"))]
static mut HOST_REGISTERS: [u32; 0xf4 / 4] = [0; 0xf4 / 4];

#[inline(always)]
fn registers() -> *mut u32 {
    #[cfg(target_os = "none")]
    { 0x3810_0000 as *mut u32 }
    #[cfg(not(target_os = "none"))]
    { ptr::addr_of_mut!(HOST_REGISTERS).cast::<u32>() }
}

/// Programs the fixed memory controller timing registers from a clock ratio.
///
/// # Safety
/// The peripheral must be accessible and access serialized with other users.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn memory_controller_timing_configure(frequency: u32) {
    let base = registers();
    ptr::write_volatile(base.add(0xf0 / 4), 0);
    let timing = 0x41000 + (frequency.wrapping_mul(64000) >> 13);
    ptr::write_volatile(base.add(8 / 4), timing);
    ptr::write_volatile(base.add(0x10 / 4), 0x1fb621);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncates_product_before_shift_and_preserves_other_registers() {
        // First fractional step, ordinary clock ratios, first product overflow,
        // exact modulo period, and signed-looking inputs treated as raw bits.
        let inputs = [0, 1, 16, 24, 48, 96, 133, 67108, 67109,
                      1 << 24, 0x7fff_ffff, 0x8000_0000, u32::MAX];
        unsafe {
            for frequency in inputs {
                HOST_REGISTERS = [0xa55a_1234; 0xf4 / 4];
                memory_controller_timing_configure(frequency);
                let product = (u64::from(frequency) * 64000) & 0xffff_ffff;
                let expected_timing = 0x41000 + (product / 8192) as u32;
                for word in 0..0xf4 / 4 {
                    let expected = match word * 4 {
                        0xf0 => 0,
                        8 => expected_timing,
                        0x10 => 0x1fb621,
                        _ => 0xa55a_1234,
                    };
                    assert_eq!(ptr::read_volatile(registers().add(word)), expected,
                               "frequency {frequency:#x}, offset {:#x}", word * 4);
                }
            }
        }
    }
}
