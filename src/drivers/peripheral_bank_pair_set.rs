//! Peripheral bank pair programming — retailOS `FUN_0809ea24` @ 0x0809ea24.
//! True extent: 52 bytes [0x0809ea24, 0x0809ea58): 48 instruction bytes
//! and the 0x39660000 literal; the next function starts with PUSH.
//! Raw aligned A32 decoding verifies two inbound plain BLs (0x081b0888,
//! 0x081b089c), no predicated inbound BLs, and no outbound BLs of either kind.
//! Select offsets 0x2c..0x38 for selector zero, 0x3c..0x48 otherwise.
//! Store the first word, zero, the second word, zero, in that order.
//! Callers supply paired object words from +0x74/+0x78; precise peripheral
//! and register meanings are not established. No callee seams are needed.
//! Deliberate deviations: volatile writes model MMIO; host builds replace
//! the fixed register block with isolated storage. No validation is added.

use core::ptr;

#[cfg(not(target_os = "none"))]
static mut HOST_REGISTERS: [u32; 20] = [0; 20];

#[inline(always)]
fn registers() -> *mut u32 {
    #[cfg(target_os = "none")]
    { 0x3966_0000 as *mut u32 }
    #[cfg(not(target_os = "none"))]
    { ptr::addr_of_mut!(HOST_REGISTERS).cast::<u32>() }
}

/// Program the selected peripheral bank's two words and clear their companions.
///
/// # Safety
/// The peripheral must be accessible; calls must be serialized with other
/// accesses to these registers (including host substitute storage).
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn peripheral_bank_pair_set(selector: u32, first: u32, second: u32) {
    let bank = registers().add(if selector == 0 { 0x2c / 4 } else { 0x3c / 4 });
    ptr::write_volatile(bank, first);
    ptr::write_volatile(bank.add(1), 0);
    ptr::write_volatile(bank.add(2), second);
    ptr::write_volatile(bank.add(3), 0);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_and_all_nonzero_selectors_replace_only_the_selected_bank() {
        unsafe {
            for selector in [0, 1, 2, 0x8000_0000, u32::MAX] {
                for (first, second) in [(0, 0), (u32::MAX, 0x8000_0000), (0x1234_5678, 0x8765_4321)] {
                    let initial = core::array::from_fn(|i| 0xa5a5_0000 | i as u32);
                    HOST_REGISTERS = initial;
                    let mut expected = initial;
                    let offset = if selector == 0 { 11 } else { 15 };
                    expected[offset..offset + 4].copy_from_slice(&[first, 0, second, 0]);
                    peripheral_bank_pair_set(selector, first, second);
                    assert_eq!(HOST_REGISTERS, expected);
                    // Reprogram the opposite bank without disturbing the first.
                    let other = if selector == 0 { 1 } else { 0 };
                    let offset = if other == 0 { 11 } else { 15 };
                    expected[offset..offset + 4].copy_from_slice(&[second, 0, first, 0]);
                    peripheral_bank_pair_set(other, second, first);
                    assert_eq!(HOST_REGISTERS, expected);
                }
            }
        }
    }
}
