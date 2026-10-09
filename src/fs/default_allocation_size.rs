//! `default_allocation_size` — `FUN_080d528c` @ `0x080d528c`.
//! True extent: 172 bytes, `0x080d528c..0x080d5338` (168 executable bytes
//! and the table-pointer literal). Next function begins with `ldrh r2,[r0,#2]`.
//! Raw-word decoding finds two inbound plain BLs at 0x08088d34/0x08088d98,
//! one outbound plain BL to `__rt_udiv` at 0x080d5324, and no predicated BLs.
//!
//! Choose an allocation-size budget from a 64-bit volume-unit count. Below
//! 2^21 units use max(units * 4, minimum * 8), with 32-bit wrapping shifts.
//! Otherwise index the firmware's paired halfword table by the bit length of
//! units >> 22, capped at 14; nonzero selector chooses the first halfword.
//! Shift that halfword by 20, round down to a multiple of max(alignment,
//! minimum), and return one alignment unit when the rounded result is zero.
//! Callers select the two default allocation sizes in the volume configuration.
//!
//! Deliberate deviations: structured Rust replaces the predicated A32 flow;
//! the already-ported ADS division preserves its divide-by-zero behavior.
//! The live firmware table at 0x08a09ce0 remains a dependency, not a guessed
//! constant table. Tests supply table data to the same inlined implementation.

use crate::runtime::rt_div::__rt_udiv;

/// Requires the live firmware halfword table for volume counts >= 2^21.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn default_allocation_size(
    alignment: u32, minimum: u32, volume_units_low: u32, volume_units_high: u32,
    selector: u32,
) -> u32 {
    select_size(alignment, minimum, volume_units_low, volume_units_high,
                selector, 0x08a0_9ce0 as *const u16)
}

#[inline(always)]
unsafe fn select_size(
    alignment: u32, minimum: u32, low: u32, high: u32, selector: u32,
    table: *const u16,
) -> u32 {
    let alignment = alignment.max(minimum);
    let budget = if high == 0 && low < 0x20_0000 {
        (low << 2).max(minimum << 3)
    } else {
        let mut remaining_low = (low >> 22) | (high << 10);
        let mut remaining_high = high >> 22;
        let mut index = 0;
        while (remaining_low != 0 || remaining_high != 0) && index < 14 {
            remaining_low = (remaining_low >> 1) | (remaining_high << 31);
            remaining_high >>= 1;
            index += 1;
        }
        let column = if selector == 0 { 1 } else { 0 };
        (*table.add(index * 2 + column) as u32) << 20
    };
    let rounded = alignment.wrapping_mul(__rt_udiv(budget, alignment));
    if rounded == 0 { alignment } else { rounded }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_volume_rounding_minimum_and_wrapping_shifts() {
        for (alignment, minimum, units, expected) in [
            (512, 4096, 0, 32768),
            (4096, 512, 1025, 4096),
            (65536, 1, 1, 65536),
            (3, 1, 10, 39),
            (512, 0x2000_0000, 1, 0x2000_0000),
            (0x8000_0000, 0, 0x1f_ffff, 0x8000_0000),
            (1, 0, 0x1f_ffff, 0x7f_fffc),
        ] {
            // A null table proves that the small-volume path never reads it.
            assert_eq!(unsafe { select_size(alignment, minimum, units, 0, 0,
                                            core::ptr::null()) }, expected);
        }
    }

    #[test]
    fn table_threshold_columns_full_width_and_saturation() {
        let mut table = [0u16; 30];
        for index in 0..15 {
            table[index * 2] = (index + 1) as u16;
            table[index * 2 + 1] = (index + 101) as u16;
        }
        for (units, index) in [
            (0x20_0000u64, 0), (0x3f_ffff, 0), (0x40_0000, 1),
            (0x7f_ffff, 1), (0x80_0000, 2), (1u64 << 32, 11),
            (1u64 << 35, 14), (1u64 << 36, 14), (1u64 << 63, 14),
            (u64::MAX, 14),
        ] {
            for selector in [0, 1, u32::MAX] {
                let halfword = if selector == 0 { index + 101 } else { index + 1 };
                assert_eq!(unsafe { select_size(512, 1024, units as u32,
                    (units >> 32) as u32, selector, table.as_ptr()) }, halfword << 20);
            }
        }
    }

    #[test]
    fn table_shift_discards_upper_bits_and_zero_budget_returns_alignment() {
        let mut table = [0u16; 30];
        table[0] = 0xf001;
        assert_eq!(unsafe { select_size(3, 1, 0x20_0000, 0, 1,
                                        table.as_ptr()) }, 0x0f_ffff);
        table[0] = 0x1000;
        assert_eq!(unsafe { select_size(512, 4096, 0x20_0000, 0, 1,
                                        table.as_ptr()) }, 4096);
    }
}
