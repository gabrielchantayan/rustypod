//! `fat_table_sector_count` — original: `FUN_080e75e4` @ `0x080e75e4`
//! (12 bytes; true extent `0x080e75e4..0x080e75f0`, followed by the distinct
//! function beginning `mov r1, #31`).
//!
//! Raw ARM is `add r0,r0,r1; add r0,r0,#1; b 0x08031568`: it wraps the
//! numerator plus sector size plus one, then tail-branches to the signed ADS
//! division runtime. The body contains no `bl`; decoding every ARM BL word
//! finds four plain unconditional inbound calls (`0x0818cd48`, `0x0818cdbc`,
//! `0x0818ce14`, and `0x0818ce64`) and no predicated forms.
//!
//! Deliberate deviation: Rust calls the already-ported `__rt_sdiv` rather
//! than encoding an ARM tail branch; `#[inline(never)]` on that runtime entry
//! preserves a real target call boundary.

use crate::runtime::rt_div::__rt_sdiv;

/// Computes `(table_bits + sector_size + 1) / sector_size` with ARM-wrapping
/// addition and ADS signed-division semantics.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn fat_table_sector_count(table_bits: i32, sector_size: i32) -> i32 {
    __rt_sdiv(table_bits.wrapping_add(sector_size).wrapping_add(1), sector_size)
}

#[cfg(test)]
mod tests {
    use super::fat_table_sector_count;

    fn reference(table_bits: i32, sector_size: i32) -> i32 {
        let dividend = table_bits.wrapping_add(sector_size).wrapping_add(1);
        ((dividend as i64) / (sector_size as i64)) as i32
    }

    #[test]
    fn divides_wrapping_biased_table_sizes() {
        for (table_bits, sector_size) in [
            (0, 512),
            (511, 512),
            (512, 512),
            (4_095 * 12, 512),
            (65_525 * 16, 4_096),
            (i32::MAX, 1),
            (i32::MAX, i32::MAX),
            (i32::MIN, 1),
            (i32::MIN, -1),
            (-513, 512),
            (511, -512),
        ] {
            assert_eq!(
                unsafe { fat_table_sector_count(table_bits, sector_size) },
                reference(table_bits, sector_size),
                "table_bits={table_bits}, sector_size={sector_size}"
            );
        }
    }
}
