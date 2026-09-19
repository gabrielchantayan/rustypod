//! Legacy Gregorian leap-year test: `FUN_08074410` @ `0x08074410`.
//!
//! Raw `osos.dec` words establish a 40-byte extent
//! (`0x08074410..0x08074438`):
//!
//! ```arm
//! stmdb sp!,{r4,lr}; mov r4,r0; mov r1,#100; bl 0x08031568
//! cmp r1,#0; moveq r4,r0; tst r4,#3; movne r0,#0; moveq r0,#1
//! ldmia sp!,{r4,pc}
//! ```
//!
//! It has four inbound plain `bl` calls (`0x0803be2c`, `0x0803be48`,
//! `0x080d6ff4`, and `0x080d704c`), no predicated `bl` calls, and one
//! outbound plain `bl` to the ADS signed divide/remainder helper
//! `__rt_sdiv` @ `0x08031568`. The caller-visible algorithm divides the
//! signed `year` by 100; only for an exact century does it test the quotient
//! for divisibility by four, otherwise it tests `year` itself. This is the
//! Gregorian leap-year rule for the observed u16 years.
//!
//! Deliberate deviation: ADS returns the remainder in `r1`; Rust obtains it
//! through `__rt_sdivmod`'s out-pointer wrapper. The ABI result in `r0` is
//! unchanged, and the wrapper remains an explicit call boundary.

use crate::runtime::rt_div::__rt_sdivmod;

/// is_legacy_leap_year — original: `FUN_08074410` @ `0x08074410` (40 bytes).
///
/// Returns one when `year` satisfies the retailOS signed-century Gregorian
/// test, otherwise zero. `year` is a raw ARM register value: the divide
/// interprets it as `i32`, while the final low-bit test uses its raw bits.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn is_legacy_leap_year(year: u32) -> i32 {
    let mut remainder = 0;
    let quotient = unsafe { __rt_sdivmod(year as i32, 100, &mut remainder) };
    let candidate = if remainder == 0 { quotient as u32 } else { year };
    if candidate & 3 == 0 { 1 } else { 0 }
}

#[cfg(test)]
mod tests {
    use super::is_legacy_leap_year;

    fn reference(year: u32) -> i32 {
        let signed_year = year as i32;
        let candidate = if signed_year % 100 == 0 {
            (signed_year / 100) as u32
        } else {
            year
        };
        if candidate & 3 == 0 { 1 } else { 0 }
    }

    #[test]
    fn covers_gregorian_centuries_and_raw_signed_inputs() {
        let cases = [
            0,
            1,
            4,
            100,
            400,
            1900,
            2000,
            2100,
            0xffff_ff9c, // -100: signed quotient -1 is not divisible by four.
            0x8000_0000,
            0x8000_0064,
            u32::MAX,
        ];

        for year in cases {
            assert_eq!(unsafe { is_legacy_leap_year(year) }, reference(year), "{year:#010x}");
        }
    }
}
