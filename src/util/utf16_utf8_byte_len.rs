//! `utf16_utf8_byte_len` — count UTF-8 bytes needed for UTF-16 code units.
//!
//! Original: `FUN_0839683c` at load address **0x0839683c**, 120 bytes
//! (`0x0839683c..0x0839683cb4`; the distinct next function begins at
//! `0x0839683cb4`). Raw ARM decoding finds **3 direct `bl` call sites**, all
//! unconditional, and no predicated inbound calls. The body has no plain
//! outbound `bl` and one predicated `blne` to `bswap16` (`0x0805dd48`).
//!
//! It processes `byte_len >> 1` independently encoded UTF-16 code units,
//! optionally byte-swapping each input unit when `flags & 1` is set. A zero
//! unit and every unit at least `0x800` count as three output bytes; units
//! below `0x80` count as one and the rest count as two. It neither recognizes
//! surrogate pairs nor stops at NUL.
//!
//! # Deliberate deviations
//!
//! None. The unused third ABI argument is retained because stock callers pass
//! four registers; the dead `r6`/`'/'` branch seen in raw ARM is unreachable.

use crate::util::bswap::bswap16;

/// Returns the UTF-8 byte count for `byte_len >> 1` UTF-16 code units.
///
/// # Safety
/// `units` must be aligned and readable for at least `byte_len >> 1` `u16`s.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn utf16_utf8_byte_len(
    units: *const u16,
    byte_len: u32,
    _unused: u32,
    flags: u32,
) -> u32 {
    let mut total = 0u32;
    let mut remaining = byte_len >> 1;
    let mut input = units;

    while remaining != 0 {
        let mut unit = unsafe { input.read() } as u32;
        if flags & 1 != 0 {
            unit = bswap16(unit);
        }

        total = total.wrapping_add(if unit == 0 || unit >= 0x800 {
            3
        } else if unit < 0x80 {
            1
        } else {
            2
        });
        input = unsafe { input.add(1) };
        remaining -= 1;
    }

    total
}

#[cfg(test)]
mod tests {
    use super::utf16_utf8_byte_len;

    #[test]
    fn counts_thresholds_nul_and_unpaired_surrogates() {
        let units = [0, 0x7f, 0x80, 0x7ff, 0x800, 0xd800, 0xffff];

        assert_eq!(unsafe { utf16_utf8_byte_len(units.as_ptr(), 14, 0, 0) }, 17);
    }

    #[test]
    fn ignores_odd_trailing_byte_and_empty_input() {
        let units = [0x41, 0x800];
        assert_eq!(unsafe { utf16_utf8_byte_len(units.as_ptr(), 3, 0, 0) }, 1);
        assert_eq!(unsafe { utf16_utf8_byte_len(units.as_ptr(), 0, 0, 1) }, 0);
    }

    #[test]
    fn swaps_each_unit_only_when_low_flag_bit_is_set() {
        let big_endian_units = [0x4100, 0x8000, 0xff07];

        assert_eq!(unsafe { utf16_utf8_byte_len(big_endian_units.as_ptr(), 6, 0, 1) }, 5);
        assert_eq!(unsafe { utf16_utf8_byte_len(big_endian_units.as_ptr(), 6, 0, 2) }, 9);
    }
}
