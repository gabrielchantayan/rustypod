//! HFS volume encoding bitmap update.
//!
//! Original: `FUN_0806d8ac` at `0x0806d8ac`, 76 bytes, ending at the
//! independent PUSH entry at `0x0806d8f8`. Raw A32 decoding finds two incoming
//! BLs: one plain at `0x08057fa0`, one BLNE at `0x0805d6cc`; no outgoing BLs.
//!
//! Mask the catalog text encoding to seven bits. Values >=48 select bit zero;
//! values 32..47 produce zero under ARM register LSL, not a wrapping shift.
//! OR the resulting word into volume +0x180 and its arithmetic sign extension
//! into +0x184. Thus bit 31 sets every upper-word bit. Callers operate on HFS+
//! volumes (signature 0x482b) while creating or renaming catalog records.
//!
//! Deliberate deviations: omit unreachable comparisons against 0x98 and 0x8c
//! after the seven-bit mask. Preserve the actual ASR, not Ghidra's unsigned
//! shift or an idealized 64-bit bitmap operation. Aligned volatile word accesses
//! retain both loads before both stores; no null guard or callee seams.

/// Marks a catalog text encoding in the volume's two-word bitmap.
///
/// # Safety
/// `volume` must address writable aligned storage through byte +0x187.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.hfs_volume_mark_encoding")]
#[inline(never)]
pub unsafe extern "C" fn hfs_volume_mark_encoding(volume: *mut u32, encoding: u32) {
    let index = encoding & 0x7f;
    let index = if index >= 48 { 0 } else { index };
    let bit = 1u32.checked_shl(index).unwrap_or(0);
    let upper_mask = ((bit as i32) >> 31) as u32;
    let lower = volume.add(0x180 / 4);
    let upper = volume.add(0x184 / 4);
    let old_lower = lower.read_volatile();
    let old_upper = upper.read_volatile();
    lower.write_volatile(old_lower | bit);
    upper.write_volatile(old_upper | upper_mask);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_masked_encodings_match_arm_shift_and_preserve_other_words() {
        for encoding in 0..512u32 {
            for initial in [[0, 0], [0x2468_ace0, 0x1357_9bdf], [u32::MAX, u32::MAX]] {
                let mut volume = [0xdead_beefu32; 100];
                volume[96] = initial[0];
                volume[97] = initial[1];
                let mut expected = volume;
                let masked = encoding & 127;
                let index = if masked < 48 { masked } else { 0 };
                // Widening models ARM LSL without Rust's modulo-32 shifts.
                let bit = (1u64 << index) as u32;
                expected[96] |= bit;
                expected[97] |= if bit & 0x8000_0000 != 0 { u32::MAX } else { 0 };
                unsafe { hfs_volume_mark_encoding(volume.as_mut_ptr(), encoding); }
                assert_eq!(volume, expected, "encoding {encoding:#x}, initial {initial:x?}");
            }
        }
    }

    #[test]
    fn repeated_updates_accumulate_with_sign_extension_and_high_input_bits() {
        let mut volume = [0u32; 98];
        for (encoding, expected) in [
            (30, [0x4000_0000, 0]),
            (32, [0x4000_0000, 0]),
            (47, [0x4000_0000, 0]),
            (48, [0x4000_0001, 0]),
            (u32::MAX, [0x4000_0001, 0]),
            (0xffff_ff9f, [0xc000_0001, u32::MAX]),
            (0x98, [0xc100_0001, u32::MAX]),
            (0x8c, [0xc100_1001, u32::MAX]),
            (0x8c, [0xc100_1001, u32::MAX]),
        ] {
            unsafe { hfs_volume_mark_encoding(volume.as_mut_ptr(), encoding); }
            assert_eq!(&volume[96..98], &expected, "encoding {encoding:#x}");
        }
    }
}
