//! Port of the list/text-layout width query at `0x0811f704`.

/// width_0c_minus_inset — original: `FUN_0811f704` @ 0x0811f704
/// (28 bytes, 13 `bl` call sites, a pure leaf).
///
/// Reads the little-endian `u16` at `obj + 0x0c` — the width field of an
/// unidentified list/text layout class — and returns it minus a
/// mode-dependent inset: 9 when `mode == 4`, 8 otherwise. The
/// subtraction runs on the zero-extended 32-bit value and the result is
/// truncated back to 16 bits (the original's `mov r0, r0, lsl #0x10` /
/// `lsr #0x10` pair), so a width smaller than the inset *wraps* rather
/// than clamping. All 13 call sites are in list/text layout code
/// (`0x080f6a80`, `0x081396xx`, `0x0819xxxx`, `0x081acxx`..`0x081afxxx`,
/// `0x081fdxxx`); several pass a sign-extended `char` as `mode`, which
/// is why the comparison is on the full 32-bit register, not a `u8`.
///
/// The field is read with a plain aligned halfword load, exactly as the
/// original's `ldrh` requires — the owning struct is always halfword-
/// aligned on the target.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn width_0c_minus_inset(obj: *const u8, mode: u32) -> u32 {
    let width = (obj.add(0x0c) as *const u16).read() as u32;
    let inset = if mode == 4 { 9 } else { 8 };
    width.wrapping_sub(inset) & 0xffff
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Writes `width` at offset `0x0c` of a scratch object standing in
    /// for the unidentified owning class. The buffer is halfword-aligned
    /// because the port, like the original's `ldrh`, requires it.
    fn with_obj(width: u16, f: impl FnOnce(*const u8) -> u32) -> u32 {
        #[repr(align(2))]
        struct Obj([u8; 0x10]);
        let mut obj = Obj([0u8; 0x10]);
        obj.0[0x0c] = width as u8;
        obj.0[0x0d] = (width >> 8) as u8;
        f(obj.0.as_ptr())
    }

    #[test]
    fn mode_4_subtracts_9_everything_else_subtracts_8() {
        assert_eq!(with_obj(100, |o| unsafe { width_0c_minus_inset(o, 4) }), 91);
        assert_eq!(with_obj(100, |o| unsafe { width_0c_minus_inset(o, 0) }), 92);
        assert_eq!(with_obj(100, |o| unsafe { width_0c_minus_inset(o, 3) }), 92);
        assert_eq!(with_obj(100, |o| unsafe { width_0c_minus_inset(o, 5) }), 92);
        // Call sites pass a sign-extended char: only an exact 4 picks 9.
        assert_eq!(
            with_obj(100, |o| unsafe { width_0c_minus_inset(o, -4i32 as u32) }),
            92
        );
    }

    #[test]
    fn wraps_to_16_bits_instead_of_clamping() {
        assert_eq!(with_obj(0, |o| unsafe { width_0c_minus_inset(o, 0) }), 0xfff8);
        assert_eq!(with_obj(0, |o| unsafe { width_0c_minus_inset(o, 4) }), 0xfff7);
        assert_eq!(with_obj(7, |o| unsafe { width_0c_minus_inset(o, 0) }), 0xffff);
        assert_eq!(with_obj(8, |o| unsafe { width_0c_minus_inset(o, 4) }), 0xffff);
    }

    #[test]
    fn matches_reference_over_widths_and_modes() {
        for width in [0u16, 1, 7, 8, 9, 10, 100, 240, 320, 0x7fff, 0x8000, 0xfffe, 0xffff] {
            for mode in [0u32, 1, 3, 4, 5, 0xff, 0xffff_ffff, 0xffff_fffc] {
                let inset = if mode == 4 { 9 } else { 8 };
                let want = (width as u32).wrapping_sub(inset) & 0xffff;
                assert_eq!(
                    with_obj(width, |o| unsafe { width_0c_minus_inset(o, mode) }),
                    want,
                    "width={width:#06x} mode={mode:#010x}"
                );
            }
        }
    }
}
