//! Port of the byte-flag query at `0x0811c564`.

/// flag_2c_is_clear — original: `FUN_0811c564` @ 0x0811c564
/// (16 bytes, 16 `bl` call sites, a pure leaf).
///
/// Reads the byte at `obj + 0x2c` of an unidentified owning class and
/// returns 1 when that byte is 0 and 0 for every other value. The
/// original is `rsbs r0, byte, #1; movcc r0, #0`: the carry-clear
/// predicate kills the negative results, so the behavior is exactly
/// `byte == 0`, *not* `1 - byte`. Call sites (`0x0811axxx`,
/// `0x0811cxxx`, `0x0816dxxx`, `0x0817axxx`, `0x081axxx`..`0x081fxxxx`)
/// treat the result as a boolean, typically branching on it before a
/// follow-up load from the same object.
///
/// The field is read with a plain byte load, exactly as the original's
/// `ldrb` — no alignment requirement. The owning class (a UI/layout
/// object, judging by the callers) is unidentified, hence the
/// descriptive offset-based name rather than a semantic one.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn flag_2c_is_clear(obj: *const u8) -> u32 {
    (obj.add(0x2c).read() == 0) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a scratch object with `flag` at offset `0x2c`, standing in
    /// for the unidentified owning class, and calls the port on it.
    fn with_obj(flag: u8) -> u32 {
        let mut obj = [0u8; 0x30];
        obj[0x2c] = flag;
        unsafe { flag_2c_is_clear(obj.as_ptr()) }
    }

    #[test]
    fn zero_flag_yields_one() {
        assert_eq!(with_obj(0), 1);
    }

    #[test]
    fn any_nonzero_flag_yields_zero() {
        for flag in [1u8, 2, 3, 0x7f, 0x80, 0xfe, 0xff] {
            assert_eq!(with_obj(flag), 0, "flag={flag:#04x}");
        }
    }

    #[test]
    fn matches_reference_for_all_byte_values() {
        for flag in 0u8..=0xff {
            // Reference: `rsbs r0, flag, #1; movcc r0, #0` on ARM.
            // `rsbs` sets carry for flag <= 1, so movcc fires for flag >= 2;
            // flag == 1 gives 0 naturally. Net effect: flag == 0.
            let want = (flag == 0) as u32;
            assert_eq!(with_obj(flag), want, "flag={flag:#04x}");
        }
    }

    #[test]
    fn reads_only_offset_2c() {
        let mut obj = [0xaau8; 0x30];
        obj[0x2c] = 0;
        assert_eq!(unsafe { flag_2c_is_clear(obj.as_ptr()) }, 1);
        obj[0x2c] = 0xaa;
        assert_eq!(unsafe { flag_2c_is_clear(obj.as_ptr()) }, 0);
    }
}
