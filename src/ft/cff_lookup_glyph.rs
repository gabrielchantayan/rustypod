//! CFF `seac` character-code to charset glyph-index lookup.

/// Prefix of the CFF font through its charset SID array. Pointer fields widen
/// on hosts; field accesses preserve the firmware layout on ARM.
#[repr(C)]
pub struct CffFontCharset {
    _reserved_00: [u32; 3],
    pub num_glyphs: u32,
    _reserved_10: [u32; 286],
    pub charset_sids: *const u16,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x488] = [0; core::mem::offset_of!(CffFontCharset, charset_sids)];

#[cfg(test)]
static ENCODING: core::sync::atomic::AtomicPtr<u16> =
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());

/// Original `FUN_080e325c` at 0x080e325c: 84 instruction bytes and a
/// four-byte literal (88 bytes through the next prologue at 0x080e32b4).
/// Raw ARM decoding verifies two incoming plain BLs at 0x080a1910 and
/// 0x080a1920, no predicated incoming BLs, and no outgoing BLs of either kind.
///
/// Reject a NULL charset or a code >= 256. Read the code's 16-bit SID from
/// the literal-address table at 0x0890d2b8, then return the first matching
/// charset index, or u32::MAX. The CFF seac caller uses this for both base
/// and accent codes and treats the sentinel as an invalid character code.
/// Zero SIDs are not special-cased, and num_glyphs is compared unsigned.
///
/// Deliberate deviations: typed fields widen the charset pointer on hosts;
/// host tests replace only the fixed encoding-table address. The raw image
/// bytes at that address are not a conventional Adobe StandardEncoding
/// table, so the target preserves the literal rather than reconstructing it.
///
/// # Safety
/// `font` must be readable. For accepted codes and a non-NULL charset,
/// its SID array must contain num_glyphs halfwords and the encoding table
/// must be readable, even when num_glyphs is zero.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cff_lookup_glyph(font: *const CffFontCharset, charcode: u32) -> u32 {
    let sids = unsafe { (*font).charset_sids };
    if sids.is_null() || charcode >= 256 {
        return u32::MAX;
    }
    #[cfg(not(test))]
    let encoding = 0x0890_d2b8 as *const u16;
    #[cfg(test)]
    let encoding = ENCODING.load(core::sync::atomic::Ordering::Relaxed) as *const u16;
    let count = unsafe { (*font).num_glyphs };
    let sid = unsafe { *encoding.add(charcode as usize) };
    let mut glyph_index = 0;
    while glyph_index < count {
        if unsafe { *sids.add(glyph_index as usize) } == sid {
            return glyph_index;
        }
        glyph_index += 1;
    }
    u32::MAX
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn charset_boundaries_first_match_and_full_width_codes() {
        let mut encoding = [0u16; 256];
        encoding[32] = 0x8123;
        encoding[255] = 0xffff;
        ENCODING.store(encoding.as_mut_ptr(), core::sync::atomic::Ordering::Relaxed);
        let sids = [0, 0x8123, 0x8123, 0xffff];
        let mut font = CffFontCharset {
            _reserved_00: [0; 3], num_glyphs: 4,
            _reserved_10: [0; 286], charset_sids: sids.as_ptr(),
        };
        unsafe {
            assert_eq!(cff_lookup_glyph(&font, 32), 1);
            assert_eq!(cff_lookup_glyph(&font, 255), 3);
            assert_eq!(cff_lookup_glyph(&font, 0), 0);
            font.num_glyphs = 3;
            assert_eq!(cff_lookup_glyph(&font, 255), u32::MAX);
            font.num_glyphs = 0;
            assert_eq!(cff_lookup_glyph(&font, 32), u32::MAX);
            // Rejected codes must not dereference either table.
            font.charset_sids = 1usize as *const u16;
            ENCODING.store(core::ptr::null_mut(), core::sync::atomic::Ordering::Relaxed);
            for code in [256, 0x10020, u32::MAX] {
                assert_eq!(cff_lookup_glyph(&font, code), u32::MAX);
            }
            font.charset_sids = core::ptr::null();
            font.num_glyphs = u32::MAX;
            assert_eq!(cff_lookup_glyph(&font, 32), u32::MAX);
        }
    }
}
