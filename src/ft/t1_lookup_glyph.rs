//! Type 1 StandardEncoding glyph lookup — FUN_080e2658 @ 0x080e2658.
//! True extent: 128 bytes, 0x080e2658..0x080e26d8 (next ARM prologue).
//! Verified raw calls: one outgoing plain BL to strcmp's 0x08391e38
//! veneer, zero predicated BL, one indirect BLX through PSNames +0x14;
//! two inbound plain BL from the seac operator, zero predicated inbound BL.
//! Codes below 256 map through the PSNames StandardEncoding u16 table to
//! a SID, resolve its name, then scan glyph names for the first exact match.
//! Null entries and differing first bytes skip strcmp; failure returns -1.
//! Deviation: repr(C) pointer fields widen on hosts, retaining the target
//! offsets on ARM. The existing Rust strcmp replaces the resident veneer.

use core::ptr;
use crate::libc::strcmp::strcmp;

type StandardSidString = unsafe extern "C" fn(u32) -> *const u8;

#[repr(C)]
pub struct T1PsNamesService {
    pub slots_before_standard_string: [u32; 5],
    pub standard_string: StandardSidString,
    pub standard_encoding: *const u16,
}

#[repr(C)]
pub struct T1GlyphNameDecoder {
    pub fields_before_psnames: [u32; 0x554 / 4],
    pub psnames: *const T1PsNamesService,
    pub glyph_count: u32,
    pub glyph_names: *const *const u8,
}

/// Finds a glyph index by its StandardEncoding character code.
///
/// # Safety
/// `decoder` must be readable even for out-of-range codes. For codes below
/// 256 its PSNames service and encoding must be valid, and its callback must
/// return a readable NUL-terminated name. Each non-null glyph name must be
/// NUL-terminated; the table must contain `glyph_count` readable pointers.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn t1_lookup_glyph_by_standard_encoding(
    decoder: *const T1GlyphNameDecoder,
    code: u32,
) -> i32 {
    let service = ptr::read_volatile(ptr::addr_of!((*decoder).psnames));
    if code >= 256 {
        return -1;
    }
    let encoding = ptr::read_volatile(ptr::addr_of!((*service).standard_encoding));
    let resolve = ptr::read_volatile(ptr::addr_of!((*service).standard_string));
    let sid = ptr::read_volatile(encoding.add(code as usize)) as u32;
    let name = resolve(sid);
    let mut index = 0u32;
    while index < ptr::read_volatile(ptr::addr_of!((*decoder).glyph_count)) {
        let names = ptr::read_volatile(ptr::addr_of!((*decoder).glyph_names));
        let candidate = ptr::read_volatile(names.add(index as usize));
        if !candidate.is_null()
            && ptr::read_volatile(candidate) == ptr::read_volatile(name)
            && strcmp(candidate, name) == 0
        {
            return index as i32;
        }
        index = index.wrapping_add(1);
    }
    -1
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn standard_name(sid: u32) -> *const u8 {
        match sid {
            42 => b"acute\0".as_ptr(),
            0 => b"\0".as_ptr(),
            _ => panic!("unexpected SID"),
        }
    }

    #[test]
    fn maps_boundary_codes_and_returns_first_exact_match() {
        let mut encoding = [42u16; 256];
        encoding[0] = 0;
        let service = T1PsNamesService {
            slots_before_standard_string: [0; 5],
            standard_string: standard_name,
            standard_encoding: encoding.as_ptr(),
        };
        let names = [ptr::null(), b"other\0".as_ptr(), b"acutely\0".as_ptr(),
            b"acute\0".as_ptr(), b"acute\0".as_ptr(), b"\0".as_ptr()];
        let mut decoder = T1GlyphNameDecoder {
            fields_before_psnames: [0; 0x554 / 4], psnames: &service,
            glyph_count: names.len() as u32, glyph_names: names.as_ptr(),
        };
        unsafe {
            assert_eq!(t1_lookup_glyph_by_standard_encoding(&decoder, 255), 3);
            assert_eq!(t1_lookup_glyph_by_standard_encoding(&decoder, 0), 5);
            decoder.glyph_count = 3;
            assert_eq!(t1_lookup_glyph_by_standard_encoding(&decoder, 255), -1);
            decoder.glyph_count = 0;
            decoder.glyph_names = ptr::null();
            assert_eq!(t1_lookup_glyph_by_standard_encoding(&decoder, 1), -1);
            decoder.psnames = ptr::null();
            assert_eq!(t1_lookup_glyph_by_standard_encoding(&decoder, 256), -1);
            assert_eq!(t1_lookup_glyph_by_standard_encoding(&decoder, u32::MAX), -1);
        }
    }
}
