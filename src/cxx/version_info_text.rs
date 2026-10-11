//! Version text serializer — FUN_08054ea0 @ 0x08054ea0.
//! True extent [0x08054ea0, 0x08054f08): 104 bytes, no literals.
//! Raw A32 words verify five outgoing plain BLs, zero predicated BLs;
//! two incoming plain BLs (0x081127ac, 0x082a1a58), zero predicated BLs.
//! Construct a 28-byte version object with (2, 4, 0x80, 0), format it
//! into a 100-byte C string, stage at most 255 UTF-8 bytes in a 256-byte
//! counted buffer, convert to counted UTF-16, and destroy the object.
//! Deviations: uninitialized storage uses MaybeUninit; incidental r2/r3
//! at the UTF-16 call are replaced by zero (r2 is ignored and the worker
//! overwrites its output count). Reuse existing constructor/conversion/
//! destructor ports. The unrecovered version formatter remains firmware
//! at 0x08165a50; host callers must install its explicit seam.

use core::mem::MaybeUninit;
use super::version_info_construct::{VersionInfo, version_info_construct};
use super::string_encoding::pascal_utf8_to_counted_u16;
use super::empty_destructor_165bfc::empty_destructor_165bfc;
use crate::libc::counted_copy::cstr_to_counted_u8;

pub type VersionInfoFormat = unsafe extern "C" fn(*mut VersionInfo, *mut u8, u32);

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_version_info_format(_: *mut VersionInfo, _: *mut u8, _: u32) {
    panic!("install VERSION_INFO_FORMAT to execute retail version formatting on host");
}
#[cfg(not(target_os = "none"))]
pub static mut VERSION_INFO_FORMAT: VersionInfoFormat = unavailable_version_info_format;

#[inline(always)]
unsafe fn format_version(object: *mut VersionInfo, text: *mut u8) {
    #[cfg(target_os = "none")]
    let format: VersionInfoFormat = core::mem::transmute(0x0816_5a50usize);
    #[cfg(not(target_os = "none"))]
    let format = core::ptr::addr_of!(VERSION_INFO_FORMAT).read_volatile();
    format(object, text, 100);
}

unsafe fn stage_version_text(
    text: *const u8, destination: *mut u16,
    convert: impl FnOnce(*const u8, *mut u16),
) {
    let mut counted = MaybeUninit::<[u8; 256]>::uninit();
    cstr_to_counted_u8(text, counted.as_mut_ptr().cast(), 255);
    convert(counted.as_ptr().cast(), destination);
}

/// Writes a leading u16 count followed by version text, without a terminator.
/// # Safety
/// Non-NULL destination must provide space for 256 aligned u16 words.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn version_info_to_counted_u16(destination: *mut u16) {
    let mut object = MaybeUninit::<VersionInfo>::uninit();
    let mut text = MaybeUninit::<[u8; 100]>::uninit();
    version_info_construct(object.as_mut_ptr(), 2, 4, 0x80, 0);
    format_version(object.as_mut_ptr(), text.as_mut_ptr().cast());
    stage_version_text(text.as_ptr().cast(), destination, |source, destination| {
        pascal_utf8_to_counted_u16(source, destination, 0, 0);
    });
    empty_destructor_165bfc(object.as_mut_ptr().cast());
}

#[cfg(test)]
extern crate std;
#[cfg(test)]
mod tests {
    use super::*;
    use super::super::string_encoding::utf8_to_utf16_bounded;
    use super::super::string_object::utf8_codepoint_count_safe;

    #[test]
    fn counted_version_payload_handles_empty_release_and_multibyte_text() {
        for text in ["", "2.0.4", "2.0β4", "é" ] {
            let mut source = std::vec::Vec::from(text.as_bytes());
            source.push(0);
            let mut destination = [0xa55au16; 256];
            unsafe {
                stage_version_text(source.as_ptr(), destination.as_mut_ptr(), |counted, out| {
                    // Exercise the real decoder without its retail allocation dependency.
                    let length = counted.read() as usize;
                    let mut terminated = [0u8; 256];
                    core::ptr::copy_nonoverlapping(counted.add(1), terminated.as_mut_ptr(), length);
                    let count = utf8_to_utf16_bounded(out.add(1), terminated.as_ptr(), utf8_codepoint_count_safe(terminated.as_ptr()) as i32);
                    out.write(count as u16);
                });
            }
            let expected: std::vec::Vec<u16> = text.encode_utf16().collect();
            assert_eq!(destination[0] as usize, expected.len());
            assert_eq!(&destination[1..1 + expected.len()], expected.as_slice());
            assert_eq!(destination[1 + expected.len()], 0xa55a);
        }
    }

    #[test]
    fn maximum_formatter_payload_preserves_destination_tail() {
        let mut source = [b'9'; 100];
        source[99] = 0;
        let mut destination = [0xa55au16; 256];
        unsafe {
            stage_version_text(source.as_ptr(), destination.as_mut_ptr(), |counted, out| {
                let mut terminated = [0u8; 256];
                core::ptr::copy_nonoverlapping(counted.add(1), terminated.as_mut_ptr(), counted.read() as usize);
                out.write(utf8_to_utf16_bounded(out.add(1), terminated.as_ptr(), utf8_codepoint_count_safe(terminated.as_ptr()) as i32) as u16);
            });
        }
        assert_eq!(destination[0], 99);
        assert_eq!(&destination[1..100], &[b'9' as u16; 99]);
        assert_eq!(destination[100], 0xa55a);
    }
}
