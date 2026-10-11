//! Counted UTF-16 final component of a retailOS path.
//!
//! Original FUN_0805a9f4 at 0x0805a9f4; true extent 180 code bytes,
//! [0x0805a9f4, 0x0805aaa8), followed by a distinct PUSH prologue.
//! Whole-image A32 decoding verifies one plain inbound BL (0x081a436c)
//! and one BLNE (0x0805a9e4); body: 12 plain BLs, zero predicated BLs.
//! Construct two PathObjects, reject NULL input with -50, assign the C
//! string after the input's leading u16, destructively extract its final
//! component with escaping disabled, assign that component to the output
//! PathObject, convert to counted UTF-16, and decrement the count if its
//! last unit is '\\'. The removed unit is not erased or NUL-terminated.
//! Deliberate deviations: host pointers widen in StringObject; MaybeUninit
//! models stack storage. The unported suffix extractor remains a firmware
//! call at 0x08278f98. Conversion's unused register arguments are supplied
//! as zero: the stock helper overwrites the count before using it.

use core::mem::MaybeUninit;
use crate::app::path_object_construct::{path_object_default_construct,
    path_object_assign_from_string_object};
use crate::cxx::string_object::{StringObject, string_object_assign_cstr,
    string_object_c_str, string_object_destroy_veneer};
use crate::cxx::string_encoding::cstr_to_counted_u16;

/// # Safety
/// Non-NULL input holds a leading u16 followed by padded NUL-terminated
/// UTF-8. Output has space for a leading count plus 255 UTF-16 units and
/// must not be NULL on the non-NULL path. Existing string allocation and
/// release contracts apply. NULL input leaves output untouched.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn counted_path_last_component(
    source: *const u16, destination: *mut u16,
) -> i32 {
    let mut remaining = MaybeUninit::<StringObject>::uninit();
    let mut component = MaybeUninit::<StringObject>::uninit();
    path_object_default_construct(remaining.as_mut_ptr());
    path_object_default_construct(component.as_mut_ptr());
    let status = counted_path_last_component_with(source, destination, |text, output| {
        string_object_assign_cstr(remaining.as_mut_ptr(), text);
        let mut extracted = MaybeUninit::<StringObject>::uninit();
        extract_suffix(extracted.as_mut_ptr(), remaining.as_mut_ptr());
        path_object_assign_from_string_object(component.as_mut_ptr(), extracted.as_ptr());
        string_object_destroy_veneer(extracted.as_mut_ptr());
        cstr_to_counted_u16(string_object_c_str(component.as_ptr()), output, 0, 0);
    });
    string_object_destroy_veneer(component.as_mut_ptr());
    string_object_destroy_veneer(remaining.as_mut_ptr());
    status
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn extract_suffix(out: *mut StringObject, remaining: *mut StringObject) {
    let helper: unsafe extern "C" fn(*mut StringObject, *mut StringObject, u32) =
        core::mem::transmute(0x0827_8f98usize);
    helper(out, remaining, 0);
}
#[cfg(not(target_os = "none"))]
unsafe fn extract_suffix(_out: *mut StringObject, _remaining: *mut StringObject) {
    panic!("retailOS suffix extraction at 0x08278f98 is unavailable on hosts");
}

#[inline(always)]
unsafe fn counted_path_last_component_with(
    source: *const u16, destination: *mut u16,
    convert: impl FnOnce(*const u8, *mut u16),
) -> i32 {
    if source.is_null() { return -50; }

    convert(source.add(1).cast(), destination);
    let count = destination.read();
    if destination.add(count as usize).read() == b'\\' as u16 {
        destination.write(count.wrapping_sub(1));
    }
    0
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    // Functional boundary model: suffix after the rightmost delimiter,
    // followed by the firmware's byte-limited, counted UTF-16 conversion.
    unsafe fn convert(text: *const u8, output: *mut u16) {
        let bytes = std::ffi::CStr::from_ptr(text.cast()).to_bytes();
        let start = bytes.iter().rposition(|b| matches!(*b, b':' | b'/' | b'\\'))
            .map_or(0, |index| index + 1);
        let suffix = &bytes[start..];
        let suffix = &suffix[..suffix.len().min(255)];
        let text = std::str::from_utf8(suffix).unwrap();
        let mut count = 0;
        for unit in text.encode_utf16() {
            output.add(count + 1).write(unit);
            count += 1;
        }
        output.write(count as u16);
    }

    #[test]
    fn null_input_does_not_touch_output_or_convert() {
        let mut output = [0xa55a; 256];
        assert_eq!(unsafe { counted_path_last_component_with(core::ptr::null(),
            output.as_mut_ptr(), |_, _| panic!("NULL conversion")) }, -50);
        assert_eq!(output, [0xa55a; 256]);
    }

    #[test]
    fn counted_input_header_is_not_a_bound_and_empty_output_stays_empty() {
        for (text, expected) in [("", ""), ("plain", "plain"),
            ("disk:folder/file", "file"), ("disk:folder\\é中", "é中"),
            ("folder/", ""), ("folder\\", ""), ("disk:", "")] {
            let mut source = [0u16; 256];
            source[0] = 0xffff;
            unsafe { core::ptr::copy_nonoverlapping(text.as_ptr(),
                source.as_mut_ptr().add(1).cast(), text.len()); }
            let mut output = [0xa55a; 256];
            assert_eq!(unsafe { counted_path_last_component_with(source.as_ptr(),
                output.as_mut_ptr(), |s, d| convert(s, d)) }, 0);
            let expected: std::vec::Vec<u16> = expected.encode_utf16().collect();
            assert_eq!(output[0] as usize, expected.len());
            assert_eq!(&output[1..1 + expected.len()], expected.as_slice());
            assert_eq!(output[1 + expected.len()], 0xa55a);
        }
    }

    #[test]
    fn trim_uses_converted_count_and_preserves_removed_unit() {
        let source = [0u16; 2];
        for (units, expected) in [(&[b'\\' as u16][..], 0),
            (&[b'x' as u16, b'\\' as u16][..], 1),
            (&[b'x' as u16, b'/' as u16][..], 2), (&[][..], 0)] {
            let mut output = [0xa55a; 256];
            unsafe { counted_path_last_component_with(source.as_ptr(), output.as_mut_ptr(),
                |_, d| { d.write(units.len() as u16);
                    core::ptr::copy_nonoverlapping(units.as_ptr(), d.add(1), units.len()); }); }
            assert_eq!(output[0], expected);
            assert_eq!(&output[1..1 + units.len()], units);
            assert_eq!(output[1 + units.len()], 0xa55a);
        }
    }
}
