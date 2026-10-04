//! XML tag emission — `FUN_0823332c` @ `0x0823332c`.
//! Raw ARM: 128 code bytes (through 0x082333a8), then 12 literal bytes;
//! next real function starts at 0x082333b8. Two incoming plain BLs, zero
//! predicated; four outbound plain BLs, one BLNE, and one BNE tail dispatch.
//! Writes `<` for nonzero mode, `</` for zero, the StringObject's byte payload,
//! then `>`. Stops on zero writer results; returns the last result verbatim.
//! After the name write, `(mode & result) != 0` and a nonzero pending word
//! invoke heap_panic. No flag updates are performed here (the callers do them).
//! Deviations: native repr(C) pointers widen on host; literal strings are Rust
//! statics. The verified 0x0820c1b4 thunk is ported below as xml_writer_write_bytes.
//! Existing string and fatal ports are reused.

use crate::cxx::string_object::{string_object_c_str, StringObject};
use crate::libc::strlen_safe_plus1::strlen_safe_plus1;
use crate::heap::veneers::heap_panic;

pub type WriteBytes = unsafe extern "C" fn(*mut TagOutput, *const u8, u32) -> u32;

#[repr(C)]
pub struct TagOutputVtable {
    pub opaque_slots: [usize; 2],
    pub write: WriteBytes,
}

#[repr(C)]
pub struct TagOutput {
    pub vtable: *const TagOutputVtable,
}

/// Recovered prefix; pointer fields occupy one target word each.
#[repr(C)]
pub struct XmlTagWriter {
    pub opaque_words: [u32; 2],
    pub output: *mut TagOutput,
    pub flags: u32,
    pub name: *const StringObject,
    pub pending: u32,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 8] = [0; core::mem::offset_of!(XmlTagWriter, output)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 16] = [0; core::mem::offset_of!(XmlTagWriter, name)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 20] = [0; core::mem::offset_of!(XmlTagWriter, pending)];

/// Writes an explicit byte range through the writer's current output object.
///
/// Original: `FUN_0820c1b4` @ `0x0820c1b4`, true size 16 bytes, ending
/// before the independent constructor at `0x0820c1c4`. Raw words:
/// `e5900008 e5903000 e5933008 e12fff13`. Two inbound plain BLs
/// (`0x0823334c`, `0x0823337c`), zero predicated BLs; additionally a BNE
/// tail caller at `0x082333a4`. No outbound BLs; one indirect tail BX.
/// Loads output at writer +8 and its vtable slot +8, passing bytes and len
/// unchanged and returning the method's result. No NULL or length guards.
/// Deliberate deviation: repr(C) pointer fields and vtable entries widen on
/// hosts. The virtual method's identity is not invented; its write role is
/// established by the XML caller. Rust expresses BX as a final C-ABI call.
///
/// # Safety
/// `writer`, its output and the output vtable must be valid and aligned.
/// The method must accept `bytes` and `len` under its unchecked C ABI.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn xml_writer_write_bytes(writer: *mut XmlTagWriter, bytes: *const u8, len: u32) -> u32 {
    let output = (*writer).output;
    ((*(*output).vtable).write)(output, bytes, len)
}

/// # Safety
/// `writer`, its name, output, and vtable must be valid. The virtual method
/// must accept the supplied readable byte ranges and obey its C ABI.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn xml_write_tag(writer: *mut XmlTagWriter, mode: u32) -> u32 {
    let prefix: &[u8] = if mode == 0 { b"</\0" } else { b"<\0" };
    let result = xml_writer_write_bytes(writer, prefix.as_ptr(), if mode == 0 { 2 } else { 1 });
    if result == 0 { return result; }
    let len = (strlen_safe_plus1((*(*writer).name).payload) as u32).wrapping_sub(1);
    let name = string_object_c_str((*writer).name);
    let result = xml_writer_write_bytes(writer, name, len);
    if mode & result != 0 && (*writer).pending != 0 { heap_panic(); }
    if result == 0 { return result; }
    xml_writer_write_bytes(writer, b">\0".as_ptr(), 1)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    #[repr(C)]
    struct Output {
        base: TagOutput,
        bytes: Vec<u8>,
        calls: usize,
        results: [u32; 3],
    }

    // A bounded output sink: accepted bytes become actual serialized output.
    unsafe extern "C" fn write(output: *mut TagOutput, bytes: *const u8, len: u32) -> u32 {
        let output = &mut *output.cast::<Output>();
        let result = output.results[output.calls];
        output.calls += 1;
        if result != 0 {
            output.bytes.extend_from_slice(core::slice::from_raw_parts(bytes, len as usize));
        }
        result
    }

    fn emit(payload: *mut u8, mode: u32, pending: u32, results: [u32; 3]) -> (u32, Vec<u8>, usize) {
        let table = TagOutputVtable { opaque_slots: [0; 2], write };
        let mut output = Output {
            base: TagOutput { vtable: &table }, bytes: Vec::new(), calls: 0, results,
        };
        let name = StringObject { vtable: core::ptr::null(), payload };
        let mut writer = XmlTagWriter {
            opaque_words: [0; 2], output: &mut output.base, flags: 0xa5, name: &name, pending,
        };
        let result = unsafe { xml_write_tag(&mut writer, mode) };
        assert_eq!(writer.flags, 0xa5);
        assert_eq!(writer.pending, pending);
        (result, output.bytes, output.calls)
    }

    #[test]
    fn emits_open_and_close_tags_without_the_name_terminator() {
        let mut name = *b"caf\xc3\xa9\0ignored";
        assert_eq!(emit(name.as_mut_ptr(), 1, 0, [7, 3, 9]), (9, b"<caf\xc3\xa9>".to_vec(), 3));
        assert_eq!(emit(name.as_mut_ptr(), 0, 17, [1; 3]), (1, b"</caf\xc3\xa9>".to_vec(), 3));
    }

    #[test]
    fn null_and_empty_payloads_still_write_an_empty_name() {
        assert_eq!(emit(core::ptr::null_mut(), 1, 0, [1; 3]), (1, b"<>".to_vec(), 3));
        let mut name = [0u8];
        assert_eq!(emit(name.as_mut_ptr(), 0, 0, [1; 3]), (1, b"</>".to_vec(), 3));
    }

    #[test]
    fn stops_at_each_failed_write_preserving_partial_output() {
        let mut name = *b"item\0";
        for (results, bytes, calls) in [
            ([0, 1, 1], &b""[..], 1),
            ([1, 0, 1], &b"<"[..], 2),
            ([1, 1, 0], &b"<item"[..], 3),
        ] {
            assert_eq!(emit(name.as_mut_ptr(), 1, 0, results), (0, bytes.to_vec(), calls));
        }
    }

    #[test]
    fn pending_check_uses_bitwise_mode_and_result() {
        let mut name = *b"x\0";
        assert_eq!(emit(name.as_mut_ptr(), 1, 99, [1, 2, 8]), (8, b"<x>".to_vec(), 3));
        assert_eq!(emit(name.as_mut_ptr(), 2, 99, [1, 1, 6]), (6, b"<x>".to_vec(), 3));
    }

    #[test]
    fn explicit_ranges_preserve_binary_bytes_and_reload_the_output() {
        let table = TagOutputVtable { opaque_slots: [0; 2], write };
        let mut first = Output {
            base: TagOutput { vtable: &table }, bytes: Vec::new(), calls: 0,
            results: [0x8000_0001, 0, 7],
        };
        let mut second = Output {
            base: TagOutput { vtable: &table }, bytes: Vec::new(), calls: 0,
            results: [u32::MAX, 1, 1],
        };
        let mut writer = XmlTagWriter {
            opaque_words: [0; 2], output: &mut first.base, flags: 0xa5,
            name: core::ptr::null(), pending: 99,
        };
        let bytes = [0x11, 0, 0xff, 0x22, 0x33];
        unsafe {
            assert_eq!(xml_writer_write_bytes(&mut writer, bytes.as_ptr().add(1), 3), 0x8000_0001);
            assert_eq!(first.bytes, [0, 0xff, 0x22]);
            assert_eq!(xml_writer_write_bytes(&mut writer, bytes.as_ptr(), 5), 0);
            assert_eq!(first.bytes, [0, 0xff, 0x22]);
            assert_eq!(xml_writer_write_bytes(&mut writer, bytes.as_ptr(), 0), 7);
            assert_eq!(first.bytes, [0, 0xff, 0x22]);
            writer.output = &mut second.base;
            assert_eq!(xml_writer_write_bytes(&mut writer, bytes.as_ptr().add(4), 1), u32::MAX);
        }
        assert_eq!(second.bytes, [0x33]);
        assert_eq!(first.bytes, [0, 0xff, 0x22]);
        assert_eq!(writer.flags, 0xa5);
        assert_eq!(writer.pending, 99);
    }
}
