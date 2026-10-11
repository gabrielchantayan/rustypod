//! Context text with its kind-selected suffix, serialized as counted UTF-16.
//!
//! FUN_080539f0 @ 0x080539f0: 156 bytes, [0x080539f0,0x08053a8c).
//! Two inbound plain BLs, no predicated inbound BLs; ten outbound plain BLs
//! and one BLHI. A leading 0xff at context+0x98 clears only the output count.
//! Otherwise construct a temporary string, append the suffix selected by the
//! halfword at +0x92, truncate above 255 codepoints, decode that many u16s,
//! store the remeasured count, then destroy the temporary.
//!
//! Deviations: omit unused incoming r1/r2/r3 and use native-width StringObject
//! fields on hosts. Resident mutation calls preserve the stock virtual allocator:
//! existing Rust mutation ports still have missing allocation defaults. The
//! suffix selector at 0x08068fe8 is verified from raw code, not ported here.

use crate::cxx::string_object::{StringObject, string_object_c_str, utf8_codepoint_count_safe};
use crate::cxx::string_encoding::utf8_to_utf16_bounded;

#[derive(Clone, Copy)]
pub struct ContextTextOps {
    pub construct: unsafe extern "C" fn(*mut StringObject, *const u8) -> *mut StringObject,
    pub suffix: unsafe extern "C" fn(u32) -> *const u8,
    pub insert: unsafe extern "C" fn(*mut StringObject, i32, *const u8),
    pub truncate: unsafe extern "C" fn(*mut StringObject, i32),
    pub destroy: unsafe extern "C" fn(*mut StringObject) -> *mut StringObject,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_construct(_: *mut StringObject, _: *const u8) -> *mut StringObject { panic!("install host ContextTextOps") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_suffix(_: u32) -> *const u8 { panic!("install host ContextTextOps") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_insert(_: *mut StringObject, _: i32, _: *const u8) { panic!("install host ContextTextOps") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_truncate(_: *mut StringObject, _: i32) { panic!("install host ContextTextOps") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_destroy(_: *mut StringObject) -> *mut StringObject { panic!("install host ContextTextOps") }

/// Host-only native implementation of resident boundaries; install before use.
#[cfg(not(target_os = "none"))]
pub static mut HOST_CONTEXT_TEXT_OPS: ContextTextOps = ContextTextOps {
    construct: unavailable_construct, suffix: unavailable_suffix,
    insert: unavailable_insert, truncate: unavailable_truncate, destroy: unavailable_destroy,
};

/// # Safety
/// Context must expose the halfword at +0x92 and a padded C string at +0x98
/// (or the 0xff sentinel). Output must fit 256 halfwords and not overlap context.
/// Host callers must install native resident operations and serialize access.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn context_text_to_counted_u16(counted: *mut u16) {
    #[cfg(target_os = "none")]
    let ops = ContextTextOps {
        construct: core::mem::transmute(0x08277304usize),
        suffix: core::mem::transmute(0x08068fe8usize),
        insert: core::mem::transmute(0x08276a18usize),
        truncate: core::mem::transmute(0x08277044usize),
        destroy: core::mem::transmute(0x08277484usize),
    };
    #[cfg(not(target_os = "none"))]
    let ops = core::ptr::read_volatile(core::ptr::addr_of!(HOST_CONTEXT_TEXT_OPS));
    serialize(crate::ui::object_state::shared_context(), counted, ops);
}

unsafe fn serialize(context: *const u8, counted: *mut u16, ops: ContextTextOps) {
    if context.add(0x98).read() == 0xff {
        counted.write(0);
        return;
    }
    let mut temporary = core::mem::MaybeUninit::<StringObject>::uninit();
    let string = temporary.as_mut_ptr();
    (ops.construct)(string, context.add(0x98));
    let suffix = (ops.suffix)(context.add(0x92).cast::<u16>().read() as u32);
    (ops.insert)(string, i32::MAX, suffix);
    if utf8_codepoint_count_safe((*string).payload) > 255 {
        (ops.truncate)(string, 255);
    }
    let count = utf8_codepoint_count_safe((*string).payload);
    utf8_to_utf16_bounded(counted.add(1), string_object_c_str(string), count as i32);
    counted.write(utf8_codepoint_count_safe((*string).payload) as u16);
    (ops.destroy)(string);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::{boxed::Box, vec::Vec};
    unsafe fn bytes(source: *const u8) -> Vec<u8> {
        std::ffi::CStr::from_ptr(source.cast()).to_bytes().to_vec()
    }
    unsafe fn replace(this: *mut StringObject, mut text: Vec<u8>) {
        text.extend_from_slice(&[0; 4]); // Padding for retail decoder/memory reads.
        (*this).payload = Box::into_raw(text.into_boxed_slice()).cast::<u8>();
    }
    unsafe fn release(this: *mut StringObject) {
        let len = bytes((*this).payload).len() + 4;
        drop(Box::from_raw(core::ptr::slice_from_raw_parts_mut((*this).payload, len)));
    }
    unsafe extern "C" fn construct(this: *mut StringObject, text: *const u8) -> *mut StringObject {
        this.write(StringObject { vtable: core::ptr::null(), payload: core::ptr::null_mut() });
        replace(this, bytes(text)); this
    }
    unsafe extern "C" fn suffix(kind: u32) -> *const u8 {
        assert_eq!(kind, 0x8192); b"\xc2\xa9\0\0\0\0".as_ptr()
    }
    unsafe extern "C" fn insert(this: *mut StringObject, index: i32, source: *const u8) {
        assert_eq!(index, i32::MAX);
        let mut text = bytes((*this).payload); text.extend(bytes(source));
        release(this); replace(this, text);
    }
    unsafe extern "C" fn truncate(this: *mut StringObject, count: i32) {
        let start = (*this).payload;
        let mut cursor = start.cast_const();
        for _ in 0..count { crate::cxx::string_object::utf8_next_codepoint(&mut cursor); }
        let text = core::slice::from_raw_parts(start, cursor as usize - start as usize).to_vec();
        release(this); replace(this, text);
    }
    unsafe extern "C" fn destroy(this: *mut StringObject) -> *mut StringObject { release(this); this }
    const OPS: ContextTextOps = ContextTextOps { construct, suffix, insert, truncate, destroy };

    #[test]
    fn sentinel_clears_only_count_without_reading_kind_or_constructing() {
        let mut context = [0u32; 40];
        unsafe { context.as_mut_ptr().cast::<u8>().add(0x98).write(0xff); }
        let mut output = [0xbeefu16; 3];
        unsafe { serialize(context.as_ptr().cast(), output.as_mut_ptr(), OPS); }
        assert_eq!(output, [0, 0xbeef, 0xbeef]);
    }

    #[test]
    fn suffix_and_multibyte_text_are_capped_by_codepoints_not_bytes() {
        for count in [0usize, 1, 254, 255, 256, 300] {
            let mut context = std::vec![0u32; (0x98 + count * 3 + 8) / 4 + 1];
            let mut output = [0xbeefu16; 258];
            unsafe {
                let base = context.as_mut_ptr().cast::<u8>();
                base.add(0x92).cast::<u16>().write(0x8192);
                for i in 0..count { core::ptr::copy_nonoverlapping(b"\xe2\x82\xac".as_ptr(), base.add(0x98 + i * 3), 3); }
                serialize(base, output.as_mut_ptr().add(1), OPS);
            }
            let length = (count + 1).min(255);
            assert_eq!(output[0], 0xbeef);
            assert_eq!(output[1], length as u16);
            for i in 0..count.min(255) { assert_eq!(output[i + 2], 0x20ac); }
            if count < 255 { assert_eq!(output[count + 2], 0xa9); }
            assert_eq!(output[length + 2], 0xbeef, "no terminator when bound exhausted");
        }
    }
}
