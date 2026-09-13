//! `ostream_insert_cstr` — original: `FUN_083eace4` @ 0x083eace4.
//!
//! **80 bytes**, exactly 20 ARM instructions from 0x083eace4 through
//! 0x083ead30; the next separately linked function starts at 0x083ead34.
//! Decoding every ARM B/BL-immediate word in osos.dec finds six direct call
//! sites, all unconditional `bl` (0x0825c51c, 0x0825c538, 0x0825c548,
//! 0x0825c558, 0x0825c574, and 0x0825c5ec), with no predicated or tail
//! branches.
//!
//! Implements C++ `operator<<` insertion of a NUL-terminated C string: take
//! the retailOS unguarded strlen, forward the source, measured length, and
//! current ostream width to the shared insertion core, then clear the width
//! word in the core-returned ostream subobject. The original ostream is
//! returned.
//!
//! # Deliberate deviation
//!
//! The shared insertion core is retailOS `FUN_083b5348` @ 0x083b5348 and is
//! not ported. This wrapper reuses the existing volatile bridge from
//! `ostream_insert_string`; host tests replace that boundary rather than
//! inventing formatting behavior.

use crate::cxx::ostream_insert_string::{OstreamInsertCore, OSTREAM_INSERT_CORE};

#[inline(always)]
fn ostream_insert_core() -> OstreamInsertCore {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(OSTREAM_INSERT_CORE)) }
}

/// Inserts a NUL-terminated C string into an ostream and consumes its width.
///
/// `stream` must be a valid ostream object whose vtable has a signed base
/// adjustment word at `vptr - 12`; `source` must point to a NUL-terminated
/// byte string. The shared insertion core may return a subobject of `stream`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ostream_insert_cstr(stream: *mut u8, source: *const u8) -> *mut u8 {
    let length = crate::libc::strlen::strlen(source) as u32;
    let vptr = stream.cast::<*mut u8>().read();
    let adjustment = vptr.sub(12).cast::<i32>().read();
    let width = stream.offset(adjustment as isize).add(12).cast::<u32>();
    let result = (ostream_insert_core())(stream, source, length, width.read());
    let result_vptr = result.cast::<*mut u8>().read();
    let result_adjustment = result_vptr.sub(12).cast::<i32>().read();
    result.offset(result_adjustment as isize).add(12).cast::<u32>().write(0);
    stream
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::cxx::ostream_insert_string::OSTREAM_INSERT_CORE_TEST_LOCK;
    use core::ptr;
    use parking_lot::MutexGuard;

    static mut CALLS: usize = 0;
    static mut CALLED_STREAM: usize = 0;
    static mut CALLED_SOURCE: usize = 0;
    static mut CALLED_LENGTH: u32 = 0;
    static mut CALLED_WIDTH: u32 = 0;
    static mut CORE_RESULT: *mut u8 = ptr::null_mut();

    unsafe extern "C" fn recording_core(
        stream: *mut u8,
        source: *const u8,
        length: u32,
        width: u32,
    ) -> *mut u8 {
        CALLS += 1;
        CALLED_STREAM = stream as usize;
        CALLED_SOURCE = source as usize;
        CALLED_LENGTH = length;
        CALLED_WIDTH = width;
        CORE_RESULT
    }

    struct CoreRestore {
        _lock: MutexGuard<'static, ()>,
        previous: OstreamInsertCore,
    }

    impl Drop for CoreRestore {
        fn drop(&mut self) {
            unsafe { OSTREAM_INSERT_CORE = self.previous; }
        }
    }

    fn install_core(result: *mut u8) -> CoreRestore {
        let lock = OSTREAM_INSERT_CORE_TEST_LOCK.lock();
        unsafe {
            let previous = OSTREAM_INSERT_CORE;
            OSTREAM_INSERT_CORE = recording_core;
            CALLS = 0;
            CALLED_STREAM = 0;
            CALLED_SOURCE = 0;
            CALLED_LENGTH = 0;
            CALLED_WIDTH = 0;
            CORE_RESULT = result;
            CoreRestore { _lock: lock, previous }
        }
    }

    #[repr(align(4))]
    struct AlignedBytes([u8; 64]);

    #[repr(align(4))]
    struct AlignedVtable([u8; 16]);

    impl AlignedBytes {
        fn new(byte: u8) -> Self {
            Self([byte; 64])
        }
    }

    impl AlignedVtable {
        fn new() -> Self {
            Self([0; 16])
        }
    }

    fn store_word(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn load_word(bytes: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
    }

    /// Installs a vptr with its RTTI base-adjustment word 12 bytes before it.
    fn make_stream(
        stream_bytes: &mut AlignedBytes,
        vtable_bytes: &mut AlignedVtable,
        adjustment: i32,
        width: u32,
    ) -> *mut u8 {
        let stream = unsafe { stream_bytes.0.as_mut_ptr().add(16) };
        let vptr = unsafe { vtable_bytes.0.as_mut_ptr().add(12) };
        store_word(&mut vtable_bytes.0, 0, adjustment as u32);
        unsafe { stream.cast::<*mut u8>().write(vptr); }
        let width_offset = 16isize + adjustment as isize + 12;
        store_word(&mut stream_bytes.0, width_offset as usize, width);
        stream
    }

    #[test]
    fn forwards_cstr_length_and_width_then_clears_width() {
        let mut stream_bytes = AlignedBytes::new(0xa5);
        let mut vtable_bytes = AlignedVtable::new();
        let stream = make_stream(&mut stream_bytes, &mut vtable_bytes, 8, 19);
        let _core = install_core(stream);
        let source = b"hello\0ignored";

        let returned = unsafe { ostream_insert_cstr(stream, source.as_ptr()) };

        assert_eq!(returned, stream);
        unsafe {
            assert_eq!(CALLS, 1);
            assert_eq!(CALLED_STREAM, stream as usize);
            assert_eq!(CALLED_SOURCE, source.as_ptr() as usize);
            assert_eq!(CALLED_LENGTH, 5, "strlen stops at the first NUL");
            assert_eq!(CALLED_WIDTH, 19, "width is read through vptr - 12");
        }
        assert_eq!(load_word(&stream_bytes.0, 36), 0, "the adjusted width is consumed");
        assert_eq!(stream_bytes.0[35], 0xa5);
        assert_eq!(stream_bytes.0[40], 0xa5);
    }

    #[test]
    fn empty_cstr_enters_core_and_clears_returned_subobject_width() {
        let mut input_bytes = AlignedBytes::new(0xa5);
        let mut input_vtable = AlignedVtable::new();
        let input = make_stream(&mut input_bytes, &mut input_vtable, 8, 7);
        let mut result_bytes = AlignedBytes::new(0xa5);
        let mut result_vtable = AlignedVtable::new();
        let result = make_stream(&mut result_bytes, &mut result_vtable, -16, 0xdead_beef);
        let _core = install_core(result);

        assert_eq!(unsafe { ostream_insert_cstr(input, b"\0".as_ptr()) }, input);
        unsafe {
            assert_eq!(CALLS, 1);
            assert_eq!(CALLED_LENGTH, 0, "empty strings still enter the shared core");
            assert_eq!(CALLED_WIDTH, 7);
        }
        assert_eq!(load_word(&input_bytes.0, 36), 7, "only the core-returned object's width clears");
        assert_eq!(load_word(&result_bytes.0, 12), 0, "negative vptr adjustment is honored");
        assert_eq!(result_bytes.0[11], 0xa5);
        assert_eq!(result_bytes.0[28], 0xa5);
    }
}
