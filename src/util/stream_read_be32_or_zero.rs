//! Big-endian stream-word reader with a zero-on-failure output —
//! `stream_read_be32_or_zero` @ 0x080575cc.
//!
//! Original: `FUN_080575cc` @ 0x080575cc (36 bytes; raw ARM confirms the
//! next sibling `FUN_080575f0` opens at 0x080575f0). Decoding every B/BL word
//! in osos.dec finds 18 direct call sites, all plain unconditional `bl`.
//!
//! Algorithm: initialize a stack-local u32 to zero; call
//! [`super::stream_read_be32::stream_read_be32`] with that local; unconditionally
//! store the local to `*out`; return the callee's 0/1 status unchanged. Thus a
//! failed read writes zero rather than leaving `*out` untouched, unlike the
//! underlying reader. Deliberate deviations: Rust uses a local `u32` rather
//! than the retail stack slot; both have the same initialized value, call ABI,
//! output store, and return status.

use super::stream_read_be32::stream_read_be32;
use super::stream_seek::StreamObject;

/// stream_read_be32_or_zero — original: `FUN_080575cc` @ 0x080575cc (36
/// bytes; 18 unpredicated `bl` call sites, verified by decoding every B/BL
/// word in osos.dec).
///
/// Reads a big-endian u32 through [`stream_read_be32`], always storing to
/// `*out`. A failed read stores zero and returns 0; a successful read stores
/// the decoded word and returns 1. The original has no NULL guard.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.stream_read_be32_or_zero")]
pub unsafe extern "C" fn stream_read_be32_or_zero(
    stream: *const *mut StreamObject,
    out: *mut u32,
) -> i32 {
    let mut value = 0;
    let status = unsafe { stream_read_be32(stream, &mut value) };
    unsafe { *out = value };
    status
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::util::stream_seek::StreamVtable;

    static TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    static mut FILL: [u8; 4] = [0; 4];
    static mut SLOT_RESULT: i32 = 0;

    unsafe extern "C" fn recording_read(
        _object: *mut StreamObject,
        buf: *mut u8,
        len: u32,
        mode: u32,
    ) -> i32 {
        unsafe {
            assert_eq!(len, 4);
            assert_eq!(mode, 2);
            let fill = core::ptr::addr_of!(FILL).read();
            core::ptr::copy_nonoverlapping(fill.as_ptr(), buf, fill.len());
            core::ptr::addr_of!(SLOT_RESULT).read()
        }
    }

    unsafe extern "C" fn unused_seek(_object: *mut StreamObject, _position: i64) -> i32 {
        0
    }

    unsafe extern "C" fn unused_tell(_object: *mut StreamObject) -> i32 {
        0
    }

    static READ_VTABLE: StreamVtable = StreamVtable {
        slots_00_0c: [0; 4],
        read_10: recording_read,
        seek: unused_seek,
        opaque_18: 0,
        tell: unused_tell,
    };

    fn fixture(result: i32) -> (parking_lot::MutexGuard<'static, ()>, StreamObject) {
        let lock = TEST_LOCK.lock();
        unsafe { core::ptr::addr_of_mut!(SLOT_RESULT).write(result) };
        (lock, StreamObject { vtable: &READ_VTABLE })
    }

    #[test]
    fn stores_decoded_word_when_stream_reader_succeeds() {
        let (_lock, mut object) = fixture(4);
        unsafe { core::ptr::addr_of_mut!(FILL).write([0x12, 0x34, 0x56, 0x78]) };
        let stream: *mut StreamObject = &mut object;
        let mut out = 0;

        let status = unsafe { stream_read_be32_or_zero(&stream, &mut out) };

        assert_eq!(status, 1);
        assert_eq!(out, 0x1234_5678);
    }

    #[test]
    fn zeroes_output_when_stream_reader_fails() {
        let (_lock, mut object) = fixture(0);
        unsafe { core::ptr::addr_of_mut!(FILL).write([0xde, 0xad, 0xbe, 0xef]) };
        let stream: *mut StreamObject = &mut object;
        let mut out = 0xfeed_face;

        let status = unsafe { stream_read_be32_or_zero(&stream, &mut out) };

        assert_eq!(status, 0);
        assert_eq!(out, 0);
    }
}
