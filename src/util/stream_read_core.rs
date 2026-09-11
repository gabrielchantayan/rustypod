//! Stream read through vtable slot +0x10 — `stream_read_core` @ 0x0805e754.
//!
//! Original: `FUN_0805e754` @ 0x0805e754 (72 bytes; raw ARM verifies the
//! next sibling begins with `cmp r0, #0` at 0x0805e79c, exactly after its
//! `pop {r4, r5, r6, pc}`). Exactly 9 direct `bl` call sites, all plain
//! unconditional `bl` and no predicated forms, were verified by decoding
//! every ARM B/BL word in osos.dec.
//!
//! Algorithm: dereference the stream handle to its object and vtable, call
//! vtable slot +0x10 with `(object, buf, len, 2)`, and optionally store that
//! raw slot result through `result_out`. A zero slot result means a short or
//! failed read: return -3 for a requested nonzero length, otherwise 0. Any
//! nonzero slot result returns 0. There is deliberately no NULL guard before
//! either handle dereference, matching the raw code and its unconditional
//! callers.
//!
//! Deliberate deviations: the assembly keeps `len` in r5 and uses conditional
//! ARM instructions for the output store and status normalization; Rust
//! expresses those conditions directly. Named vtable fields widen pointer
//! words on 64-bit hosts while retaining the target's 32-bit slot positions.

use super::stream_seek::StreamObject;

/// The stream-core result for a zero-length slot result and nonzero request.
pub const STREAM_READ_SHORT_ERROR: i32 = -3;

/// stream_read_core — original: `FUN_0805e754` @ 0x0805e754 (72 bytes; 9
/// unpredicated `bl` call sites, verified by decoding every B/BL word in
/// osos.dec).
///
/// Dispatches the stream object's vtable slot +0x10 with mode 2. The slot's
/// raw result is optionally written to `result_out`; this function returns 0
/// for a nonzero slot result or zero-length request, and -3 for a zero result
/// on a nonzero request.
///
/// # Safety
///
/// `stream` must point to a readable stream-object pointer whose object and
/// vtable are readable, `buf` must designate a writable range of `len` bytes
/// accepted by the vtable slot, and non-NULL `result_out` must be writable.
/// The retail function has no NULL guard for the handle, object, or vtable.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.stream_read_core")]
pub unsafe extern "C" fn stream_read_core(
    stream: *const *mut StreamObject,
    buf: *mut u8,
    len: u32,
    result_out: *mut i32,
) -> i32 {
    let object = unsafe { *stream };
    let vtable = unsafe { (*object).vtable };
    let result = unsafe { ((*vtable).read_10)(object, buf, len, 2) };
    if !result_out.is_null() {
        unsafe { *result_out = result };
    }
    if result == 0 && len != 0 {
        STREAM_READ_SHORT_ERROR
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::util::stream_seek::StreamVtable;

    static TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    static mut CALLS: u32 = 0;
    static mut SEEN_OBJECT: usize = 0;
    static mut SEEN_LEN: u32 = 0;
    static mut SEEN_MODE: u32 = 0;
    static mut SLOT_RESULT: i32 = 0;

    unsafe extern "C" fn recording_read(
        object: *mut StreamObject,
        _buf: *mut u8,
        len: u32,
        mode: u32,
    ) -> i32 {
        unsafe {
            CALLS += 1;
            SEEN_OBJECT = object as usize;
            SEEN_LEN = len;
            SEEN_MODE = mode;
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
        unsafe {
            core::ptr::addr_of_mut!(CALLS).write(0);
            core::ptr::addr_of_mut!(SEEN_OBJECT).write(0);
            core::ptr::addr_of_mut!(SEEN_LEN).write(0);
            core::ptr::addr_of_mut!(SEEN_MODE).write(0);
            core::ptr::addr_of_mut!(SLOT_RESULT).write(result);
        }
        (lock, StreamObject { vtable: &READ_VTABLE })
    }

    #[test]
    fn nonzero_slot_result_succeeds_and_records_raw_result() {
        let (_lock, mut object) = fixture(7);
        let stream: *mut StreamObject = &mut object;
        let mut buf = [0; 7];
        let mut result_out = -1;

        let status = unsafe { stream_read_core(&stream, buf.as_mut_ptr(), 7, &mut result_out) };

        assert_eq!(status, 0);
        assert_eq!(result_out, 7);
        assert_eq!(unsafe { core::ptr::addr_of!(CALLS).read() }, 1);
        assert_eq!(unsafe { core::ptr::addr_of!(SEEN_OBJECT).read() }, stream as usize);
        assert_eq!(unsafe { core::ptr::addr_of!(SEEN_LEN).read() }, 7);
        assert_eq!(unsafe { core::ptr::addr_of!(SEEN_MODE).read() }, 2);
    }

    #[test]
    fn zero_slot_result_with_data_requested_returns_short_error() {
        let (_lock, mut object) = fixture(0);
        let stream: *mut StreamObject = &mut object;
        let mut result_out = -1;

        let status = unsafe { stream_read_core(&stream, core::ptr::null_mut(), 1, &mut result_out) };

        assert_eq!(status, -3);
        assert_eq!(result_out, 0);
    }

    #[test]
    fn zero_length_accepts_a_zero_slot_result_without_result_pointer() {
        let (_lock, mut object) = fixture(0);
        let stream: *mut StreamObject = &mut object;

        let status = unsafe { stream_read_core(&stream, core::ptr::null_mut(), 0, core::ptr::null_mut()) };

        assert_eq!(status, 0);
        assert_eq!(unsafe { core::ptr::addr_of!(CALLS).read() }, 1);
    }
}
