//! Big-endian u16 field reader over a stream — `stream_read_be16` @
//! 0x080578c4.
//!
//! Original: `FUN_080578c4` @ 0x080578c4 (56 bytes; raw ARM verifies the
//! extent: its `pop {r3, r4, r5, pc}` ends at 0x080578f8 and the separate
//! `b 0x08057924` thunk starts at 0x080578fc). Exactly 8 direct `bl` call
//! sites, all plain unconditional `bl` and no predicated forms, were verified
//! by decoding every B/BL word in osos.dec.
//!
//! Algorithm: call [`super::stream_read_core::stream_read_core`] with a
//! two-byte stack buffer and NULL result pointer. On a nonzero core status,
//! return 0 without touching `*out`; otherwise gather the bytes big-endian,
//! store them, and return 1. The core dispatches the stream's vtable slot
//! +0x10 with mode 2 and normalizes a zero result for a nonzero request to -3.
//!
//! Deliberate deviations: `u16::from_be_bytes` replaces the original's two
//! `ldrb`/shift/`orr` steps while retaining the same observable byte order.

/// stream_read_be16 — original: `FUN_080578c4` @ 0x080578c4 (56 bytes; 8
/// unpredicated `bl` call sites, verified by decoding every B/BL word in
/// osos.dec).
///
/// Reads two bytes through [`super::stream_read_core::stream_read_core`] and
/// stores them big-endian into `*out`. Returns 1 on success and 0 on core
/// failure; on failure `*out` is left untouched.
///
/// # Safety
///
/// `stream` must satisfy `stream_read_core`'s stream-handle requirements and
/// `out` must be writable. The original has no NULL guard.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.stream_read_be16")]
pub unsafe extern "C" fn stream_read_be16(
    stream: *const *mut super::stream_seek::StreamObject,
    out: *mut u16,
) -> i32 {
    let mut buf = [0u8; 2];
    if unsafe {
        super::stream_read_core::stream_read_core(
            stream,
            buf.as_mut_ptr(),
            2,
            core::ptr::null_mut(),
        )
    } != 0 {
        return 0;
    }
    unsafe { *out = u16::from_be_bytes(buf) };
    1
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::util::stream_seek::{StreamObject, StreamVtable};

    static TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    static mut FILL: [u8; 2] = [0; 2];
    static mut SLOT_RESULT: i32 = 0;

    unsafe extern "C" fn recording_read(
        _object: *mut StreamObject,
        buf: *mut u8,
        len: u32,
        mode: u32,
    ) -> i32 {
        unsafe {
            assert_eq!(len, 2);
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
        unsafe {
            core::ptr::addr_of_mut!(SLOT_RESULT).write(result);
        }
        (lock, StreamObject { vtable: &READ_VTABLE })
    }

    #[test]
    fn reads_two_bytes_big_endian_and_reports_success() {
        let (_lock, mut object) = fixture(2);
        unsafe { core::ptr::addr_of_mut!(FILL).write([0xbe, 0xef]) };
        let stream: *mut StreamObject = &mut object;
        let mut out = 0;

        let ok = unsafe { stream_read_be16(&stream, &mut out) };

        assert_eq!(ok, 1);
        assert_eq!(out, 0xbeef);
    }

    #[test]
    fn every_byte_lane_lands_in_its_big_endian_slot() {
        let (_lock, mut object) = fixture(2);
        let stream: *mut StreamObject = &mut object;
        let cases: [([u8; 2], u16); 2] = [([1, 0], 0x0100), ([0, 1], 0x0001)];
        for (bytes, want) in cases {
            unsafe { core::ptr::addr_of_mut!(FILL).write(bytes) };
            let mut out = 0;
            let ok = unsafe { stream_read_be16(&stream, &mut out) };
            assert_eq!(ok, 1);
            assert_eq!(out, want, "bytes {bytes:02x?}");
        }
    }

    #[test]
    fn zero_slot_result_leaves_out_untouched() {
        let (_lock, mut object) = fixture(0);
        unsafe { core::ptr::addr_of_mut!(FILL).write([0xaa, 0xbb]) };
        let stream: *mut StreamObject = &mut object;
        let mut out = 0x5afe;

        let ok = unsafe { stream_read_be16(&stream, &mut out) };

        assert_eq!(ok, 0);
        assert_eq!(out, 0x5afe);
    }
}
