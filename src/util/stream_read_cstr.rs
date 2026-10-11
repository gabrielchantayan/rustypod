//! Bounded stream string reader, retailOS `FUN_08057698` @ 0x08057698.
//!
//! Raw ARM extent: 56 bytes, ending at the next PUSH at 0x080576d0.
//! Whole-image word decoding finds two incoming plain BLs (0x080e6600,
//! 0x080e6684), zero predicated BLs; one outgoing plain BL to
//! `stream_read_core` @ 0x0805e754, zero predicated BLs.
//! Clamp the requested byte count to capacity minus one with unsigned
//! wrapping arithmetic, read through the existing stream core, ignore its
//! status, append NUL at the raw returned count, and return that count.
//! No deliberate behavioral deviations; zero capacity still wraps to
//! u32::MAX, and negative read results are not filtered.

use super::stream_read_core::stream_read_core;
use super::stream_seek::StreamObject;

/// Read a byte string and terminate it at the stream's returned count.
///
/// # Safety
/// `stream` must satisfy `stream_read_core`'s contract. `dst` must support
/// the clamped read and a writable byte at the signed returned offset,
/// even for zero capacity or a negative stream result. No NULL guards.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.stream_read_cstr")]
pub unsafe extern "C" fn stream_read_cstr(
    stream: *const *mut StreamObject,
    requested: u32,
    dst: *mut u8,
    capacity: u32,
) -> i32 {
    let len = requested.min(capacity.wrapping_sub(1));
    let mut count = capacity as i32;
    unsafe {
        stream_read_core(stream, dst, len, &mut count);
        dst.wrapping_offset(count as isize).write(0);
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::stream_seek::StreamVtable;

    #[repr(C)]
    struct Reader {
        object: StreamObject,
        available: u32,
        result: i32,
        seen_len: u32,
    }

    unsafe extern "C" fn read(
        object: *mut StreamObject, dst: *mut u8, len: u32, mode: u32,
    ) -> i32 {
        let reader = unsafe { &mut *object.cast::<Reader>() };
        assert_eq!(mode, 2);
        reader.seen_len = len;
        let copied = len.min(reader.available);
        for index in 0..copied {
            unsafe { dst.add(index as usize).write(b'a' + index as u8) };
        }
        if reader.result == i32::MAX { copied as i32 } else { reader.result }
    }

    unsafe extern "C" fn seek(_: *mut StreamObject, _: i64) -> i32 { 0 }
    unsafe extern "C" fn tell(_: *mut StreamObject) -> i32 { 0 }

    static VTABLE: StreamVtable = StreamVtable {
        slots_00_0c: [0; 4], read_10: read, seek, opaque_18: 0, tell,
    };

    #[test]
    fn clamps_and_terminates_full_short_and_empty_reads() {
        for (requested, capacity, available, expected) in [
            (3, 8, 8, 3), (8, 4, 8, 3), (3, 4, 8, 3),
            (8, 8, 2, 2), (8, 8, 0, 0), (0, 8, 8, 0), (8, 1, 8, 0),
        ] {
            let mut reader = Reader {
                object: StreamObject { vtable: &VTABLE }, available,
                result: i32::MAX, seen_len: u32::MAX,
            };
            let handle = &mut reader.object as *mut StreamObject;
            let mut buffer = [0x5a; 12];
            let result = unsafe {
                stream_read_cstr(&handle, requested, buffer.as_mut_ptr().add(1), capacity)
            };
            assert_eq!(result, expected);
            assert_eq!(reader.seen_len, requested.min(capacity - 1));
            assert_eq!(buffer[0], 0x5a);
            for index in 0..expected as usize {
                assert_eq!(buffer[index + 1], b'a' + index as u8);
            }
            assert_eq!(buffer[expected as usize + 1], 0);
            assert!(buffer[expected as usize + 2..].iter().all(|&byte| byte == 0x5a));
        }
    }

    #[test]
    fn preserves_zero_capacity_wrap_and_negative_raw_result() {
        let mut reader = Reader {
            object: StreamObject { vtable: &VTABLE }, available: 0,
            result: 0, seen_len: 0,
        };
        let handle = &mut reader.object as *mut StreamObject;
        let mut buffer = [0x5a; 3];
        assert_eq!(unsafe {
            stream_read_cstr(&handle, u32::MAX, buffer.as_mut_ptr().add(1), 0)
        }, 0);
        assert_eq!(reader.seen_len, u32::MAX);
        assert_eq!(buffer, [0x5a, 0, 0x5a]);
        reader.result = -1;
        buffer = [0x5a; 3];
        assert_eq!(unsafe {
            stream_read_cstr(&handle, 1, buffer.as_mut_ptr().add(1), 2)
        }, -1);
        assert_eq!(buffer, [0, 0x5a, 0x5a]);
    }
}
