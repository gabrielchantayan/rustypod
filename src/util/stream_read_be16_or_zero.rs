//! Big-endian halfword reader with unconditional output assignment.
//!
//! `stream_read_be16_or_zero` — `FUN_080575f0` @ 0x080575f0, 36 bytes
//! (0x080575f0..0x08057614; the next function starts with PUSH). Raw A32
//! decoding verifies two plain incoming BLs at 0x0805745c and 0x08057470,
//! zero predicated incoming BLs, and one outgoing BL to 0x080578c4.
//!
//! Initialize a stack word to zero, call the existing big-endian u16 reader,
//! then unconditionally copy the low halfword to the output. Preserve the
//! callee's 0/1 result: failure writes zero rather than preserving output.
//! The caller reads the first two halfwords of a serialized record header.
//!
//! Deliberate deviations: a u16 temporary replaces the original zeroed u32
//! stack word; only its low halfword is ever read or written. No behavioral
//! deviations. Ghidra's void return is corrected from raw r0 preservation.

use super::stream_read_be16::stream_read_be16;
use super::stream_seek::StreamObject;

/// # Safety
/// `stream` must satisfy `stream_read_be16`'s handle requirements. `out`
/// must be writable and halfword-aligned even when the read fails.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.stream_read_be16_or_zero")]
pub unsafe extern "C" fn stream_read_be16_or_zero(
    stream: *const *mut StreamObject,
    out: *mut u16,
) -> i32 {
    let mut value = 0u16;
    let result = unsafe { stream_read_be16(stream, &mut value) };
    unsafe { out.write(value) };
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::stream_seek::StreamVtable;

    #[repr(C)]
    struct ByteStream {
        object: StreamObject,
        bytes: [u8; 2],
        cursor: usize,
        result: i32,
    }

    unsafe extern "C" fn read(
        object: *mut StreamObject, buffer: *mut u8, len: u32, mode: u32,
    ) -> i32 {
        let source = unsafe { &mut *object.cast::<ByteStream>() };
        assert_eq!((len, mode), (2, 2));
        if source.cursor == 0 {
            unsafe { core::ptr::copy_nonoverlapping(source.bytes.as_ptr(), buffer, 2) };
            source.cursor = 2;
            source.result
        } else {
            0
        }
    }

    unsafe extern "C" fn seek(_: *mut StreamObject, _: i64) -> i32 { 0 }
    unsafe extern "C" fn tell(_: *mut StreamObject) -> i32 { 0 }

    static VTABLE: StreamVtable = StreamVtable {
        slots_00_0c: [0; 4], read_10: read, seek, opaque_18: 0, tell,
    };

    #[test]
    fn decodes_boundary_values_then_clears_output_at_exhaustion() {
        for value in [0u16, 1, 0x0100, 0x80ff, 0xff80, u16::MAX] {
            for slot_result in [1, 2, -1, i32::MIN] {
                let mut source = ByteStream {
                    object: StreamObject { vtable: &VTABLE },
                    bytes: value.to_be_bytes(), cursor: 0, result: slot_result,
                };
                let handle: *mut StreamObject = &mut source.object;
                let mut output = [0x1357u16, 0xaaaa, 0x2468];
                assert_eq!(unsafe { stream_read_be16_or_zero(&handle, &mut output[1]) }, 1);
                assert_eq!(output, [0x1357, value, 0x2468]);
                output[1] = 0xbeef;
                assert_eq!(unsafe { stream_read_be16_or_zero(&handle, &mut output[1]) }, 0);
                assert_eq!(output, [0x1357, 0, 0x2468]);
            }
        }
    }

    #[test]
    fn failed_read_discards_bytes_written_by_backend() {
        let mut source = ByteStream {
            object: StreamObject { vtable: &VTABLE },
            bytes: [0xde, 0xad], cursor: 0, result: 0,
        };
        let handle: *mut StreamObject = &mut source.object;
        let mut output = 0xbeef;
        assert_eq!(unsafe { stream_read_be16_or_zero(&handle, &mut output) }, 0);
        assert_eq!(output, 0);
    }
}
