//! Buffered-write flush — `FUN_081d64c4` at **0x081d64c4**.
//! Raw extent: 68 bytes, [0x081d64c4, 0x081d6508); the next function
//! starts with push {r4-r10,lr}. Ghidra's 64-byte size omits the return.
//! Whole-image aligned ARM decoding finds one plain inbound BL (0x081d6574)
//! and one BLNE (0x081d65f0). Outgoing: zero BL, one register BLX.
//!
//! Calls destination vtable slot +0x50 with the pending length, buffer,
//! and a zero-initialized output word. Clears the pending length regardless
//! of the method's status or output count; returns 1 exactly for status zero.
//! The writer caller at 0x081d6508 fills this buffer and flushes at capacity;
//! the destructor at 0x081d65d4 flushes when the pending length is nonzero.
//!
//! Deliberate deviations: repr(C) pointer fields and usize vtable entries
//! expand on hosts; target offsets remain +8/+12/+16 and slot index 20.
//! The virtual method's concrete identity is unknown; no fixed callee seam
//! is invented. No retries, short-write handling, or NULL checks are added.

/// Destination prefix needed for virtual dispatch.
#[repr(C)]
pub struct BufferedWriteDestination {
    pub vtable: *const usize,
}

/// Buffered writer prefix; unused header words are preserved.
#[repr(C)]
pub struct BufferedWriter {
    pub header: [u32; 2],
    pub destination: *mut BufferedWriteDestination,
    pub buffer: *const u8,
    pub pending_length: u32,
}

type WriteMethod = unsafe extern "C" fn(
    *mut BufferedWriteDestination, u32, *const u8, *mut u32,
) -> i32;

/// Flushes once and discards the pending count even on failure.
///
/// # Safety
/// `writer` must be writable, with a live destination and readable vtable
/// containing a valid `WriteMethod` at word 20. Its buffer must satisfy that
/// method's requirements for `pending_length` bytes, including zero length.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn buffered_write_flush(writer: *mut BufferedWriter) -> u32 {
    let length = (*writer).pending_length;
    let buffer = (*writer).buffer;
    let destination = (*writer).destination;
    let method: WriteMethod = core::mem::transmute((*destination).vtable.add(20).read());
    let mut written = 0u32;
    let status = method(destination, length, buffer, &mut written);
    (*writer).pending_length = 0;
    (status == 0) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    struct Sink {
        destination: BufferedWriteDestination,
        status: i32,
        accepted: u32,
        writer: *mut BufferedWriter,
        calls: u32,
        checksum: u32,
    }

    unsafe extern "C" fn write(
        destination: *mut BufferedWriteDestination, length: u32,
        buffer: *const u8, written: *mut u32,
    ) -> i32 {
        let sink = &mut *destination.cast::<Sink>();
        assert_eq!(*written, 0);
        assert_eq!((*sink.writer).pending_length, length, "clear only after dispatch");
        sink.calls += 1;
        for index in 0..length as usize {
            sink.checksum = sink.checksum.wrapping_add(*buffer.add(index) as u32);
        }
        *written = sink.accepted;
        // A method changing the count must still be followed by the stock clear.
        (*sink.writer).pending_length = 123;
        sink.status
    }

    #[test]
    fn clears_pending_on_success_failure_and_short_write() {
        let mut vtable = [0usize; 21];
        vtable[20] = write as *const () as usize;
        let bytes = [0, 255, 17, 128];
        for length in [0, 1, 4] {
            for status in [0, 1, -1, i32::MIN, i32::MAX] {
                for accepted in [0, 1, u32::MAX] {
                    let mut sink = Sink {
                        destination: BufferedWriteDestination { vtable: vtable.as_ptr() },
                        status, accepted, writer: core::ptr::null_mut(), calls: 0, checksum: 0,
                    };
                    let mut writer = BufferedWriter {
                        header: [0x12345678, 0x87654321],
                        destination: &mut sink.destination,
                        buffer: bytes.as_ptr(), pending_length: length,
                    };
                    sink.writer = &mut writer;
                    let result = unsafe { buffered_write_flush(&mut writer) };
                    assert_eq!(result, if status == 0 { 1 } else { 0 });
                    assert_eq!(writer.pending_length, 0);
                    assert_eq!(sink.calls, 1, "no retries even on failure or short write");
                    assert_eq!(sink.checksum, bytes[..length as usize].iter().map(|&b| b as u32).sum());
                    assert_eq!(writer.header, [0x12345678, 0x87654321]);
                    assert_eq!(writer.buffer, bytes.as_ptr());
                    assert_eq!(writer.destination, &mut sink.destination as *mut _);
                }
            }
        }
    }
}
