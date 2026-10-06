//! Buffered reader refill — FUN_0816bd2c @ 0x0816bd2c.
//! True size: 208 bytes, next function starts at 0x0816bdfc.
//! Raw A32: one plain BL, zero predicated BLs, one virtual BLX.
//! Compact unread bytes when cursor + requested exceeds buffered length, then
//! perform at most one read capped by capacity and remaining source bytes.
//! Count reads, preserve the unlimited remaining sentinel, and latch EOF only
//! if the resulting buffer is empty. Arithmetic wraps as in the original.
//! Deviations: call the existing Rust memmove instead of the 0x08037e00 veneer
//! (literal 0x220000d4, IRAM mirror of 0x080000d4). repr(C) pointers and vtable
//! slots widen on hosts; target offsets remain the original 32-bit layout.

use crate::libc::memmove::memmove;

#[repr(C)]
pub struct BufferedReaderVtable {
    pub preceding_slots: [usize; 17],
    pub read: unsafe extern "C" fn(*mut BufferedReader, *mut u8, u32) -> u32,
}

#[repr(C)]
pub struct BufferedReader {
    pub vtable: *const BufferedReaderVtable,
    pub remaining: u32,
    pub reserved_08_10: [u32; 3],
    pub buffer: *mut u8,
    pub capacity: u32,
    pub buffered: u32,
    pub cursor: u32,
    pub position: u32,
    pub eof: u8,
    pub reserved_29_2b: [u8; 3],
    pub read_count: u32,
}

/// # Safety
/// Reader and vtable must be valid. Buffer must hold capacity bytes and all
/// unread bytes. The virtual read must obey its buffer bound and object ABI.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn buffered_reader_refill(reader: *mut BufferedReader, requested: u32) {
    if (*reader).cursor.wrapping_add(requested) <= (*reader).buffered || (*reader).eof != 0 {
        return;
    }
    if (*reader).cursor < (*reader).buffered {
        memmove((*reader).buffer, (*reader).buffer.wrapping_add((*reader).cursor as usize),
            (*reader).buffered.wrapping_sub((*reader).cursor) as usize);
        (*reader).buffered = (*reader).buffered.wrapping_sub((*reader).cursor);
    } else {
        (*reader).buffered = 0;
    }
    (*reader).cursor = 0;
    let count = (*reader).capacity.wrapping_sub((*reader).buffered).min((*reader).remaining);
    if count != 0 {
        let read = (*(*reader).vtable).read;
        let received = read(reader, (*reader).buffer.wrapping_add((*reader).buffered as usize), count);
        (*reader).buffered = (*reader).buffered.wrapping_add(received);
        (*reader).read_count = (*reader).read_count.wrapping_add(1);
        if (*reader).remaining != u32::MAX {
            (*reader).remaining = (*reader).remaining.wrapping_sub(received);
        }
    }
    if (*reader).buffered == 0 {
        (*reader).eof = 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn read(reader: *mut BufferedReader, dst: *mut u8, count: u32) -> u32 {
        // Fixture source has only three bytes, so this is a genuine short read.
        let received = count.min(3);
        for i in 0..received { dst.add(i as usize).write(0xa0 + i as u8); }
        (*reader).position = (*reader).position.wrapping_add(received);
        received
    }
    unsafe extern "C" fn empty(_: *mut BufferedReader, _: *mut u8, _: u32) -> u32 { 0 }

    #[test]
    fn compaction_caps_and_short_reads() {
        let vtable = BufferedReaderVtable { preceding_slots: [0; 17], read };
        for remaining in [0, 1, 2, 3, 9, u32::MAX] {
            for buffered in 0..=8u32 {
                for cursor in 0..=8u32 {
                    let mut bytes = [0x55u8; 16];
                    for i in 0..8 { bytes[i] = i as u8; }
                    let original = bytes;
                    let mut reader = BufferedReader { vtable: &vtable, remaining,
                        reserved_08_10: [0; 3], buffer: bytes.as_mut_ptr(), capacity: 8,
                        buffered, cursor, position: 10, eof: 0, reserved_29_2b: [7; 3], read_count: u32::MAX };
                    unsafe { buffered_reader_refill(&mut reader, 9); }
                    let kept = buffered.saturating_sub(cursor);
                    let received = (8 - kept).min(remaining).min(3);
                    assert_eq!(reader.buffered, kept + received);
                    assert_eq!(reader.cursor, 0);
                    assert_eq!(reader.remaining, if remaining == u32::MAX { remaining } else { remaining - received });
                    assert_eq!(reader.read_count, if (8 - kept).min(remaining) == 0 { u32::MAX } else { 0 });
                    assert_eq!(reader.eof, u8::from(kept + received == 0));
                    assert_eq!(reader.position, 10 + received);
                    assert_eq!(reader.reserved_29_2b, [7; 3]);
                    for i in 0..kept as usize { assert_eq!(bytes[i], original[cursor as usize + i]); }
                    for i in 0..received as usize { assert_eq!(bytes[kept as usize + i], 0xa0 + i as u8); }
                    assert_eq!(&bytes[8..], &[0x55; 8]);
                }
            }
        }
    }

    #[test]
    fn gates_wrapping_request_and_empty_source() {
        let vtable = BufferedReaderVtable { preceding_slots: [0; 17], read: empty };
        let mut bytes = [1u8; 8];
        let mut reader = BufferedReader { vtable: &vtable, remaining: u32::MAX,
            reserved_08_10: [0; 3], buffer: bytes.as_mut_ptr(), capacity: 8,
            buffered: 4, cursor: 2, position: 99, eof: 0, reserved_29_2b: [0; 3], read_count: 0 };
        unsafe { buffered_reader_refill(&mut reader, 2); }
        assert_eq!((reader.buffered, reader.cursor, reader.read_count), (4, 2, 0));
        unsafe { buffered_reader_refill(&mut reader, u32::MAX); }
        assert_eq!((reader.buffered, reader.cursor, reader.read_count), (4, 2, 0));
        reader.eof = 7;
        unsafe { buffered_reader_refill(&mut reader, 8); }
        assert_eq!((reader.buffered, reader.cursor, reader.read_count), (4, 2, 0));
        reader.eof = 0;
        unsafe { buffered_reader_refill(&mut reader, 8); }
        assert_eq!((reader.buffered, reader.cursor, reader.read_count, reader.eof), (2, 0, 1, 0));
        reader.cursor = 2;
        unsafe { buffered_reader_refill(&mut reader, 1); }
        assert_eq!((reader.buffered, reader.cursor, reader.read_count, reader.eof), (0, 0, 2, 1));
        assert_eq!(reader.remaining, u32::MAX);
        assert_eq!(reader.position, 99);
    }
}
