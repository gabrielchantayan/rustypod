//! Type 1 font signature probe.

use crate::ft::stream::{ft_stream_enter_frame, ft_stream_exit_frame, ft_stream_seek, FtStream};
use crate::ft::t1_pfb_header::t1_read_pfb_segment_header;
use crate::libc::memcmp::memcmp;

/// t1_check_header — original: `FUN_080a8318` @ 0x080a8318.
/// True extent: 152 bytes, ending at the distinct indirect-dispatch function
/// at 0x080a83b0. Raw-word verification: six unconditional BL instructions,
/// zero predicated BL instructions; two incoming unconditional BL calls.
///
/// Seeks to zero and reads a PFB segment header. Only ASCII tag 0x8001
/// leaves the stream after that header; every other tag rewinds to zero.
/// Enters a frame of `length` bytes, compares it with `signature`, and exits
/// the frame on both match and mismatch. Returns 2 for mismatch, otherwise
/// propagates the first stream error. The segment's declared length does not
/// constrain the comparison. Deliberate deviation: initializes the header
/// helper's error argument to zero rather than inheriting a scratch register;
/// its first reader overwrites that value before it is used. The saved r3
/// stack word is dead, so the Rust interface has only three arguments.
///
/// # Safety
/// `stream` must be a valid, unframed stream satisfying the stream helpers'
/// requirements. `signature` must be readable for `length` bytes.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn t1_check_header(
    stream: *mut FtStream,
    signature: *const u8,
    length: u32,
) -> i32 {
    let error = ft_stream_seek(stream, 0);
    if error != 0 { return error; }
    let mut tag = 0u16;
    let mut segment_size = 0u32;
    let error = t1_read_pfb_segment_header(stream, &mut tag, &mut segment_size, 0);
    if error != 0 { return error; }
    if tag != 0x8001 {
        let error = ft_stream_seek(stream, 0);
        if error != 0 { return error; }
    }
    let error = ft_stream_enter_frame(stream, length);
    if error != 0 { return error; }
    let error = if memcmp((*stream).cursor, signature, length as usize) == 0 { 0 } else { 2 };
    ft_stream_exit_frame(stream);
    error
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr::null_mut;

    fn memory_stream(bytes: &mut [u8]) -> FtStream {
        FtStream {
            base: bytes.as_mut_ptr(), size: bytes.len() as u32, pos: 99,
            descriptor: null_mut(), pathname: null_mut(), read: None, close: None,
            memory: null_mut(), cursor: null_mut(), limit: null_mut(),
        }
    }

    #[test]
    fn plain_signature_rewinds_and_releases_frame_on_match_and_mismatch() {
        for (signature, expected) in [(b"%!PS" as &[u8], 0), (b"%!PX", 2)] {
            let mut bytes = *b"%!PS-AdobeFont";
            let mut stream = memory_stream(&mut bytes);
            assert_eq!(unsafe { t1_check_header(&mut stream, signature.as_ptr(), 4) }, expected);
            assert_eq!(stream.pos, 4);
            assert!(stream.cursor.is_null() && stream.limit.is_null());
        }
    }

    #[test]
    fn ascii_pfb_skips_header_without_using_declared_size() {
        for size in [0u32, 1, u32::MAX] {
            let mut bytes = [0x80, 1, 0, 0, 0, 0, b'%', b'!', b'P', b'S'];
            bytes[2..6].copy_from_slice(&size.to_le_bytes());
            let mut stream = memory_stream(&mut bytes);
            assert_eq!(unsafe { t1_check_header(&mut stream, b"%!PS".as_ptr(), 4) }, 0);
            assert_eq!(stream.pos, 10);
            assert!(stream.cursor.is_null() && stream.limit.is_null());
        }
    }

    #[test]
    fn binary_and_end_tags_are_compared_from_file_start() {
        for tag in [2u8, 3] {
            let mut bytes = [0x80, tag, 0, 0, 0, 0, b'%', b'!'];
            let signature = [0x80, tag];
            let mut stream = memory_stream(&mut bytes);
            assert_eq!(unsafe { t1_check_header(&mut stream, signature.as_ptr(), 2) }, 0);
            assert_eq!(stream.pos, 2);
        }
    }

    #[test]
    fn truncated_headers_and_frames_preserve_first_error_and_position() {
        for (bytes, count, pos) in [
            (&[0x80][..], 1, 0),
            (&[0x80, 1, 0, 0, 0][..], 1, 2),
            (&[0x80, 2, 0, 0, 0][..], 1, 2),
            (&[b'%', b'!'][..], 3, 0),
            (&[0x80, 1, 0, 0, 0, 0][..], 0, 6),
        ] {
            let mut storage = [0u8; 8];
            storage[..bytes.len()].copy_from_slice(bytes);
            let mut stream = memory_stream(&mut storage[..bytes.len()]);
            assert_eq!(unsafe { t1_check_header(&mut stream, b"%!PS".as_ptr(), count) }, 0x55);
            assert_eq!(stream.pos, pos);
            assert!(stream.cursor.is_null() && stream.limit.is_null());
        }
    }

    #[test]
    fn zero_length_comparison_still_reads_header_and_enters_frame() {
        let mut bytes = *b"%!";
        let mut stream = memory_stream(&mut bytes);
        assert_eq!(unsafe { t1_check_header(&mut stream, core::ptr::null(), 0) }, 0);
        assert_eq!(stream.pos, 0);
        assert!(stream.cursor.is_null() && stream.limit.is_null());
    }
}
