//! Type 1 PFB segment-header reader.

use crate::ft::stream::{ft_stream_read_long_le, ft_stream_read_short, FtStream};

/// t1_read_pfb_segment_header — original: `FUN_0807d4d4` @ 0x0807d4d4
/// (116 bytes; 2 unpredicated `bl` instructions, 0 predicated `bl`
/// instructions, verified from the raw firmware through the next function
/// boundary at 0x0807d548).
///
/// Clears `*tag` and `*size`, then reads the big-endian PFB segment tag. For
/// the PFB ASCII and binary segment tags (`0x8001` and `0x8002`), reads the
/// following little-endian 32-bit segment size. A reader error prevents the
/// corresponding result store and is returned unchanged. Deliberate
/// deviation: the retail helper's incoming r3 is represented explicitly as
/// `error`, rather than relying on the ABI register's prior value.
///
/// # Safety
/// `stream`, `tag`, and `size` must be valid pointers. `stream` must satisfy
/// the read helpers' safety requirements.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn t1_read_pfb_segment_header(
    stream: *mut FtStream,
    tag: *mut u16,
    size: *mut u32,
    mut error: i32,
) -> i32 {
    *tag = 0;
    *size = 0;

    let segment_tag = ft_stream_read_short(stream, &mut error);
    if error == 0 {
        let segment_tag = segment_tag as u16;
        if segment_tag == 0x8001 || segment_tag == 0x8002 {
            let segment_size = ft_stream_read_long_le(stream, &mut error);
            if error == 0 {
                *size = segment_size as u32;
            }
        }
        *tag = segment_tag;
    }
    error
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr::null_mut;

    fn memory_stream(bytes: &mut [u8]) -> FtStream {
        FtStream {
            base: bytes.as_mut_ptr(), size: bytes.len() as u32, pos: 0,
            descriptor: null_mut(), pathname: null_mut(), read: None, close: None,
            memory: null_mut(), cursor: null_mut(), limit: null_mut(),
        }
    }

    #[test]
    fn reads_pfb_ascii_and_binary_segment_sizes() {
        for (tag_bytes, expected_tag) in [([0x80, 0x01], 0x8001), ([0x80, 0x02], 0x8002)] {
            let mut bytes = [tag_bytes[0], tag_bytes[1], 0x78, 0x56, 0x34, 0x12];
            let mut stream = memory_stream(&mut bytes);
            let (mut tag, mut size) = (0xffff, u32::MAX);
            assert_eq!(unsafe { t1_read_pfb_segment_header(&mut stream, &mut tag, &mut size, 0) }, 0);
            assert_eq!((tag, size, stream.pos), (expected_tag, 0x1234_5678, 6));
        }
    }

    #[test]
    fn non_pfb_tag_does_not_consume_a_size() {
        let mut bytes = [0x12, 0x34, 0xaa, 0xbb, 0xcc, 0xdd];
        let mut stream = memory_stream(&mut bytes);
        let (mut tag, mut size) = (0xffff, u32::MAX);
        assert_eq!(unsafe { t1_read_pfb_segment_header(&mut stream, &mut tag, &mut size, 0) }, 0);
        assert_eq!((tag, size, stream.pos), (0x1234, 0, 2));
    }

    #[test]
    fn preserves_zeroed_outputs_on_short_or_long_read_error() {
        let mut short = [0x80];
        let mut stream = memory_stream(&mut short);
        let (mut tag, mut size) = (0xffff, u32::MAX);
        assert_eq!(unsafe { t1_read_pfb_segment_header(&mut stream, &mut tag, &mut size, 0) }, 0x55);
        assert_eq!((tag, size, stream.pos), (0, 0, 0));

        let mut long = [0x80, 0x01, 0x12, 0x34, 0x56];
        let mut stream = memory_stream(&mut long);
        let (mut tag, mut size) = (0xffff, u32::MAX);
        assert_eq!(unsafe { t1_read_pfb_segment_header(&mut stream, &mut tag, &mut size, 0) }, 0x55);
        assert_eq!((tag, size, stream.pos), (0x8001, 0, 2));
    }
}
