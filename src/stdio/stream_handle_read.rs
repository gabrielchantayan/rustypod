//! Stream-handle byte reader — FUN_08266b84 @ 0x08266b84.
//!
//! True extent: 60 bytes, ending at the next prologue @ 0x08266bc0.
//! Raw-word verification: 2 unconditional BLs and 1 predicated BL (bleq).
//! Reads up to the wrapping 32-bit product of size and nitems through
//! stream_read_chars, then clears EOF/sticky state only if the stream's
//! error indicator is clear. Returns bytes, not whole items; short reads
//! are not retried. The stream pointer is reloaded after the read and
//! before the conditional clear, as in the original.
//! Deviations: existing Rust stream layouts widen pointers on hosts;
//! the flag accessors may inline rather than retain the original BLs.

use crate::stdio::fread::{AdsStream, stream_read_chars};
use crate::stdio::stream_flags::{stream_clear_error, stream_test_error_flag};

/// `handle` points to a readable stream-pointer slot. The destination must
/// satisfy stream_read_chars' buffer requirements for the wrapping product.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn stream_handle_read(
    handle: *const *mut AdsStream,
    dest: *mut u8,
    size: i32,
    nitems: i32,
) -> i32 {
    let read = stream_read_chars(dest, size.wrapping_mul(nitems), *handle);
    if stream_test_error_flag(*handle) == 0 {
        stream_clear_error(*handle);
    }
    read
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stdio::stream_flags::{FLAG_STREAM_ERROR, FLAG_STREAM_EOF, FLAG_STREAM_STICKY};

    fn stream(buf: &mut [u8], flags: u32) -> AdsStream {
        AdsStream {
            count: buf.len() as i32, ptr: buf.as_mut_ptr(), field_08: 0,
            flags, base: buf.as_mut_ptr(), handle: 0, offset_end: 0,
            bulk_threshold: 0, field_20: 0, field_24: 0, alt_offset: 0,
            lim: buf.as_mut_ptr(),
        }
    }

    #[test]
    fn short_read_returns_bytes_and_clears_indicators_without_retry() {
        let mut buf = *b"abc";
        let mut s = stream(&mut buf, FLAG_STREAM_EOF | FLAG_STREAM_STICKY | 1);
        let slot = &mut s as *mut AdsStream;
        let mut dest = [0xcc; 8];
        unsafe { assert_eq!(stream_handle_read(&slot, dest.as_mut_ptr(), 2, 3), 3); }
        assert_eq!(dest, [b'a', b'b', b'c', 0xcc, 0xcc, 0xcc, 0xcc, 0xcc]);
        assert_eq!(s.flags, 1);
        assert_eq!(s.count, 0);
        assert_eq!(s.ptr, unsafe { buf.as_mut_ptr().add(3) });
    }

    #[test]
    fn error_indicator_preserves_all_flags_and_read_result() {
        let mut buf = *b"abcd";
        let flags = FLAG_STREAM_ERROR | FLAG_STREAM_EOF | FLAG_STREAM_STICKY | 1;
        let mut s = stream(&mut buf, flags);
        let slot = &mut s as *mut AdsStream;
        let mut dest = [0xcc; 4];
        unsafe { assert_eq!(stream_handle_read(&slot, dest.as_mut_ptr(), 1, 2), 2); }
        assert_eq!(dest, [b'a', b'b', 0xcc, 0xcc]);
        assert_eq!(s.flags, flags);
        assert_eq!(s.count, 2);
    }

    #[test]
    fn zero_and_overflow_products_still_clear_nonerror_indicators() {
        for (size, nitems) in [(0, 7), (65536, 65536), (i32::MIN, 2), (-1, -2)] {
            let mut buf = *b"abcd";
            let mut s = stream(&mut buf, FLAG_STREAM_EOF | FLAG_STREAM_STICKY | 1);
            let slot = &mut s as *mut AdsStream;
            let mut dest = [0xcc; 4];
            let expected = size.wrapping_mul(nitems) as usize;
            unsafe { assert_eq!(stream_handle_read(&slot, dest.as_mut_ptr(), size, nitems), expected as i32); }
            assert_eq!(&dest[..expected], &buf[..expected]);
            assert_eq!(&dest[expected..], &[0xcc; 4][expected..]);
            assert_eq!(s.count, 4 - expected as i32);
            assert_eq!(s.flags, 1);
        }
    }
}
