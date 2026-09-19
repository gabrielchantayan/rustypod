//! `read_record_preamble` — original: `FUN_08028e4c` @ 0x08028e4c (200
//! bytes, 4 plain `bl` call sites, zero predicated `bl` call sites).
//!
//! Seeks the stream to its start, rejects names longer than 512 bytes, then
//! reads a two-word record preamble. The first word must be one of the paired
//! mode sentinels `0x44332211` and `0x11223344`; it selects mode 1 or 0
//! respectively. The second word is transformed for that mode and accepted
//! only when it is in the inclusive range 1..=9.
//!
//! Deliberate deviations: the retail fseek result is discarded; this port
//! likewise invokes [`fseek`] and deliberately ignores its status. Typed
//! pointers replace the original stack-word aliases without changing the
//! target's four-byte word accesses.

use crate::libc::strlen::strlen;
use crate::stdio::fread::fread;
use crate::stdio::stdio_init::fseek;
use crate::stdio::stream_file::AdsFile;
use crate::util::bswap::transform_word_for_mode;

const MODE_ONE_SENTINEL: u32 = 0x4433_2211;
const MODE_ZERO_SENTINEL: u32 = 0x1122_3344;
const MAX_RECORD_NAME_LEN: usize = 0x200;

/// Reads and validates the first two words of a record stream.
///
/// Returns 0 for an accepted preamble; 6 when `name` exceeds 512 bytes; and
/// 1 for a null stream, malformed sentinel, short read, or a transformed
/// second word outside 1..=9. Pointer arguments have the retail ABI and must
/// point to writable four-byte words when reached.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn read_record_preamble(
    file: *mut AdsFile,
    name: *const u8,
    sentinel_out: *mut u32,
    mode_out: *mut u32,
    record_kind_out: *mut u32,
) -> i32 {
    if file.is_null() {
        return 1;
    }

    let _ = fseek(file, 0, 0);
    if strlen(name) > MAX_RECORD_NAME_LEN {
        return 6;
    }
    if fread(sentinel_out.cast(), 1, 4, core::ptr::addr_of_mut!((*file).stream)) != 4 {
        return 1;
    }

    let sentinel = *sentinel_out;
    let mode = if sentinel == MODE_ONE_SENTINEL {
        1
    } else if sentinel == MODE_ZERO_SENTINEL {
        0
    } else {
        return 1;
    };
    *mode_out = mode;

    if fread(record_kind_out.cast(), 1, 4, core::ptr::addr_of_mut!((*file).stream)) != 4 {
        return 1;
    }
    let record_kind = transform_word_for_mode(mode, *record_kind_out);
    *record_kind_out = record_kind;
    if record_kind.wrapping_sub(1) < 9 { 0 } else { 1 }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::semihost::tests::{mock_swi, restore_swi};
    use crate::stdio::seek_core::fseek_core;
    use crate::stdio::stdio_init::{StreamSeekFn, STREAM_SEEK_CORE};
    use crate::stdio::stream_file::ADS_FILE_ZERO;

    unsafe extern "C" fn seek_start_stub(_file: *mut AdsFile, _offset: i32, _whence: i32) -> i32 {
        0
    }

    unsafe fn with_stream(bytes: &mut [u8]) -> AdsFile {
        let mut file = ADS_FILE_ZERO;
        file.stream.flags = 0;
        file.stream.count = bytes.len() as i32;
        file.stream.base = bytes.as_mut_ptr();
        file.stream.ptr = bytes.as_mut_ptr();
        file.stream.lim = bytes.as_mut_ptr();
        file.field_30 = bytes.len() as u32;
        file
    }

    unsafe fn call_with_seek_stub(
        file: *mut AdsFile,
        name: *const u8,
        sentinel_out: *mut u32,
        mode_out: *mut u32,
        record_kind_out: *mut u32,
    ) -> i32 {
        let guard = mock_swi(&[]);
        STREAM_SEEK_CORE = seek_start_stub as StreamSeekFn;
        let result = read_record_preamble(file, name, sentinel_out, mode_out, record_kind_out);
        STREAM_SEEK_CORE = fseek_core;
        restore_swi();
        drop(guard);
        result
    }

    #[test]
    fn accepts_both_mode_sentinels_and_transforms_only_mode_one() {
        let name = b"record\0";
        let mut mode_one = [0x11, 0x22, 0x33, 0x44, 0, 0, 0, 1];
        let mut mode_zero = [0x44, 0x33, 0x22, 0x11, 1, 0, 0, 0];
        unsafe {
            let mut file = with_stream(&mut mode_one);
            let (mut sentinel, mut mode, mut kind) = (0, 99, 0);
            assert_eq!(call_with_seek_stub(&mut file, name.as_ptr(), &mut sentinel, &mut mode, &mut kind), 0);
            assert_eq!((sentinel, mode, kind), (MODE_ONE_SENTINEL, 1, 1));

            let mut file = with_stream(&mut mode_zero);
            let (mut sentinel, mut mode, mut kind) = (0, 99, 0);
            assert_eq!(call_with_seek_stub(&mut file, name.as_ptr(), &mut sentinel, &mut mode, &mut kind), 0);
            assert_eq!((sentinel, mode, kind), (MODE_ZERO_SENTINEL, 0, 1));
        }
    }

    #[test]
    fn preserves_retail_failure_order_and_range_edges() {
        let name = b"record\0";
        unsafe {
            let mut invalid_sentinel = [0u8; 8];
            let mut file = with_stream(&mut invalid_sentinel);
            let (mut sentinel, mut mode, mut kind) = (0, 77, 88);
            assert_eq!(call_with_seek_stub(&mut file, name.as_ptr(), &mut sentinel, &mut mode, &mut kind), 1);
            assert_eq!((mode, kind), (77, 88), "invalid first word stops before later outputs");

            for (kind_word, expected) in [(0u32, 1), (1, 0), (9, 0), (10, 1)] {
                let mut bytes = [0x44, 0x33, 0x22, 0x11, 0, 0, 0, 0];
                bytes[4..].copy_from_slice(&kind_word.to_le_bytes());
                let mut file = with_stream(&mut bytes);
                let (mut sentinel, mut mode, mut kind) = (0, 99, 99);
                assert_eq!(call_with_seek_stub(&mut file, name.as_ptr(), &mut sentinel, &mut mode, &mut kind), expected);
                assert_eq!((mode, kind), (0, kind_word));
            }

            let mut short = [0x11, 0x22, 0x33, 0x44];
            let mut file = with_stream(&mut short);
            let (mut sentinel, mut mode, mut kind) = (0, 99, 88);
            assert_eq!(call_with_seek_stub(&mut file, name.as_ptr(), &mut sentinel, &mut mode, &mut kind), 1);
            assert_eq!((sentinel, mode, kind), (MODE_ONE_SENTINEL, 1, 88));
        }
    }

    #[test]
    fn rejects_long_names_before_any_read() {
        let mut name = [b'x'; 514];
        name[513] = 0;
        unsafe {
            let mut file = ADS_FILE_ZERO;
            let (mut sentinel, mut mode, mut kind) = (11, 22, 33);
            assert_eq!(call_with_seek_stub(&mut file, name.as_ptr(), &mut sentinel, &mut mode, &mut kind), 6);
            assert_eq!((sentinel, mode, kind), (11, 22, 33));
        }
    }
}
