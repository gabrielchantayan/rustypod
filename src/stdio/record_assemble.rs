//! `assemble_record_from_stream` — `FUN_080298e0` @ 0x080298e0.
//! True extent: 156 bytes, ending at the next function's push @ 0x0802997c.
//! Raw ARM scan: two incoming plain BLs (0x08029bf8, 0x08029f54), zero
//! predicated BLs; four outgoing plain BLs, zero predicated BLs.
//!
//! Writes the sentinel unchanged and transforms the kind, payload length,
//! and prefix length only for mode 1. Copies the prefix in ascending byte
//! order, then reads payload_length one-byte items after it. Returns 4 on a
//! short read, leaving size_out untouched; otherwise writes the wrapping
//! sum prefix_length + payload_length + 16 and returns 0. The signed prefix
//! loop skips nonpositive lengths, but the header retains their bit pattern.
//!
//! Deliberate deviations: typed stream/word pointers preserve target layout;
//! volatile byte accesses preserve forward overlap and prevent LLVM memcpy
//! substitution. No additional validation or rollback is performed.

use crate::stdio::fread::{fread, AdsStream};
use crate::util::bswap::transform_word_for_mode;

/// # Safety
/// `output` is word-aligned and writable for the header and copied/read bytes.
/// Positive prefix lengths require readable prefix bytes; overlapping prefix
/// and output storage is allowed with retail forward-copy semantics. `stream`
/// must reference a valid ADS FILE prefix, and `size_out` must be writable on
/// success. Sizes and buffer capacities are the caller's responsibility.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn assemble_record_from_stream(
    stream: *mut AdsStream,
    sentinel: u32,
    record_kind: u32,
    payload_length: i32,
    prefix_length: i32,
    prefix: *const u8,
    mode: u32,
    output: *mut u32,
    size_out: *mut u32,
) -> i32 {
    let kind = transform_word_for_mode(mode, record_kind);
    let payload_size = transform_word_for_mode(mode, payload_length as u32);
    let prefix_size = transform_word_for_mode(mode, prefix_length as u32);
    output.add(3).write(prefix_size);
    output.write(sentinel);
    output.add(1).write(kind);
    output.add(2).write(payload_size);
    let mut cursor = output.add(4).cast::<u8>();
    let mut index = 0;
    while index < prefix_length {
        cursor.write_volatile(prefix.add(index as usize).read_volatile());
        cursor = cursor.add(1);
        index += 1;
    }
    if fread(cursor, 1, payload_length, stream) != payload_length {
        return 4;
    }
    size_out.write((prefix_length as u32).wrapping_add(payload_length as u32).wrapping_add(16));
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stdio::stream_file::ADS_FILE_ZERO;

    #[test]
    fn headers_and_bytes_match_for_modes_and_length_edges() {
        unsafe {
            for mode in [0, 1, 2, u32::MAX] {
                for prefix_length in [-1, 0, 1, 7] {
                    for payload_length in [-1, 0, 1, 5] {
                        let mut payload = [0x91, 0x82, 0x73, 0x64, 0x55];
                        let prefix = [1, 2, 3, 4, 5, 6, 7];
                        let mut file = ADS_FILE_ZERO;
                        file.stream.count = payload.len() as i32;
                        file.stream.ptr = payload.as_mut_ptr();
                        file.stream.base = payload.as_mut_ptr();
                        let mut output = [0xcccc_ccccu32; 12];
                        let mut size = 0;
                        assert_eq!(assemble_record_from_stream(&mut file.stream, 0x1122_3344,
                            0x1234_5678, payload_length, prefix_length, prefix.as_ptr(), mode,
                            output.as_mut_ptr(), &mut size), 0);
                        let encode = |word: u32| if mode == 1 { word.swap_bytes() } else { word };
                        assert_eq!(&output[..4], &[0x1122_3344, encode(0x1234_5678),
                            encode(payload_length as u32), encode(prefix_length as u32)]);
                        let bytes = core::slice::from_raw_parts(output.as_ptr().cast::<u8>(), 48);
                        let n = prefix_length.max(0) as usize;
                        let p = payload_length.max(0) as usize;
                        assert_eq!(&bytes[16..16 + n], &prefix[..n]);
                        assert_eq!(&bytes[16 + n..16 + n + p], &payload[..p]);
                        assert!(bytes[16 + n + p..].iter().all(|&b| b == 0xcc));
                        assert_eq!(file.stream.count, 5 - p as i32);
                        assert_eq!(size, (prefix_length as u32).wrapping_add(payload_length as u32).wrapping_add(16));
                    }
                }
            }
        }
    }

    #[test]
    fn short_read_keeps_partial_record_and_size_sentinel() {
        let _guard = crate::stdio::fread::tests::HOOK_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let mut payload = [0xa1, 0xb2];
            let mut file = ADS_FILE_ZERO;
            file.stream.count = 2;
            file.stream.ptr = payload.as_mut_ptr();
            file.stream.base = payload.as_mut_ptr();
            file.stream.flags = crate::stdio::fread::FLAG_ERROR;
            file.field_30 = 2;
            let prefix = [0x35, 0x46, 0x57];
            let mut output = [0xcccc_ccccu32; 8];
            let mut size = 0xdead_beef;
            assert_eq!(assemble_record_from_stream(&mut file.stream, 9, 8, 4, 3,
                prefix.as_ptr(), 0, output.as_mut_ptr(), &mut size), 4);
            assert_eq!(&output[..4], &[9, 8, 4, 3]);
            let bytes = core::slice::from_raw_parts(output.as_ptr().cast::<u8>(), 32);
            assert_eq!(&bytes[16..21], &[0x35, 0x46, 0x57, 0xa1, 0xb2]);
            assert!(bytes[21..].iter().all(|&b| b == 0xcc));
            assert_eq!(size, 0xdead_beef);
            assert_eq!(file.stream.count, 0);
        }
    }

    #[test]
    fn overlapping_prefix_is_copied_forward_and_size_wraps() {
        unsafe {
            let mut file = ADS_FILE_ZERO;
            let mut output = [0u32; 8];
            let bytes = output.as_mut_ptr().cast::<u8>();
            let mut size = 0;
            // Mode one writes the prefix length's high byte (5) at byte 15.
            // Each copied byte becomes the source of the next overlap step.
            assert_eq!(assemble_record_from_stream(&mut file.stream, 1, 2, 0, 5,
                bytes.add(15), 1, output.as_mut_ptr(), &mut size), 0);
            assert_eq!(core::slice::from_raw_parts(bytes.add(16), 5), &[5; 5]);
            assert_eq!(size, 21);
            assert_eq!(assemble_record_from_stream(&mut file.stream, 1, 2, 0, i32::MIN,
                core::ptr::null(), 0, output.as_mut_ptr(), &mut size), 0);
            assert_eq!(size, 0x8000_0010);
        }
    }
}
