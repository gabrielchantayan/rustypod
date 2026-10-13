//! `read_and_decode_record` — FUN_08029858 @ 0x08029858.
//! True size: 136 bytes, bounded by the PUSH at 0x080298e0.
//! Raw aligned A32 scan: two incoming plain BLs (0x08029ad8,
//! 0x08029e24), three outgoing plain BLs (fread, legacy decoder,
//! extended decoder), and zero predicated BLs in either direction.
//!
//! Read length one-byte items into scratch. A short read returns 4 without
//! decoding; a complete read selects the legacy decoder for versions 1/2
//! or the extended decoder for signed versions >=3. Other versions return
//! 4 after reading. Decoder status is returned unchanged.
//!
//! Deliberate deviations: typed pointers retain the target ABI. Unported
//! decoders use the existing buffered_record_decode firmware/host seams;
//! no extra validation, allocation, or rollback is introduced.

use crate::stdio::fread::{fread, AdsStream};

/// # Safety
/// Stream must be a valid ADS FILE prefix. Scratch must hold the requested
/// read and satisfy the selected decoder's alignment/layout requirements.
/// Output must satisfy that decoder's writable extent/layout requirements.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn read_and_decode_record(
    stream: *mut AdsStream, length: i32, version: i32, mode: u32,
    scratch: *mut u8, output: *mut u32,
) -> u32 {
    if fread(scratch, 1, length, stream) != length { return 4; }
    type DecodeRecord = unsafe extern "C" fn(i32, i32, u32, *mut u8, *mut u32) -> u32;
    let decoder: DecodeRecord;
    if version == 1 || version == 2 {
        #[cfg(target_os = "none")]
        { decoder = core::mem::transmute::<usize, DecodeRecord>(0x0802_9630); }
        #[cfg(not(target_os = "none"))]
        { decoder = core::ptr::addr_of!(crate::util::buffered_record_decode::LEGACY_RECORD_DECODE).read(); }
    } else if version >= 3 {
        #[cfg(target_os = "none")]
        { decoder = core::mem::transmute::<usize, DecodeRecord>(0x0802_974c); }
        #[cfg(not(target_os = "none"))]
        { decoder = core::ptr::addr_of!(crate::util::buffered_record_decode::EXTENDED_RECORD_DECODE).read(); }
    } else { return 4; }
    decoder(length, version, mode, scratch, output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stdio::stream_file::ADS_FILE_ZERO;

    #[test]
    fn unsupported_signed_versions_still_read_and_preserve_output() {
        for version in [i32::MIN, -1, 0] {
            for length in [0, 1, 4] {
                let mut input = [0x12, 0x34, 0x56, 0x78];
                let mut file = ADS_FILE_ZERO;
                file.stream.count = 4;
                file.stream.ptr = input.as_mut_ptr();
                file.stream.base = input.as_mut_ptr();
                let mut scratch = [0xaau8; 6];
                let mut output = [0xdead_beefu32; 4];
                unsafe {
                    assert_eq!(read_and_decode_record(&mut file.stream, length, version, 1,
                        scratch.as_mut_ptr().add(1), output.as_mut_ptr()), 4);
                }
                assert_eq!(&scratch[1..1 + length as usize], &input[..length as usize]);
                assert_eq!(scratch[0], 0xaa);
                assert!(scratch[1 + length as usize..].iter().all(|&b| b == 0xaa));
                assert_eq!(file.stream.count, 4 - length);
                assert_eq!(output, [0xdead_beef; 4]);
            }
        }
    }

    #[test]
    fn short_read_precedes_version_dispatch_and_keeps_partial_bytes() {
        let _guard = crate::stdio::fread::tests::HOOK_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        for version in [1, 2, 3, i32::MAX, 0] {
            let mut input = [0x12, 0x34];
            let mut file = ADS_FILE_ZERO;
            file.stream.count = 2;
            file.stream.ptr = input.as_mut_ptr();
            file.stream.base = input.as_mut_ptr();
            file.stream.flags = crate::stdio::fread::FLAG_ERROR;
            file.field_30 = 2;
            let mut scratch = [0xaa; 5];
            let mut output = [0xdead_beef; 4];
            unsafe {
                assert_eq!(read_and_decode_record(&mut file.stream, 4, version, 0,
                    scratch.as_mut_ptr(), output.as_mut_ptr()), 4);
            }
            assert_eq!(scratch, [0x12, 0x34, 0xaa, 0xaa, 0xaa]);
            assert_eq!(file.stream.count, 0);
            assert_eq!(output, [0xdead_beef; 4]);
        }
    }
}
