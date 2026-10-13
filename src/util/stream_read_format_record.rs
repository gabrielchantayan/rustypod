//! Tagged format-record reader — `FUN_080391e0` @ 0x080391e0.
//!
//! Raw A32 extent: 156 bytes, [0x080391e0,0x0803927c), ending in POP;
//! the next function starts with PUSH. Whole-image word decoding finds two
//! incoming plain BLs (0x08038ff0, 0x08138258), no predicated incoming BLs,
//! nine outgoing plain BLs, and no predicated outgoing BLs.
//!
//! Seek tag 6, discard six big-endian words, read a big-endian format u16,
//! and store it as record[0]. A failed lookup stores its status truncated to
//! u16. Ignore all reader results, fill the remaining five record words via
//! the verified retail helper at 0x08056fa0 with (0, 1, record), and return 0.
//!
//! Deliberate deviations: expose incoming r2 as a register seed because the
//! original PUSH initializes the u16 slot from it and a failed reader leaves
//! it unchanged. Neither caller sets r2 as an argument. Incoming r3 only
//! seeds unread scratch, replaced here by zero. The unported record helper
//! uses a fixed-address target call and an explicit host seam. No inferred
//! codec identity or extra error handling is introduced.

use super::stream_read_be16::stream_read_be16;
use super::stream_read_be32::stream_read_be32;
use super::stream_seek::StreamObject;
use super::stream_seek_tagged_entry::stream_seek_tagged_entry;

type FillFormatRecord = unsafe extern "C" fn(u32, u32, *mut u32);

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_format_record_helper(_: u32, _: u32, _: *mut u32) {
    panic!("stream_read_format_record requires the 0x08056fa0 host seam")
}

/// Host equivalent of the unported helper at 0x08056fa0.
/// Install only while no other thread is calling this module.
#[cfg(not(target_os = "none"))]
pub static mut FILL_FORMAT_RECORD: FillFormatRecord = missing_format_record_helper;

/// # Safety
/// `stream` must hold a valid stream handle below 4 GiB. `record` must be
/// word-aligned and writable for six u32 words. `incoming_r2` preserves the
/// entry register bits used only if the final halfword read fails.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn stream_read_format_record(
    stream: u32,
    record: *mut u32,
    incoming_r2: u32,
) -> i32 {
    let handle = stream as usize as *const *mut StreamObject;
    let mut ignored_word = 0u32;
    let status = unsafe { stream_seek_tagged_entry(stream, 6, &mut ignored_word) };
    let format = if status == 0 {
        unsafe { stream_read_be32(handle, &mut ignored_word) };
        unsafe { stream_read_be32(handle, &mut ignored_word) };
        unsafe { stream_read_be32(handle, &mut ignored_word) };
        unsafe { stream_read_be32(handle, &mut ignored_word) };
        unsafe { stream_read_be32(handle, &mut ignored_word) };
        unsafe { stream_read_be32(handle, &mut ignored_word) };
        let mut format = incoming_r2 as u16;
        unsafe { stream_read_be16(handle, &mut format) };
        format
    } else {
        status as u16
    };
    unsafe { record.write(format as u32) };
    #[cfg(target_os = "none")]
    unsafe { core::mem::transmute::<usize, FillFormatRecord>(0x0805_6fa0)(0, 1, record) };
    #[cfg(not(target_os = "none"))]
    unsafe { core::ptr::addr_of!(FILL_FORMAT_RECORD).read()(0, 1, record) };
    0
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use super::super::stream_seek::StreamVtable;
    use std::sync::LazyLock;

    static LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    static HANDLE: LazyLock<Option<u32>> = LazyLock::new(|| {
        let slab = try_map_u32_slab(hints::STREAM_READ_FORMAT_RECORD, 32)?;
        unsafe {
            let object = slab.add(8).cast::<StreamObject>();
            object.write(StreamObject { vtable: &VTABLE });
            slab.cast::<*mut StreamObject>().write(object);
        }
        Some(slab as usize as u32)
    });
    static mut INPUT: [u8; 80] = [0; 80];
    static mut POSITION: usize = 0;
    static mut FAIL_AT: usize = usize::MAX;

    unsafe extern "C" fn seek(_: *mut StreamObject, offset: i64) -> i32 {
        unsafe { POSITION = offset as usize };
        0
    }
    unsafe extern "C" fn tell(_: *mut StreamObject) -> i32 {
        unsafe { POSITION as i32 }
    }
    unsafe extern "C" fn read(_: *mut StreamObject, out: *mut u8, len: u32, mode: u32) -> i32 {
        assert_eq!(mode, 2);
        unsafe {
            let offset = POSITION;
            POSITION += len as usize;
            if offset == FAIL_AT { return 0; }
            assert!(offset + len as usize <= 80);
            core::ptr::copy_nonoverlapping(core::ptr::addr_of!(INPUT).cast::<u8>().add(offset), out, len as usize);
        }
        len as i32
    }
    static VTABLE: StreamVtable = StreamVtable {
        slots_00_0c: [0; 4], read_10: read, seek, opaque_18: 0, tell,
    };

    // Reference for the helper's known c00c branch and default branch,
    // independently decoded at 0x08056fe4 and 0x080570a0. Not a production port.
    unsafe extern "C" fn fill(bytes: u32, divisor: u32, record: *mut u32) {
        let output = unsafe { core::slice::from_raw_parts_mut(record, 6) };
        if output[0] == 0xc00c {
            output[1..].copy_from_slice(&[16000, 20, 160, 16000, 16]);
        } else {
            output[1..].copy_from_slice(&[bytes.wrapping_shl(3) / divisor, u32::MAX, u32::MAX, u32::MAX, u32::MAX]);
        }
    }

    fn install(tag: u32, fail_at: usize, format: u16) {
        unsafe {
            INPUT = [0; 80];
            let input = core::slice::from_raw_parts_mut(core::ptr::addr_of_mut!(INPUT).cast::<u8>(), 80);
            for (i, word) in [1u32, 0, tag, 40, 0x11223344].iter().enumerate() {
                input[8 + i * 4..12 + i * 4].copy_from_slice(&word.to_be_bytes());
            }
            for i in 0..6 { input[40 + i * 4..44 + i * 4].copy_from_slice(&(0xfedc0000u32 + i as u32).to_be_bytes()); }
            input[64..66].copy_from_slice(&format.to_be_bytes());
            POSITION = 0;
            FAIL_AT = fail_at;
            FILL_FORMAT_RECORD = fill;
        }
    }

    #[test]
    fn reads_format_after_six_words_even_when_discard_read_fails() {
        let _lock = LOCK.lock();
        let Some(handle) = *HANDLE else { note_missing_u32_fixture("stream_read_format_record"); return; };
        for failure in [usize::MAX, 40, 60] {
            install(6, failure, 0xc00c);
            let mut guarded = [0xdeadbeef; 8];
            assert_eq!(unsafe { stream_read_format_record(handle, guarded.as_mut_ptr().add(1), 0xaaaa1234) }, 0);
            assert_eq!(guarded, [0xdeadbeef, 0xc00c, 16000, 20, 160, 16000, 16, 0xdeadbeef]);
            assert_eq!(unsafe { POSITION }, 66);
        }
    }

    #[test]
    fn missing_tag_truncates_error_and_does_not_read_payload() {
        let _lock = LOCK.lock();
        let Some(handle) = *HANDLE else { note_missing_u32_fixture("stream_read_format_record"); return; };
        install(3, usize::MAX, 0xc00c);
        let mut record = [0xdeadbeef; 6];
        assert_eq!(unsafe { stream_read_format_record(handle, record.as_mut_ptr(), 0xc00c) }, 0);
        assert_eq!(record, [0xffe8, 0, u32::MAX, u32::MAX, u32::MAX, u32::MAX]);
        assert_eq!(unsafe { POSITION }, 28);
    }

    #[test]
    fn failed_halfword_read_preserves_low_entry_register_bits() {
        let _lock = LOCK.lock();
        let Some(handle) = *HANDLE else { note_missing_u32_fixture("stream_read_format_record"); return; };
        for seed in [0xabc_dc00c, 0xffff0000, 0x1234ffff] {
            install(6, 64, 0x9999);
            let mut record = [0xdeadbeef; 6];
            unsafe { stream_read_format_record(handle, record.as_mut_ptr(), seed) };
            let expected = if seed as u16 == 0xc00c {
                [0xc00c, 16000, 20, 160, 16000, 16]
            } else {
                [seed & 0xffff, 0, u32::MAX, u32::MAX, u32::MAX, u32::MAX]
            };
            assert_eq!(record, expected);
        }
    }
}
