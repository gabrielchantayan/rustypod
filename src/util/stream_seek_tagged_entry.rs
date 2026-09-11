//! Tagged stream-index entry seeker — `stream_seek_tagged_entry` @ 0x080570cc.
//!
//! Original: `FUN_080570cc` @ 0x080570cc (152 bytes; raw ARM confirms the
//! following `bx lr` sibling starts at 0x08057164). Decoding every ARM B/BL
//! word in osos.dec finds 10 direct call sites: all are plain unconditional
//! `bl`, with no predicated calls.
//!
//! Algorithm: seek the stream to absolute offset 8 and read the signed entry
//! count plus a second, ignored header word. Each entry contains a big-endian
//! tag, absolute seek offset, and third value. The function reads entries in
//! order, writing the third value through `out_entry_value` for every
//! successful read. On a matching tag it seeks to that entry's offset and
//! returns zero; after a signed-count-bounded miss it returns -24. Every
//! stream read and seek status is deliberately ignored, as in the raw ARM.
//!
//! Deliberate deviations: named locals replace the retail stack slots. The
//! exact header's second word and the third entry word have no established
//! format-level identity, so they remain explicitly opaque rather than being
//! assigned an invented media-database meaning.

use super::stream_read_be32::stream_read_be32;
use super::stream_read_be32_or_zero::stream_read_be32_or_zero;
use super::stream_seek::{stream_seek, StreamObject};

/// stream_seek_tagged_entry — original: `FUN_080570cc` @ 0x080570cc (152
/// bytes; 10 unpredicated `bl` call sites, verified by decoding every ARM
/// B/BL word in osos.dec).
///
/// Seeks `stream` to byte 8, scans its signed-count tagged index entries,
/// and leaves the stream at the matching entry's absolute offset. Each entry
/// is `{ tag, offset, value }` in big-endian u32 words. `out_entry_value` is
/// supplied to the direct third-word reader on every iteration, so a failed
/// read leaves its prior value untouched; the result is `0` on a tag match
/// and `-24` when the signed count is exhausted. Seek and read statuses are
/// intentionally ignored, matching retailOS.
///
/// # Safety
///
/// `stream` is the target-width stream handle passed to the existing stream
/// wrappers. It must be a valid pointer to the stream object pointer whenever
/// the wrapper dereferences it. `out_entry_value` must be valid for a u32
/// store whenever the third word read succeeds. The original has no NULL
/// checks for either argument.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.stream_seek_tagged_entry")]
pub unsafe extern "C" fn stream_seek_tagged_entry(
    stream: u32,
    entry_tag: u32,
    out_entry_value: *mut u32,
) -> i32 {
    let stream_handle = stream as usize as *const *mut StreamObject;
    unsafe { stream_seek(stream_handle, 8) };

    let mut entry_count = 0u32;
    unsafe { stream_read_be32_or_zero(stream, &mut entry_count) };
    let mut ignored_header_word = 0u32;
    unsafe { stream_read_be32_or_zero(stream, &mut ignored_header_word) };

    let mut entry_index = 0i32;
    while entry_index < entry_count as i32 {
        let mut tag = 0u32;
        unsafe { stream_read_be32_or_zero(stream, &mut tag) };
        let mut offset = 0u32;
        unsafe { stream_read_be32_or_zero(stream, &mut offset) };
        unsafe { stream_read_be32(stream, out_entry_value) };

        if tag == entry_tag {
            unsafe { stream_seek(stream_handle, offset as i32) };
            return 0;
        }
        entry_index = entry_index.wrapping_add(1);
    }

    -24
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab, STREAM_READ_CORE_TEST_LOCK};
    use crate::util::stream_read_be32::{reset_stream_read_core, STREAM_READ_CORE};
    use crate::util::stream_seek::StreamVtable;
    use std::sync::LazyLock;

    static HANDLE: LazyLock<Option<u32>> = LazyLock::new(|| {
        let base = try_map_u32_slab(hints::STREAM_SEEK_TAGGED_ENTRY, 32)?;
        unsafe {
            let object = base.add(8).cast::<StreamObject>();
            object.write(StreamObject { vtable: &STREAM_VTABLE });
            base.cast::<*mut StreamObject>().write(object);
        }
        Some(base as usize as u32)
    });
    static mut INPUT: [u8; 128] = [0; 128];
    static mut INPUT_LEN: usize = 0;
    static mut READ_CALL: usize = 0;
    static mut FAILED_READ: usize = usize::MAX;
    static mut SEEK_CALLS: usize = 0;
    static mut SEEK_POSITIONS: [i64; 2] = [0; 2];
    static mut SEEK_STATUS: i32 = 0;

    unsafe extern "C" fn recording_seek(_this: *mut StreamObject, position: i64) -> i32 {
        unsafe {
            let call = core::ptr::addr_of!(SEEK_CALLS).read();
            assert!(call < 2, "the target function makes at most two seeks");
            core::ptr::addr_of_mut!(SEEK_POSITIONS).cast::<i64>().add(call).write(position);
            core::ptr::addr_of_mut!(SEEK_CALLS).write(call + 1);
            core::ptr::addr_of!(SEEK_STATUS).read()
        }
    }

    unsafe extern "C" fn unused_tell(_this: *mut StreamObject) -> i32 {
        0
    }

    static STREAM_VTABLE: StreamVtable = StreamVtable {
        slots_00_0c: [0; 4],
        read_10: 0,
        seek: recording_seek,
        opaque_18: 0,
        tell: unused_tell,
    };

    unsafe extern "C" fn fake_stream_read_core(
        _stream: u32,
        buf: *mut u8,
        len: u32,
        _err_out: *mut u32,
    ) -> i32 {
        unsafe {
            assert_eq!(len, 4);
            let call = core::ptr::addr_of!(READ_CALL).read();
            core::ptr::addr_of_mut!(READ_CALL).write(call + 1);
            if call == core::ptr::addr_of!(FAILED_READ).read() {
                return -3;
            }
            let offset = call * 4;
            assert!(offset + 4 <= core::ptr::addr_of!(INPUT_LEN).read());
            core::ptr::copy_nonoverlapping(
                core::ptr::addr_of!(INPUT).cast::<u8>().add(offset),
                buf,
                4,
            );
            0
        }
    }

    struct CoreReset;

    impl Drop for CoreReset {
        fn drop(&mut self) {
            unsafe { reset_stream_read_core() };
        }
    }

    fn stream_handle() -> Option<u32> {
        *HANDLE
    }

    fn install_reads(words: &[u32], failed_read: usize, seek_status: i32) {
        assert!(words.len() * 4 <= unsafe { core::ptr::addr_of!(INPUT).read().len() });
        unsafe {
            for (index, word) in words.iter().enumerate() {
                core::ptr::copy_nonoverlapping(
                    word.to_be_bytes().as_ptr(),
                    core::ptr::addr_of_mut!(INPUT).cast::<u8>().add(index * 4),
                    4,
                );
            }
            core::ptr::addr_of_mut!(INPUT_LEN).write(words.len() * 4);
            core::ptr::addr_of_mut!(READ_CALL).write(0);
            core::ptr::addr_of_mut!(FAILED_READ).write(failed_read);
            core::ptr::addr_of_mut!(SEEK_CALLS).write(0);
            core::ptr::addr_of_mut!(SEEK_POSITIONS).write([0; 2]);
            core::ptr::addr_of_mut!(SEEK_STATUS).write(seek_status);
            core::ptr::addr_of_mut!(STREAM_READ_CORE).write_volatile(fake_stream_read_core);
        }
    }

    #[test]
    fn seeks_to_matching_entry_and_stores_its_third_word() {
        let _lock = STREAM_READ_CORE_TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let Some(stream) = stream_handle() else {
            note_missing_u32_fixture("util/stream_seek_tagged_entry");
            return;
        };
        install_reads(
            &[2, 0x1122_3344, 0x101, 0x400, 0xdead_beef, 0x202, 0x800, 0xcafe_babe],
            usize::MAX,
            0,
        );
        let _reset = CoreReset;
        let mut value = 0;

        let result = unsafe { stream_seek_tagged_entry(stream, 0x202, &mut value) };

        assert_eq!(result, 0);
        assert_eq!(value, 0xcafe_babe);
        assert_eq!(unsafe { core::ptr::addr_of!(READ_CALL).read() }, 8);
        assert_eq!(unsafe { core::ptr::addr_of!(SEEK_CALLS).read() }, 2);
        assert_eq!(unsafe { core::ptr::addr_of!(SEEK_POSITIONS).read() }, [8, 0x800]);
    }

    #[test]
    fn missing_tag_returns_minus_twenty_four_after_scanning_signed_count() {
        let _lock = STREAM_READ_CORE_TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let Some(stream) = stream_handle() else {
            note_missing_u32_fixture("util/stream_seek_tagged_entry");
            return;
        };
        install_reads(&[1, 0, 0x101, 0x400, 0xdead_beef], usize::MAX, 0);
        let _reset = CoreReset;
        let mut value = 0;

        let result = unsafe { stream_seek_tagged_entry(stream, 0x202, &mut value) };

        assert_eq!(result, -24);
        assert_eq!(value, 0xdead_beef, "nonmatching entries still write the third word");
        assert_eq!(unsafe { core::ptr::addr_of!(SEEK_CALLS).read() }, 1);
        assert_eq!(unsafe { core::ptr::addr_of!(SEEK_POSITIONS).read() }, [8, 0]);
    }

    #[test]
    fn negative_signed_count_skips_the_entry_loop() {
        let _lock = STREAM_READ_CORE_TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let Some(stream) = stream_handle() else {
            note_missing_u32_fixture("util/stream_seek_tagged_entry");
            return;
        };
        install_reads(&[0x8000_0000, 0], usize::MAX, 0);
        let _reset = CoreReset;
        let mut value = 0x5afe_5afe;

        let result = unsafe { stream_seek_tagged_entry(stream, 0x202, &mut value) };

        assert_eq!(result, -24);
        assert_eq!(value, 0x5afe_5afe);
        assert_eq!(unsafe { core::ptr::addr_of!(READ_CALL).read() }, 2);
        assert_eq!(unsafe { core::ptr::addr_of!(SEEK_CALLS).read() }, 1);
    }

    #[test]
    fn ignores_seek_failures_and_preserves_output_on_direct_read_failure() {
        let _lock = STREAM_READ_CORE_TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let Some(stream) = stream_handle() else {
            note_missing_u32_fixture("util/stream_seek_tagged_entry");
            return;
        };
        install_reads(&[1, 0, 0x202, 0x620, 0x1234_5678], 4, 1);
        let _reset = CoreReset;
        let mut value = 0x5afe_5afe;

        let result = unsafe { stream_seek_tagged_entry(stream, 0x202, &mut value) };

        assert_eq!(result, 0, "both stream_seek results are ignored");
        assert_eq!(value, 0x5afe_5afe, "direct reader failure does not overwrite output");
        assert_eq!(unsafe { core::ptr::addr_of!(SEEK_CALLS).read() }, 2);
        assert_eq!(unsafe { core::ptr::addr_of!(SEEK_POSITIONS).read() }, [8, 0x620]);
    }
}
