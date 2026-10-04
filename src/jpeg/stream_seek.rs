//! `jpeg_stream_seek` — original: `FUN_082104e8` @ `0x082104e8`.
//! True extent: 64 bytes (`0x082104e8..0x08210528`, next real push).
//! Whole-image A32 decoding verifies two inbound plain BLs at `0x082106c4`
//! and `0x0821074c`, zero predicated inbound BLs; the body has one plain BL
//! at `0x08210518` to the already-ported file seek at `0x082787b8`.
//!
//! A null file-handle word stores error -7 and returns -7 without changing
//! the stream position. Otherwise seek absolutely with a zero high word,
//! ignore the seek status, store the requested position at +0x14, and return
//! zero without clearing a prior stream error. Callers skip JPEG segments.
//!
//! Deliberate deviations: none. Reuses the existing target-width stream
//! prefix and the real file-seek implementation, including on the host.

use core::ffi::c_void;
use super::stream_read_byte::JpegStream;

/// Seek the JPEG parser stream to an absolute unsigned byte position.
///
/// # Safety
/// `stream` must be a valid writable `JpegStream`. Its nonzero file handle
/// must identify an initialized file accepted by `ft_platform_file_seek`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn jpeg_stream_seek(stream: *mut JpegStream, position: u32) -> i32 {
    let handle = unsafe { (*stream).file_handle };
    if handle == 0 {
        unsafe { (*stream).error_status = (-7i32) as u32 };
        return -7;
    }
    unsafe {
        crate::ft::system::ft_platform_file_seek(handle as usize as *mut c_void, 0, position, 0, 0);
        (*stream).bytes_read = position;
    }
    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::ft::system::{FtPlatformFile, FtPlatformFileSynchronizationOwner, TEST_OPS_LOCK};
    use crate::kernel::sync_mutex::{CountedMutex, Mutex};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::mem::{align_of, size_of};
    use std::sync::LazyLock;

    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::JPEG_STREAM_SEEK, 0x1000).map(|base| base as usize)
    });

    #[repr(C)]
    struct HostFile {
        _vtable: *const u8,
        synchronization_owner: *mut HostOwner,
        length_query_state: u8,
        _unknown_09: [u8; 0x0f],
        directory_entry_index: i32,
        open_status: i32,
        cached_entry_length: u32,
        _unknown_24: [u8; 0x10],
        cursor: u32,
        _unknown_38: [u8; 0x1c],
    }

    #[repr(C)]
    struct HostOwner {
        _unknown_00: [u8; 0x44],
        length_query_lock: CountedMutex,
    }

    #[test]
    fn null_handle_preserves_position_and_opaque_words() {
        let mut words = [0x1234_5678, 19, 0, 31, 41, 53];
        let stream = words.as_mut_ptr().cast::<JpegStream>();
        assert_eq!(unsafe { jpeg_stream_seek(stream, u32::MAX) }, -7);
        assert_eq!(words, [0x1234_5678, (-7i32) as u32, 0, 31, 41, 53]);
    }

    #[test]
    fn absolute_seek_records_position_even_when_file_rejects_it() {
        let _guard = TEST_OPS_LOCK.lock();
        let Some(base) = *SLAB else {
            note_missing_u32_fixture("jpeg::stream_seek");
            return;
        };
        assert_eq!(size_of::<HostFile>(), size_of::<FtPlatformFile>());
        assert_eq!(align_of::<HostFile>(), align_of::<FtPlatformFile>());
        assert_eq!(size_of::<HostOwner>(), size_of::<FtPlatformFileSynchronizationOwner>());
        assert_eq!(align_of::<HostOwner>(), align_of::<FtPlatformFileSynchronizationOwner>());
        let mut owner = HostOwner {
            _unknown_00: [0; 0x44],
            length_query_lock: CountedMutex {
                mutex: Mutex { sem_cell: core::ptr::null_mut(), unused: 0 },
                hold_count: 0,
            },
        };
        let file = base as *mut HostFile;
        unsafe {
            file.write(HostFile {
                _vtable: core::ptr::null(),
                synchronization_owner: &mut owner,
                length_query_state: 0,
                _unknown_09: [0; 0x0f],
                directory_entry_index: 0,
                open_status: -37,
                cached_entry_length: 64,
                _unknown_24: [0; 0x10],
                cursor: 17,
                _unknown_38: [0; 0x1c],
            });
            let mut words = [7, 19, base as u32, 31, 41, 53];
            let stream = words.as_mut_ptr().cast::<JpegStream>();
            for position in [0, 23, 64, 65, u32::MAX] {
                let old_cursor = (*file).cursor;
                assert_eq!(jpeg_stream_seek(stream, position), 0);
                assert_eq!((*file).cursor, if position <= 64 { position } else { old_cursor });
                assert_eq!(words, [7, 19, base as u32, 31, 41, position]);
                assert_eq!(owner.length_query_lock.hold_count, 0);
            }
            (*file).length_query_state = 1;
            assert_eq!(jpeg_stream_seek(stream, 11), 0);
            assert_eq!((*file).cursor, 64);
            assert_eq!(words[5], 11);
            assert_eq!(words[1], 19);
            assert_eq!(owner.length_query_lock.hold_count, 0);
        }
    }
}
