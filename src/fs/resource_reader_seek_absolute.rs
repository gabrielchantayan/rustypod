//! `resource_reader_seek_absolute` — original: `FUN_082a6ad8` @ `0x082a6ad8`
//! (44 bytes, `0x082a6ad8..0x082a6b04`; 12 verified direct `bl` call sites,
//! all unconditional).
//!
//! # Algorithm
//!
//! Loads the resource reader's file handle from target offset `+0x8c`, seeks
//! it to the supplied unsigned 32-bit absolute offset through
//! [`crate::ft::system::ft_platform_file_seek`], and returns one exactly when
//! that seek returns status zero. It passes zero in the otherwise unused
//! duplicate-offset word, zero in the high offset word, and zero for origin.
//!
//! # Deliberate deviations
//!
//! None. The callee at `0x082787b8` is already ported, so this calls it
//! directly rather than adding a duplicate dispatch seam.

use core::ffi::c_void;

use crate::fs::resource_reader_read_exact::ResourceReader;

/// `resource_reader_seek_absolute` — original: `FUN_082a6ad8` @ `0x082a6ad8`
/// (44 bytes; 12 unconditional `bl` call sites, verified by decoding every
/// ARM B/BL word in `osos.dec`).
///
/// Seeks the reader's file handle to `offset` from the start of the file.
/// Status zero becomes one; every nonzero status becomes zero. The original
/// has no reader or handle NULL guard.
///
/// # Safety
///
/// `reader` must point to a valid [`ResourceReader`] whose file handle is a
/// valid file object accepted by [`crate::ft::system::ft_platform_file_seek`].
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.resource_reader_seek_absolute")]
#[inline(never)]
pub unsafe extern "C" fn resource_reader_seek_absolute(
    reader: *const ResourceReader,
    offset: u32,
) -> u32 {
    let handle = unsafe { (*reader).file_handle as usize as *mut c_void };
    (unsafe { crate::ft::system::ft_platform_file_seek(handle, 0, offset, 0, 0) } == 0) as u32
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

    const SLAB_LEN: usize = 0x1000;
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::RESOURCE_READER_SEEK_ABSOLUTE, SLAB_LEN).map(|base| base as usize)
    });

    // `FtPlatformFile` intentionally uses native pointers on hosts. These
    // mirrors keep every pointer field named and thus non-overlapping while
    // placing the file itself in the low-u32 slab consumed by ResourceReader.
    #[repr(C)]
    struct HostFile {
        _vtable: *const u8,
        synchronization_owner: *mut HostSynchronizationOwner,
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
    struct HostSynchronizationOwner {
        _unknown_00: [u8; 0x44],
        length_query_lock: CountedMutex,
    }

    struct Fixture {
        reader: *mut ResourceReader,
        file: *mut HostFile,
        owner: std::boxed::Box<HostSynchronizationOwner>,
    }

    fn fixture(state: u8, length: u32, cursor: u32) -> Option<Fixture> {
        assert_eq!(size_of::<HostFile>(), size_of::<FtPlatformFile>());
        assert_eq!(align_of::<HostFile>(), align_of::<FtPlatformFile>());
        assert_eq!(
            size_of::<HostSynchronizationOwner>(),
            size_of::<FtPlatformFileSynchronizationOwner>(),
        );
        assert_eq!(
            align_of::<HostSynchronizationOwner>(),
            align_of::<FtPlatformFileSynchronizationOwner>(),
        );

        let base = (*SLAB)? as *mut u8;
        let mut owner = std::boxed::Box::new(HostSynchronizationOwner {
            _unknown_00: [0; 0x44],
            length_query_lock: CountedMutex {
                mutex: Mutex { sem_cell: core::ptr::null_mut(), unused: 0 },
                hold_count: 0,
            },
        });
        unsafe {
            core::ptr::write_bytes(base, 0, SLAB_LEN);
            let reader = base.cast::<ResourceReader>();
            let file = base.add(0x200).cast::<HostFile>();
            core::ptr::write(
                file,
                HostFile {
                    _vtable: core::ptr::null(),
                    synchronization_owner: &mut *owner,
                    length_query_state: state,
                    _unknown_09: [0; 0x0f],
                    directory_entry_index: 0,
                    open_status: -37,
                    cached_entry_length: length,
                    _unknown_24: [0; 0x10],
                    cursor,
                    _unknown_38: [0; 0x1c],
                },
            );
            (*reader).file_handle = file as usize as u32;
            Some(Fixture { reader, file, owner })
        }
    }

    #[test]
    fn seeks_absolutely_and_reports_success() {
        let _guard = TEST_OPS_LOCK.lock();
        let Some(fixture) = fixture(0, 64, 17) else {
            note_missing_u32_fixture("fs::resource_reader_seek_absolute");
            return;
        };

        unsafe {
            assert_eq!(resource_reader_seek_absolute(fixture.reader, 23), 1);
            assert_eq!((*fixture.file).cursor, 23);
            assert_eq!(fixture.owner.length_query_lock.hold_count, 0);
        }
    }

    #[test]
    fn rejects_file_seek_errors_without_moving_cursor() {
        let _guard = TEST_OPS_LOCK.lock();
        let Some(stateful) = fixture(1, 64, 17) else {
            note_missing_u32_fixture("fs::resource_reader_seek_absolute");
            return;
        };

        unsafe {
            assert_eq!(resource_reader_seek_absolute(stateful.reader, 23), 0);
            assert_eq!((*stateful.file).cursor, 17);
            assert_eq!(stateful.owner.length_query_lock.hold_count, 0);
        }

        let out_of_range = fixture(0, 64, 17).expect("the permanent slab remains mapped");
        unsafe {
            assert_eq!(resource_reader_seek_absolute(out_of_range.reader, 65), 0);
            assert_eq!((*out_of_range.file).cursor, 17);
            assert_eq!(out_of_range.owner.length_query_lock.hold_count, 0);
        }
    }
}
