//! `sqlite_os_access` — original: `FUN_0837dae0` @ **0x0837dae0**
//! (**8 bytes**, `0x0837dae0..0x0837dae8`; the next independently linked
//! function, `sqlite_os_close`, starts at `0x0837dae8`).
//!
//! Raw ARM decoding:
//!
//! ```text
//! 0837dae0  ldr r3,[r0,#0x20]       ; sqlite3_vfs::xAccess
//! 0837dae4  bx  r3                  ; tail-dispatch, preserving r1-r3
//! ```
//!
//! Binary-scanning every ARM `B`/`BL`-immediate word in `osos.dec` finds
//! **three inbound direct calls**, all unconditional `bl` (`0x082dd4ec`,
//! `0x082dd5ac`, `0x0837fc0c`); no predicated `bl` calls. The wrapper has no
//! outbound `bl`: its `bx r3` is the runtime VFS-method dispatch.
//!
//! This is SQLite's `sqlite3OsAccess`: it forwards `vfs`, `path`, `flags`,
//! and `result` to `sqlite3_vfs::xAccess` at target offset `+0x20`, returning
//! the method status unchanged.
//!
//! # Deliberate deviations
//!
//! The runtime method pointer is represented as a native-width function
//! pointer for host tests. `SqliteVfs` asserts the `+0x20` target offset on
//! 32-bit builds, so target layout remains exact.

use super::os_open::SqliteVfs;

/// sqlite_os_access — original: `FUN_0837dae0` @ `0x0837dae0` (8 bytes; three
/// unconditional direct `bl` call sites, no predicated `bl`).
///
/// Dispatches `sqlite3_vfs::xAccess` (`+0x20`) with every argument unchanged
/// and returns its SQLite status unchanged.
///
/// # Safety
///
/// `vfs` must point to a readable `sqlite3_vfs` with a callable `xAccess`
/// entry. The ARM wrapper performs no validation.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn sqlite_os_access(
    vfs: *mut SqliteVfs,
    path: *const u8,
    flags: u32,
    result: *mut i32,
) -> i32 {
    ((*vfs).access)(vfs, path, flags, result)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::sqlite::os_open::SqliteVfsOpenFn;
    use parking_lot::Mutex;

    #[derive(Default)]
    struct Recorder {
        calls: u32,
        vfs: usize,
        path: usize,
        flags: u32,
        result: usize,
    }

    static LOCK: Mutex<()> = Mutex::new(());
    static RECORDER: Mutex<Recorder> = Mutex::new(Recorder {
        calls: 0,
        vfs: 0,
        path: 0,
        flags: 0,
        result: 0,
    });

    unsafe extern "C" fn recording_access(
        vfs: *mut SqliteVfs,
        path: *const u8,
        flags: u32,
        result: *mut i32,
    ) -> i32 {
        let mut recorder = RECORDER.lock();
        recorder.calls += 1;
        recorder.vfs = vfs as usize;
        recorder.path = path as usize;
        recorder.flags = flags;
        recorder.result = result as usize;
        if !result.is_null() {
            result.write(1);
        }
        -14
    }

    unsafe extern "C" fn unused_open(
        _vfs: *mut SqliteVfs,
        _path: *const u8,
        _file: *mut super::super::os_write::SqliteFile,
        _flags: u32,
        _out_flags: *mut u32,
    ) -> i32 {
        0
    }

    fn vfs() -> SqliteVfs {
        SqliteVfs {
            version: 1,
            os_file_size: 0,
            max_pathname: 0,
            next: core::ptr::null_mut(),
            name: core::ptr::null(),
            app_data: core::ptr::null_mut(),
            open: unused_open as SqliteVfsOpenFn,
            delete: 0,
            access: recording_access,
        }
    }

    #[test]
    fn forwards_null_path_all_flag_bits_and_null_result() {
        let _lock = LOCK.lock();
        *RECORDER.lock() = Recorder::default();
        let mut vfs = vfs();

        let status = unsafe {
            sqlite_os_access(
                core::ptr::addr_of_mut!(vfs),
                core::ptr::null(),
                u32::MAX,
                core::ptr::null_mut(),
            )
        };

        let recorder = RECORDER.lock();
        assert_eq!(status, -14);
        assert_eq!(recorder.calls, 1);
        assert_eq!(recorder.vfs, core::ptr::addr_of!(vfs) as usize);
        assert_eq!(recorder.path, 0);
        assert_eq!(recorder.flags, u32::MAX);
        assert_eq!(recorder.result, 0);
    }

    #[test]
    fn forwards_non_null_path_and_result_word() {
        let _lock = LOCK.lock();
        *RECORDER.lock() = Recorder::default();
        let mut vfs = vfs();
        let path = b"Library/Media/iTunesCDB\0";
        let mut result = -1;

        let status = unsafe {
            sqlite_os_access(
                core::ptr::addr_of_mut!(vfs),
                path.as_ptr(),
                7,
                core::ptr::addr_of_mut!(result),
            )
        };

        let recorder = RECORDER.lock();
        assert_eq!(status, -14);
        assert_eq!(result, 1);
        assert_eq!(recorder.calls, 1);
        assert_eq!(recorder.path, path.as_ptr() as usize);
        assert_eq!(recorder.flags, 7);
        assert_eq!(recorder.result, core::ptr::addr_of!(result) as usize);
    }
}
