//! `sqlite_os_open_forced_flags` — original: `FUN_0837e784` @ **0x0837e784**
//! (**40 bytes**, `0x0837e784..0x0837e7a8`; the next separately linked
//! function starts at `0x0837e7ac`).
//!
//! **2 direct `bl` call sites, both unconditional**: binary-scanning every
//! ARM B/BL word in `osos.dec` finds calls at `0x082dd7c4` and `0x082ded54`.
//! There are no predicated `bl` forms targeting this wrapper.
//!
//! # Algorithm
//!
//! Rearrange `(vfs, file, path, flags)` into `sqlite_os_open`'s
//! `(vfs, path, file, flags, out_flags)` order, force bits `0x1e` in `flags`,
//! and pass a null `out_flags` pointer. Return the VFS status unchanged.
//!
//! # Deliberate deviations
//!
//! The ARM wrapper emits its own stack slot for the null fifth argument. Rust
//! delegates through the already-ported `sqlite_os_open`; its ABI supplies the
//! same null pointer to `sqlite3_vfs::xOpen` without exposing stack layout.

use super::os_open::{sqlite_os_open, SqliteVfs};
use super::os_write::SqliteFile;

const FORCED_OPEN_FLAGS: u32 = 0x1e;

/// Opens a SQLite VFS file after forcing the retailOS temporary/exclusive flag
/// bits. Original: `FUN_0837e784` @ `0x0837e784` (40 bytes; 2 unconditional
/// direct `bl` call sites, binary-scanned).
///
/// # Safety
///
/// `vfs` must point to a readable `sqlite3_vfs` with a callable `xOpen` entry.
/// `file` and `path` are forwarded without validation, as in the ARM wrapper.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn sqlite_os_open_forced_flags(
    vfs: *mut SqliteVfs,
    file: *mut SqliteFile,
    path: *const u8,
    flags: u32,
) -> i32 {
    sqlite_os_open(vfs, path, file, flags | FORCED_OPEN_FLAGS, core::ptr::null_mut())
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::Mutex;

    #[derive(Default)]
    struct OpenCall {
        calls: u32,
        vfs: usize,
        path: usize,
        file: usize,
        flags: u32,
        out_flags: usize,
    }

    static LOCK: Mutex<()> = Mutex::new(());
    static OPEN_CALL: Mutex<OpenCall> = Mutex::new(OpenCall {
        calls: 0,
        vfs: 0,
        path: 0,
        file: 0,
        flags: 0,
        out_flags: 0,
    });

    unsafe extern "C" fn recording_open(
        vfs: *mut SqliteVfs,
        path: *const u8,
        file: *mut SqliteFile,
        flags: u32,
        out_flags: *mut u32,
    ) -> i32 {
        let mut call = OPEN_CALL.lock();
        call.calls += 1;
        call.vfs = vfs as usize;
        call.path = path as usize;
        call.file = file as usize;
        call.flags = flags;
        call.out_flags = out_flags as usize;
        -73
    }

    unsafe extern "C" fn recording_access(
        _vfs: *mut SqliteVfs,
        _path: *const u8,
        _flags: u32,
        _result: *mut i32,
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
            open: recording_open,
            delete: 0,
            access: recording_access,
        }
    }

    #[test]
    fn reorders_arguments_forces_flags_and_discards_output_flags() {
        let _lock = LOCK.lock();
        *OPEN_CALL.lock() = OpenCall::default();
        let mut vfs = vfs();
        let mut file = SqliteFile { methods: core::ptr::null() };
        let path = [b't', b'e', b'm', b'p', 0];

        let status = unsafe {
            sqlite_os_open_forced_flags(&mut vfs, &mut file, path.as_ptr(), 0x8000_0021)
        };

        let call = OPEN_CALL.lock();
        assert_eq!(status, -73);
        assert_eq!(call.calls, 1);
        assert_eq!(call.vfs, core::ptr::addr_of_mut!(vfs) as usize);
        assert_eq!(call.path, path.as_ptr() as usize);
        assert_eq!(call.file, core::ptr::addr_of_mut!(file) as usize);
        assert_eq!(call.flags, 0x8000_003f);
        assert_eq!(call.out_flags, 0);
    }

    #[test]
    fn preserves_already_set_forced_bits_and_null_path() {
        let _lock = LOCK.lock();
        *OPEN_CALL.lock() = OpenCall::default();
        let mut vfs = vfs();
        let mut file = SqliteFile { methods: core::ptr::null() };

        let status = unsafe {
            sqlite_os_open_forced_flags(&mut vfs, &mut file, core::ptr::null(), u32::MAX)
        };

        let call = OPEN_CALL.lock();
        assert_eq!(status, -73);
        assert_eq!(call.path, 0);
        assert_eq!(call.flags, u32::MAX);
        assert_eq!(call.out_flags, 0);
    }
}
