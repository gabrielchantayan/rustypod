//! `sqlite_os_open` — original: `FUN_0837db80` @ **0x0837db80**
//! (**32 bytes**, `0x0837db80..0x0837db9c`; the next separately linked
//! function starts at `0x0837dba0`).
//!
//! Raw ARM decoding gives:
//!
//! ```text
//! 0837db80  push {r3,lr}
//! 0837db84  mov  lr,r3
//! 0837db88  ldr  r3,[sp,#8]         ; incoming fifth argument
//! 0837db8c  str  r3,[sp]            ; stack argument for xOpen
//! 0837db90  ldr  ip,[r0,#24]        ; sqlite3_vfs::xOpen
//! 0837db94  mov  r3,lr              ; restore fourth argument
//! 0837db98  blx  ip
//! 0837db9c  pop  {ip,pc}
//! ```
//!
//! **7 direct `bl` call sites, all unconditional**: binary-scanning every
//! ARM B/BL word in `osos.dec` finds calls at `0x082dd5d8`, `0x082dd8c0`,
//! `0x082dd99c`, `0x082dde2c`, `0x0837e568`, `0x0837e7a4`, and `0x083972b4`.
//! No predicated call, tail branch, or aligned raw data word targets this
//! wrapper. The adjacent `0x0837db44..0x0837dc18` forwarding family matches
//! SQLite's `sqlite3_vfs`; slot `+0x18` is `xOpen`. This wrapper has no NULL
//! guards; the VFS and its slot must be readable and callable.
//!
//! # Algorithm
//!
//! Forward `vfs`, `path`, `file`, `flags`, and `out_flags` to the VFS's `xOpen`
//! entry at `+0x18`, returning its SQLite status unchanged. `out_flags` is the
//! fifth AAPCS argument and is copied from the caller stack into the outgoing
//! stack slot.
//!
//! # Deliberate deviations
//!
//! `sqlite3_vfs` is runtime data. The port dispatches the supplied VFS table
//! itself; its host representation uses native-width pointers, while the named
//! xOpen slot is asserted to remain at target offset `+0x18` on 32-bit builds.

use super::os_write::SqliteFile;

/// Recovered prefix of SQLite's `sqlite3_vfs`.
#[repr(C)]
pub struct SqliteVfs {
    /// `+0x00`: interface version.
    pub version: u32,
    /// `+0x04`: size of each VFS file object.
    pub os_file_size: u32,
    /// `+0x08`: maximum path length.
    pub max_pathname: u32,
    /// `+0x0c`: next registered VFS.
    pub next: *mut SqliteVfs,
    /// `+0x10`: VFS name.
    pub name: *const u8,
    /// `+0x14`: VFS application data.
    pub app_data: *mut u8,
    /// `+0x18`: `xOpen(vfs, path, file, flags, out_flags)`.
    pub open: SqliteVfsOpenFn,
}

/// ABI of SQLite's `sqlite3_vfs::xOpen` entry.
pub type SqliteVfsOpenFn = unsafe extern "C" fn(
    *mut SqliteVfs,
    *const u8,
    *mut SqliteFile,
    u32,
    *mut u32,
) -> i32;

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x18] = [0; core::mem::offset_of!(SqliteVfs, open)];

/// sqlite_os_open — original: `FUN_0837db80` @ `0x0837db80` (32 bytes; 7
/// unconditional direct `bl` call sites, binary-scanned).
///
/// Dispatches SQLite's `sqlite3_vfs::xOpen` (`+0x18`) for `vfs`, forwarding
/// `path`, `file`, `flags`, and `out_flags` unchanged. The method status is
/// returned unchanged.
///
/// # Safety
///
/// `vfs` must point to a readable `sqlite3_vfs` with a callable `xOpen` entry.
/// Every argument is passed through without validation, exactly as the ARM
/// wrapper does.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn sqlite_os_open(
    vfs: *mut SqliteVfs,
    path: *const u8,
    file: *mut SqliteFile,
    flags: u32,
    out_flags: *mut u32,
) -> i32 {
    ((*vfs).open)(vfs, path, file, flags, out_flags)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::Mutex;

    #[derive(Default)]
    struct Recorder {
        calls: u32,
        vfs: usize,
        path: usize,
        file: usize,
        flags: u32,
        out_flags: usize,
    }

    static LOCK: Mutex<()> = Mutex::new(());
    static RECORDER: Mutex<Recorder> = Mutex::new(Recorder {
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
        let mut recorder = RECORDER.lock();
        recorder.calls += 1;
        recorder.vfs = vfs as usize;
        recorder.path = path as usize;
        recorder.file = file as usize;
        recorder.flags = flags;
        recorder.out_flags = out_flags as usize;
        if !out_flags.is_null() {
            out_flags.write(0x8000_0001);
        }
        -522
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
        }
    }

    #[test]
    fn forwards_null_path_full_flags_and_output_word_to_xopen() {
        let _lock = LOCK.lock();
        *RECORDER.lock() = Recorder::default();
        let mut vfs = vfs();
        let mut file = SqliteFile { methods: core::ptr::null() };
        let mut out_flags = 0;

        let status = unsafe {
            sqlite_os_open(
                &mut vfs,
                core::ptr::null(),
                &mut file,
                u32::MAX,
                &mut out_flags,
            )
        };

        let recorder = RECORDER.lock();
        assert_eq!(status, -522);
        assert_eq!(recorder.calls, 1);
        assert_eq!(recorder.vfs, core::ptr::addr_of_mut!(vfs) as usize);
        assert_eq!(recorder.path, 0);
        assert_eq!(recorder.file, core::ptr::addr_of_mut!(file) as usize);
        assert_eq!(recorder.flags, u32::MAX);
        assert_eq!(recorder.out_flags, core::ptr::addr_of_mut!(out_flags) as usize);
        assert_eq!(out_flags, 0x8000_0001);
    }

    #[test]
    fn forwards_null_output_word_without_a_guard() {
        let _lock = LOCK.lock();
        *RECORDER.lock() = Recorder::default();
        let mut vfs = vfs();
        let mut file = SqliteFile { methods: core::ptr::null() };
        let path = [b't', b'e', b's', b't', 0];

        let status = unsafe {
            sqlite_os_open(
                &mut vfs,
                path.as_ptr(),
                &mut file,
                0,
                core::ptr::null_mut(),
            )
        };

        let recorder = RECORDER.lock();
        assert_eq!(status, -522);
        assert_eq!(recorder.calls, 1);
        assert_eq!(recorder.path, path.as_ptr() as usize);
        assert_eq!(recorder.out_flags, 0);
    }
}
