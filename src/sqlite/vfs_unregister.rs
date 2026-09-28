//! SQLite VFS registry unlink.
//!
//! `sqlite_vfs_unregister` — original: `FUN_083975b0` @ `0x083975b0`
//! (84 bytes; **0 direct `bl` instructions**, unconditional or predicated).
//! Raw `osos.dec` words establish the exact body as
//! `0x083975b0..0x08397600` (21 words): its `bx lr` is followed by the
//! `0x08a09918` registry literal, then a distinct `push {r4-r11,lr}` at
//! `0x08397608`.
//!
//! The function removes a non-NULL `sqlite3_vfs` from the singly linked VFS
//! registry headed by the word at `0x08a09918`: it handles the head directly,
//! otherwise walks `next` at `+0x0c` and splices the predecessor when found.
//! Null and absent VFS pointers are inert. Deliberate deviation: host builds
//! share `vfs_find`'s stand-in registry; target builds use the retail address.

use super::os_open::SqliteVfs;
use super::vfs_find::registry;

/// Unlink `vfs` from SQLite's registered-VFS list, if present.
///
/// # Safety
///
/// `vfs` must be NULL or a readable VFS node. Every VFS node reachable from
/// the registry must be readable; if `vfs` is found, its predecessor must be
/// writable. RetailOS does not validate these conditions.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn sqlite_vfs_unregister(vfs: *mut SqliteVfs) {
    if vfs.is_null() {
        return;
    }

    let registry = registry();
    let mut current = (*registry).head;
    if current == vfs {
        (*registry).head = (*vfs).next;
        return;
    }

    while !current.is_null() {
        let next = (*current).next;
        if next.is_null() {
            return;
        }
        if next == vfs {
            (*current).next = (*vfs).next;
            return;
        }
        current = next;
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    unsafe extern "C" fn dummy_open(
        _vfs: *mut SqliteVfs,
        _path: *const u8,
        _file: *mut super::super::os_write::SqliteFile,
        _flags: u32,
        _out_flags: *mut u32,
    ) -> i32 {
        0
    }

    unsafe extern "C" fn dummy_access(
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
            open: dummy_open,
            delete: 0,
            access: dummy_access,
        }
    }

    unsafe fn set_head(head: *mut SqliteVfs) {
        (*registry()).head = head;
    }

    #[test]
    fn removes_head_without_touching_its_next_link() {
        let _lock = TEST_LOCK.lock();
        let mut head = vfs();
        let mut tail = vfs();
        head.next = &mut tail;
        unsafe {
            set_head(&mut head);
            sqlite_vfs_unregister(&mut head);
            assert!(core::ptr::eq((*registry()).head, &mut tail));
            assert!(core::ptr::eq(head.next, &mut tail));
            set_head(core::ptr::null_mut());
        }
    }

    #[test]
    fn removes_middle_by_splicing_predecessor() {
        let _lock = TEST_LOCK.lock();
        let mut first = vfs();
        let mut middle = vfs();
        let mut last = vfs();
        first.next = &mut middle;
        middle.next = &mut last;
        unsafe {
            set_head(&mut first);
            sqlite_vfs_unregister(&mut middle);
            assert!(core::ptr::eq(first.next, &mut last));
            assert!(core::ptr::eq(middle.next, &mut last));
            set_head(core::ptr::null_mut());
        }
    }

    #[test]
    fn null_and_absent_nodes_leave_list_unchanged() {
        let _lock = TEST_LOCK.lock();
        let mut head = vfs();
        let mut tail = vfs();
        let mut absent = vfs();
        head.next = &mut tail;
        unsafe {
            set_head(&mut head);
            sqlite_vfs_unregister(core::ptr::null_mut());
            sqlite_vfs_unregister(&mut absent);
            assert!(core::ptr::eq((*registry()).head, &mut head));
            assert!(core::ptr::eq(head.next, &mut tail));
            assert!(tail.next.is_null());
            set_head(core::ptr::null_mut());
        }
    }
}
