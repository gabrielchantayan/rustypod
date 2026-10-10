//! Directory visitation — FUN_0807a378 at 0x0807a378.
//!
//! True extent [0x0807a378,0x0807a38c): 20 bytes. Zero outgoing plain
//! or predicated BLs; one tail B to 0x08093f70. Two incoming plain BLs
//! (0x08117660, 0x08117864), zero predicated BLs, independently decoded
//! from firmware words. Swap visitor/path into r1/r0, preserve continuation
//! in r2, and visit with a zero exclusion mask. The next real function
//! at 0x0807a38c updates object+0x3c, returns one, and ends with BX LR.
//! Ghidra incorrectly absorbs the directory walker into this wrapper.
//! Deliberate deviations: LLVM chooses the tail-transfer encoding; host
//! execution reuses the existing replaceable directory walker seam.

use super::itunes_directory_visit::{DirectoryVisitor, DirectoryWalk};

/// Visit eligible entries beneath `path` without excluding entry flags.
///
/// # Safety
/// The NUL-terminated path, visitor, and continuation must satisfy the stock
/// directory walker's contract. Host access to DIRECTORY_WALK must be serialized.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn directory_visit(
    visitor: DirectoryVisitor, path: *const u8, continuation: u32,
) {
    #[cfg(target_os = "none")]
    let walk: DirectoryWalk = core::mem::transmute(0x0809_3f70usize);
    #[cfg(not(target_os = "none"))]
    let walk: DirectoryWalk = core::ptr::read_volatile(core::ptr::addr_of!(
        super::itunes_directory_visit::DIRECTORY_WALK
    ));
    walk(path, visitor, continuation, 0);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use super::super::itunes_directory_visit::DIRECTORY_WALK;
    use std::sync::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut SEEN: u32 = 0;
    static mut STOP_AFTER: u32 = 0;

    unsafe extern "C" fn visitor(
        _: u32, flags: u32, _: u32, _: u32, _: u32, _: *const u8, _: u32,
    ) -> i32 {
        SEEN |= flags;
        (SEEN != STOP_AFTER) as i32
    }

    // A behavioral walker fixture: empty directories, flag filtering, and
    // callback cancellation. No pointer-width assumptions or firmware reads.
    unsafe extern "C" fn walk(
        path: *const u8, callback: DirectoryVisitor, continuation: u32, mask: u32,
    ) {
        if path.read() == 0 { return; }
        for flags in [1, 2, 4] {
            if flags & mask == 0 && callback(0, flags, 0, 0, 0, path, 0) == 0 {
                break;
            }
            assert_eq!(continuation, u32::MAX);
        }
    }

    #[test]
    fn empty_directory_flagged_entries_and_callback_cancellation() {
        let _guard = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            let saved = DIRECTORY_WALK;
            DIRECTORY_WALK = walk;
            for (path, stop, expected) in [
                (b"\0".as_slice(), 0, 0),
                (b"Notes/\0".as_slice(), 0, 7),
                (b"Notes/\0".as_slice(), 1, 1),
                (b"Notes/\0".as_slice(), 3, 3),
            ] {
                SEEN = 0;
                STOP_AFTER = stop;
                directory_visit(visitor, path.as_ptr(), u32::MAX);
                let seen = SEEN;
                assert_eq!(seen, expected);
            }
            DIRECTORY_WALK = saved;
        }
    }
}
