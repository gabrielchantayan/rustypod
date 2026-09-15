//! Drive-prefix parser — `FUN_082e377c` @ `0x082e377c` (88 bytes; 5 verified
//! direct `bl` call sites, all unconditional).
//!
//! Raw ARM from `0x082e377c` through `0x082e37d0` first reads the two leading
//! bytes unchecked. A nonempty `X:` prefix is ASCII-folded through
//! `ascii_to_uppercase`, converted from `A` to a zero-based drive index, and
//! skipped. All other paths retain their address and use the current drive
//! index from `FUN_082e2254`. The index is accepted only when unsigned
//! `index < 4`; success stores it through `drive_out` and returns the selected
//! path address, while failure returns NULL without modifying `drive_out`.
//!
//! The verified inbound calls are `bl` at `0x082c3018`, `0x082e0618`,
//! `0x082e15e8`, `0x082e3488`, and `0x082e349c`; none is predicated and no
//! direct branch enters this address. `FUN_082e2254` remains a resident
//! dependency because it has not been ported. Host builds use drive 0 for that
//! dependency; this affects only host-only tests of paths without a prefix.

use crate::util::ascii_to_uppercase::ascii_to_uppercase;

/// Resident retailOS current-drive getter at `0x082e2254`.
const CURRENT_DRIVE_INDEX_ADDRESS: usize = 0x082e_2254;

type CurrentDriveIndex = unsafe extern "C" fn() -> u32;

#[inline(always)]
unsafe fn current_drive_index() -> u32 {
    #[cfg(target_os = "none")]
    {
        let current: CurrentDriveIndex = core::mem::transmute(CURRENT_DRIVE_INDEX_ADDRESS);
        current()
    }
    #[cfg(not(target_os = "none"))]
    {
        0
    }
}

/// Parses an optional `X:` drive prefix and stores its zero-based index.
///
/// # Safety
///
/// `path` must point to at least two readable bytes. `drive_out` is written on
/// success and must be valid for a `u32` write. This deliberately has no NULL
/// guards, matching the retail ABI.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.parse_drive_prefix")]
pub unsafe extern "C" fn parse_drive_prefix(drive_out: *mut u32, path: *const u8) -> *const u8 {
    let (index, remainder) = if path.read() != 0 && path.add(1).read() == b':' {
        (
            ascii_to_uppercase(path.read() as u32).wrapping_sub(b'A' as u32),
            path.add(2),
        )
    } else {
        (current_drive_index(), path)
    };

    if index < 4 {
        drive_out.write(index);
        remainder
    } else {
        core::ptr::null()
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    #[test]
    fn accepts_case_insensitive_drive_prefixes_and_skips_them() {
        for (path, expected) in [(b"A:\\music\0".as_slice(), 0), (b"d:file\0".as_slice(), 3)] {
            let mut drive = u32::MAX;
            let remainder = unsafe { parse_drive_prefix(&mut drive, path.as_ptr()) };

            assert_eq!(drive, expected);
            assert_eq!(remainder, unsafe { path.as_ptr().add(2) });
        }
    }

    #[test]
    fn uses_current_drive_and_keeps_paths_without_a_prefix() {
        let path = b"relative/path\0";
        let mut drive = u32::MAX;

        let remainder = unsafe { parse_drive_prefix(&mut drive, path.as_ptr()) };

        assert_eq!(drive, 0);
        assert_eq!(remainder, path.as_ptr());
    }

    #[test]
    fn empty_path_uses_current_drive_without_reading_a_second_byte() {
        let path = b"\0";
        let mut drive = u32::MAX;

        assert_eq!(unsafe { parse_drive_prefix(&mut drive, path.as_ptr()) }, path.as_ptr());
        assert_eq!(drive, 0);
    }

    #[test]
    fn rejects_out_of_range_prefix_without_writing_output() {
        for path in [b"E:\\bad\0".as_slice(), b"@:\\bad\0".as_slice(), b"1:\\bad\0".as_slice()] {
            let mut drive = 0xfeed_face;

            assert!(unsafe { parse_drive_prefix(&mut drive, path.as_ptr()) }.is_null());
            assert_eq!(drive, 0xfeed_face);
        }
    }
}
