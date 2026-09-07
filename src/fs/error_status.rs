//! fs_error_status — original: `FUN_0829dcf8` @ 0x0829dcf8 (Ghidra's 40
//! bytes cover only the entry stub; the function's out-of-line body is
//! the 324 bytes at 0x0829dbb4..0x0829dcf4 that the stub tail-branches
//! into, so the real extent is 0x0829dbb4..0x0829dd1c = 364 bytes.
//! Ghidra lists no function at 0x0829dbb4 at all yet inlines its switch
//! into the C for 0x0829dcf8 — the two halves are one function).
//!
//! Call sites, from a scan of every ARM B/BL word in osos.dec: 21 to the
//! entry — 20 plain `bl`, plus one `beq 0x0829dcf8` tail-call at
//! 0x081bc9c4. That predicated site is the sibling accessor
//! `FUN_081bc998`, which returns 0 outright when its drive-letter check
//! succeeds and only falls through to the error mapping when it fails;
//! it is a success short-circuit, not a NULL guard. The body at
//! 0x0829dbb4 has exactly one reference in the whole image — the entry's
//! own tail `b` — and appears in no DATA word, so it is not dispatched
//! virtually and is private to this function.
//!
//! Algorithm: the failure-path status accessor of the file-path layer
//! (the `bl` cluster @ 0x081bc9f8..0x081bded8, the same accessor object
//! `path_lengths_ok` @ 0x081bd910 is a member of). Every failing entry
//! point in that cluster ends `return fs_error_status(this);`. It
//! answers in two steps:
//!
//! 1. If the accessor's sticky status override at +0x20 is nonzero,
//!    return it verbatim. The transfer loops @ 0x081bdfe0 and
//!    0x081be11c clear that word before each chunk, so a nonzero value
//!    is a status a deeper layer deliberately parked on the object.
//! 2. Otherwise read the calling task's storage-layer errno — the code
//!    word `ata_report_error` (0x083690a8) stores at +0x04 of the record
//!    that `ata_error_record` (0x082d0ae8) owns — and translate it into
//!    a file-layer status through the table at 0x0829dbb4.
//!
//! Deliberate deviations:
//!
//! - The original's `mov r0, r4` before the tail `b 0x0829dbb4` hands
//!   the mapping body a `this` it never reads (the body only ever tests
//!   r1). The port drops the dead argument.
//! - The mapping's dispatch is a signed compare tree over a jump table,
//!   but every non-default arm is an exact `==` test, so a `match` over
//!   the unsigned code is outcome-identical. Values the original routes
//!   as negative (`cmp r1,#0xa` is `ls`, i.e. unsigned, so they miss the
//!   table) land on the same 0x4b default the tree gives them.
//! - The errno read at 0x082d0aa4 (16 bytes: `bl ata_error_record; ldr
//!   r0,[r0,#4]`) is not yet a ported function of its own. Rather than
//!   stub it, the default hook below open-codes it over the already
//!   ported [`ata_error_record`], which is the same memory effect. The
//!   indirection exists so host tests can drive the mapping without
//!   racing `ata_cmd`'s tests for the shared record pool.
//! - Codegen: the original splits the mapping into an 11-entry
//!   `pc`-relative jump table plus a signed compare tree for the sparse
//!   high codes; LLVM instead emits one dense 0x68-entry table covering
//!   0..=0x67 with the default in every hole. Same answer for every
//!   input, 158 instructions against 81.

use crate::drivers::ata_cmd::ata_error_record;

/// The file-path layer's accessor object, as far as this function reads
/// it. Word-indexed rather than byte-offset: the head is opaque here
/// (the cluster's own sub-object lives at +0x28, past everything this
/// function touches), and only the word at +0x20 is named.
#[repr(C)]
pub struct FileAccessor {
    /// Words +0x00..+0x1c — untouched by this function.
    pub head: [u32; 8],
    /// +0x20: the sticky status override. Zero means "ask the storage
    /// layer"; nonzero is returned to the caller unchanged.
    pub status_override: u32,
}

/// The status the mapping returns for every code it does not know,
/// including the gaps inside the low run (12, 14..16, ...) and anything
/// the original's signed compare tree treats as negative.
pub const STATUS_UNKNOWN: u32 = 0x4b;

/// Offset of the error code inside a per-task storage error record —
/// the word `ata_report_error` writes with `str r4, [r0, #4]` and the
/// reader @ 0x082d0aa4 loads back.
const RECORD_ERROR_CODE: usize = 0x04;

/// The one external dependency of [`fs_error_status`]: where the calling task's
/// storage-layer errno comes from.
#[derive(Copy, Clone)]
pub struct FsErrorHooks {
    /// The reader @ 0x082d0aa4. Defaults to the real record lookup.
    pub storage_errno: unsafe extern "C" fn() -> u32,
}

/// Default: the original's own path — the calling task's error record,
/// code word at +0x04.
unsafe extern "C" fn storage_errno_from_record() -> u32 {
    let record = ata_error_record();
    (record.add(RECORD_ERROR_CODE) as *const u32).read_volatile()
}

/// Hook table. Host tests swap `storage_errno` through
/// `core::ptr::addr_of_mut!`; target builds leave the default.
pub static mut FS_ERROR_HOOKS: FsErrorHooks = FsErrorHooks {
    storage_errno: storage_errno_from_record,
};

/// Volatile so LLVM cannot constant-fold the load to the default (the
/// `heap/wrappers.rs` pattern).
#[inline(always)]
fn fs_error_hooks() -> FsErrorHooks {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(FS_ERROR_HOOKS)) }
}

/// The mapping body @ 0x0829dbb4 (324 bytes): storage-layer errno to
/// file-layer status. Codes 0..=11 come out of a `pc`-relative jump
/// table, the rest out of a binary compare tree; unlisted codes are
/// [`STATUS_UNKNOWN`].
///
/// `#[inline(never)]` keeps it the separate branch target the original
/// makes of it, so `match.py` still sees the entry stub's tail call.
#[inline(never)]
pub fn status_for_storage_error(errno: u32) -> u32 {
    match errno {
        0 => 0x3f,
        1 => 0x40,
        2 => 0x07,
        3 => 0x42,
        4 => 0x43,
        5 => 0x44,
        6 => 0x45,
        7 => 0x46,
        8 => 0x47,
        9 => 0x32,
        10 => 0x49,
        11 => 0x4a,
        0x0d => 0x36,
        0x11 => 0x35,
        0x16 => 0x37,
        0x18 => 0x34,
        0x1c => 0x38,
        0x1e => 0x39,
        0x1f => 0x3a,
        0x20 => 0x3b,
        0x65 => 0x3c,
        0x66 => 0x3d,
        0x67 => 0x3e,
        _ => STATUS_UNKNOWN,
    }
}

/// fs_error_status — the entry stub @ 0x0829dcf8. Returns the
/// accessor's status override when it is set, else the translated
/// storage-layer errno.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn fs_error_status(accessor: *const FileAccessor) -> u32 {
    let parked = core::ptr::addr_of!((*accessor).status_override).read_volatile();
    if parked != 0 {
        return parked;
    }
    status_for_storage_error((fs_error_hooks().storage_errno)())
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::{Mutex, MutexGuard};

    /// Every code the original maps to something other than
    /// [`STATUS_UNKNOWN`], transcribed from osos.dec at 0x0829dbb4.
    const MAPPED: &[(u32, u32)] = &[
        (0, 0x3f),
        (1, 0x40),
        (2, 0x07),
        (3, 0x42),
        (4, 0x43),
        (5, 0x44),
        (6, 0x45),
        (7, 0x46),
        (8, 0x47),
        (9, 0x32),
        (10, 0x49),
        (11, 0x4a),
        (0x0d, 0x36),
        (0x11, 0x35),
        (0x16, 0x37),
        (0x18, 0x34),
        (0x1c, 0x38),
        (0x1e, 0x39),
        (0x1f, 0x3a),
        (0x20, 0x3b),
        (0x65, 0x3c),
        (0x66, 0x3d),
        (0x67, 0x3e),
    ];

    static HOOK_LOCK: Mutex<()> = Mutex::new(());
    static mut MOCK_ERRNO: u32 = 0;

    unsafe extern "C" fn mock_storage_errno() -> u32 {
        MOCK_ERRNO
    }

    /// Serializes the hook tests and restores the default on drop.
    struct MockErrno(#[allow(dead_code)] MutexGuard<'static, ()>);

    impl MockErrno {
        fn install() -> Self {
            let guard = HOOK_LOCK.lock().unwrap();
            unsafe {
                (*core::ptr::addr_of_mut!(FS_ERROR_HOOKS)).storage_errno = mock_storage_errno;
            }
            MockErrno(guard)
        }

        fn set(&self, errno: u32) {
            unsafe { MOCK_ERRNO = errno };
        }
    }

    impl Drop for MockErrno {
        fn drop(&mut self) {
            unsafe {
                (*core::ptr::addr_of_mut!(FS_ERROR_HOOKS)).storage_errno =
                    storage_errno_from_record;
            }
        }
    }

    fn accessor(status_override: u32) -> FileAccessor {
        FileAccessor {
            head: [0xdead_beef; 8],
            status_override,
        }
    }

    // ---- the mapping body @ 0x0829dbb4 --------------------------------

    #[test]
    fn every_listed_code_maps_to_its_status() {
        for &(errno, status) in MAPPED {
            assert_eq!(
                status_for_storage_error(errno),
                status,
                "errno {errno:#x}"
            );
        }
    }

    #[test]
    fn the_gaps_and_the_tail_fall_through_to_unknown() {
        // 12 sits between the jump table (0..=10) and the 11 special
        // case; 14..=21, 23, 25..=27, 29 and everything past 0x67 are
        // holes in the compare tree.
        for errno in 0..=0x80u32 {
            if MAPPED.iter().any(|&(code, _)| code == errno) {
                continue;
            }
            assert_eq!(
                status_for_storage_error(errno),
                STATUS_UNKNOWN,
                "unmapped errno {errno:#x}"
            );
        }
    }

    #[test]
    fn codes_the_original_reads_as_negative_are_unknown() {
        // `cmp r1,#0xa; addls pc, ...` is an UNSIGNED test, so a
        // negative code misses the jump table; the signed tree above it
        // then routes it to the 0x4b default.
        for errno in [0x8000_0000, 0xffff_ffff, 0xffff_fff6, 0x7fff_ffff] {
            assert_eq!(status_for_storage_error(errno), STATUS_UNKNOWN, "{errno:#x}");
        }
    }

    #[test]
    fn no_status_collides_with_success() {
        // Callers return this value straight out as their result, where
        // 0 means success — the mapping must never produce one.
        for &(_, status) in MAPPED {
            assert_ne!(status, 0);
        }
        assert_ne!(STATUS_UNKNOWN, 0);
    }

    // ---- the entry stub @ 0x0829dcf8 ----------------------------------

    #[test]
    fn a_parked_override_is_returned_verbatim() {
        let mock = MockErrno::install();
        mock.set(2); // would map to 0x07 if consulted
        for parked in [1, 0x4b, 0x53, 0xffff_ffff] {
            let object = accessor(parked);
            assert_eq!(unsafe { fs_error_status(&object) }, parked);
        }
    }

    #[test]
    fn a_cleared_override_consults_the_storage_errno() {
        let mock = MockErrno::install();
        for &(errno, status) in MAPPED {
            mock.set(errno);
            let object = accessor(0);
            assert_eq!(unsafe { fs_error_status(&object) }, status, "errno {errno:#x}");
        }
        mock.set(0x1234);
        let object = accessor(0);
        assert_eq!(unsafe { fs_error_status(&object) }, STATUS_UNKNOWN);
    }

    #[test]
    fn errno_zero_maps_rather_than_reading_as_success() {
        // The zero test is on the override word, not on the errno: a
        // cleared record still yields the code-0 status 0x3f.
        let mock = MockErrno::install();
        mock.set(0);
        let object = accessor(0);
        assert_eq!(unsafe { fs_error_status(&object) }, 0x3f);
    }

    #[test]
    fn only_the_word_at_plus_0x20_is_read() {
        // The head is poison; touching it would show up as a wrong
        // answer rather than a silent field overlap.
        let mock = MockErrno::install();
        mock.set(9);
        let mut object = accessor(0);
        object.head = [0x1111_1111; 8];
        assert_eq!(unsafe { fs_error_status(&object) }, 0x32);
        assert_eq!(object.head, [0x1111_1111; 8], "the accessor is not written");
    }

    #[test]
    fn the_override_field_sits_at_byte_offset_0x20() {
        let object = accessor(0);
        let base = &object as *const FileAccessor as usize;
        let field = core::ptr::addr_of!(object.status_override) as usize;
        assert_eq!(field - base, 0x20);
    }
}
