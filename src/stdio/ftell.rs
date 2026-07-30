//! Port of the ADS 1.0.1 public `ftell` entry from osos.
//!
//! - `ftell` — original: `FUN_0802ff38` @ 0x0802ff38 (112 bytes).
//!   Returns the stream's logical position: `(ptr - base) + offset_end`
//!   (stream +0x04/+0x10/+0x18), or the `alt_offset` word (+0x28) when
//!   `FLAG_ALT_OFFSET` (0x20) is set — the exact `cur` formula
//!   `fseek_core`'s SEEK_CUR arm offsets from (seek_core.rs) — minus one
//!   when `FLAG_UNGETC_PENDING` (0x80000) is set and the position is
//!   positive (a parked ungetc byte backs the reported position up).
//!   A not-open stream (`flags & 3 == 0`) stores 1 (EPERM, osos/ADS
//!   errno numbering) through `__rt_errno_addr` (0x0802ecb4, ported in
//!   runtime/errno.rs) and returns -1.
//!
//! Position/identity verified from the machine code: sandwiched between
//! `fseek` @ 0x0802fef0 and `stream_write_block`/`fwrite` @ 0x0802ffa8,
//! and its two callers (binary bl scan: 0x0802907c and 0x0802910c,
//! both inside FUN_08028ff4) take the result and feed it straight into
//! `fseek` — the classic tell-then-seek pattern. Ghidra's three-
//! parameter signature is an artifact: r1/r2 are only scratch loads of
//! `ptr`/`offset_end` on the buffered path; the function takes one
//! argument (the FILE).
//!
//! The `mov r0, file+0x3c; mov r0, r0` pairs bracketing the original
//! are the patched-out per-stream lock hooks — omitted, house precedent
//! (stream_flags.rs / seek_core.rs).

use crate::fread::{AdsStream, FLAG_ALT_OFFSET};
use crate::getc_core::{ptr_diff, FLAG_UNGETC_PENDING, MODE_READ, MODE_WRITE};
use crate::stream_file::AdsFile;

/// ftell — original: `FUN_0802ff38` @ 0x0802ff38 (112 bytes).
///
/// The public ftell entry. See the module header for the full algorithm;
/// in short: logical position from the buffered-view words (or the
/// alt-offset override), ungetc-backed-up by one when a byte is parked,
/// -1 + errno 1 (EPERM) on a stream with no open-mode bits. No state is
/// modified on the success paths, exactly like the original.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ftell(file: *mut AdsFile) -> i32 {
    let s = core::ptr::addr_of_mut!((*file).stream);
    let flags = (*s).flags;
    if flags & (MODE_READ | MODE_WRITE) == 0 {
        // Original: bl __rt_errno_addr; mov r1, #1; str r1, [r0].
        *crate::errno::__rt_errno_addr() = 1; // EPERM
        return -1;
    }
    let mut pos = if flags & FLAG_ALT_OFFSET == 0 {
        ptr_diff((*s).ptr, (*s).base).wrapping_add((*s).offset_end)
    } else {
        (*s).alt_offset
    };
    if flags & FLAG_UNGETC_PENDING != 0 && pos > 0 {
        pos -= 1;
    }
    pos
}

/// Compile-time anchor: ftell touches only the 48-byte stream prefix —
/// it must stay callable on any FILE-like object with an [`AdsStream`]
/// head (mirrors the original, which never reads past +0x28).
#[allow(dead_code)]
fn _ftell_works_on_the_stream_prefix(s: *mut AdsStream) -> i32 {
    unsafe { ftell(s as *mut AdsFile) }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::errno::{errno_get, errno_set};
    use crate::stream_file::ADS_FILE_ZERO;
    use std::sync::{Mutex, MutexGuard};

    /// Serializes tests that read/write the shared errno word
    /// (d2f_checked.rs precedent — each errno consumer owns a lock).
    static ERRNO_LOCK: Mutex<()> = Mutex::new(());

    fn lock_errno() -> MutexGuard<'static, ()> {
        ERRNO_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A FILE over `buf` with the read cursor `used` bytes past base.
    fn file_over(buf: &mut [u8], flags: u32, used: usize) -> AdsFile {
        let mut f = ADS_FILE_ZERO;
        f.stream.flags = flags;
        f.stream.base = buf.as_mut_ptr();
        f.stream.ptr = unsafe { buf.as_mut_ptr().add(used) };
        f
    }

    #[test]
    fn ftell_not_open_stream_fails_with_eperm() {
        let _guard = lock_errno();
        unsafe {
            let saved = errno_get();
            errno_set(0);
            let mut buf = *b"abcdefgh";
            // 0x4 (binary) and 0x1000000 (string mode) set, no open bit.
            let mut f = file_over(&mut buf, 0x4 | 0x1000000, 3);
            f.stream.offset_end = 100;
            assert_eq!(ftell(&mut f), -1);
            assert_eq!(errno_get(), 1, "EPERM through __rt_errno_addr");
            // Stream untouched on the failure path.
            assert_eq!(f.stream.offset_end, 100);
            assert_eq!(f.stream.ptr, buf.as_mut_ptr().add(3));
            errno_set(saved);
        }
    }

    #[test]
    fn ftell_buffered_position_is_ptr_minus_base_plus_offset_end() {
        let mut buf = *b"abcdefgh";
        let mut f = file_over(&mut buf, MODE_READ, 3);
        f.stream.offset_end = 100;
        unsafe {
            assert_eq!(ftell(&mut f), 103);
        }
        // Write-mode stream, cursor at base: exactly offset_end.
        let mut g = file_over(&mut buf, MODE_WRITE, 0);
        g.stream.offset_end = 40;
        unsafe {
            assert_eq!(ftell(&mut g), 40);
        }
    }

    #[test]
    fn ftell_alt_offset_overrides_the_buffered_view() {
        let mut buf = *b"abcdefgh";
        let mut f = file_over(&mut buf, MODE_READ | FLAG_ALT_OFFSET, 3);
        f.stream.offset_end = 100;
        f.stream.alt_offset = 250;
        unsafe {
            assert_eq!(ftell(&mut f), 250, "buffered words ignored");
        }
    }

    #[test]
    fn ftell_parked_ungetc_byte_backs_the_position_up_by_one() {
        let mut buf = *b"abcdefgh";
        let mut f = file_over(&mut buf, MODE_READ | FLAG_UNGETC_PENDING, 3);
        f.stream.offset_end = 100; // logical position 103
        unsafe {
            assert_eq!(ftell(&mut f), 102);
        }
        // The decrement applies on the alt-offset path too.
        let mut g = file_over(&mut buf, MODE_READ | FLAG_ALT_OFFSET | FLAG_UNGETC_PENDING, 3);
        g.stream.alt_offset = 5;
        unsafe {
            assert_eq!(ftell(&mut g), 4);
        }
    }

    #[test]
    fn ftell_ungetc_pending_never_drives_the_position_negative() {
        let mut buf = *b"abcdefgh";
        // Position exactly 0 with a byte parked: stays 0 (subgt).
        let mut f = file_over(&mut buf, MODE_READ | FLAG_UNGETC_PENDING, 0);
        f.stream.offset_end = 0;
        unsafe {
            assert_eq!(ftell(&mut f), 0);
        }
        // A negative position (alt_offset) is left alone as well.
        let mut g = file_over(&mut buf, MODE_READ | FLAG_ALT_OFFSET | FLAG_UNGETC_PENDING, 0);
        g.stream.alt_offset = -7;
        unsafe {
            assert_eq!(ftell(&mut g), -7);
        }
    }
}
