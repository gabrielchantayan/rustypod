//! The ADS 1.0.1 buffered-stream core trio from osos: the buffered flush
//! core, the alt-offset reconciler, and (next in this module) the
//! __filbuf-scale getc core. Everything operates on the ADS FILE object
//! ([`AdsFile`], see `stream_file.rs`) whose 48-byte [`AdsStream`] prefix
//! is documented in `fread.rs`.
//!
//! Ports:
//! - `stdio_flush_buffer_core` @ 0x08030138 (156 bytes) — drains the live
//!   buffer extent (`max_u(ptr, lim) - base`) of a write-active stream to
//!   the semihost handle via the ported `stdio_writeback` @ 0x08030044 and
//!   rewinds `ptr`/`lim` to `base`. Reached from the fclose core
//!   0x0802fc00 (bl @ 0x0802fc68), from `stdio_sync_alt_offset`
//!   (0x080301d4) and three times from the getc core (0x08034fec).
//! - `stdio_sync_alt_offset` @ 0x080301d4 (100 bytes) — clears
//!   `fread.rs`'s `FLAG_ALT_OFFSET` (0x20) and, when the stream position
//!   (+0x18) disagrees with `alt_offset` (+0x28) — an fseek-style
//!   override happened — flushes any pending write data through the
//!   flush core (result ignored), drops the buffer-live pair (0x3000),
//!   raises [`FLAG_SEEK_PENDING`] (0x10) so the next physical I/O seeks
//!   first, adopts `alt_offset` as the position and rewinds `ptr`/`lim`
//!   to `base`. Always finishes by clearing the EOF pair 0x4040
//!   (`FLAG_EOF_REACHED` + the sticky EOF latch `fread.rs` names
//!   `FLAG_ERROR`). Sole caller: the getc core (0x08034fec).
//!
//! Flag bits recovered here (see also `fread.rs` / `stream_file.rs`):
//! - [`MODE_READ`]/[`MODE_WRITE`] (bits 0/1): the open-mode pair. A
//!   read-only stream (`flags & 3 == 1`) has nothing to flush (success);
//!   flushing is refused (-1) unless the stream is open for write with no
//!   error latched (`flags & 0x82 == 2`).
//! - [`FLAG_WRITE_ACTIVE`] (0x10000): the buffer currently holds pending
//!   write data; only then is anything drained. Cleared on success.
//! - [`FLAG_UNGETC_PENDING`] (0x80000): a pushback byte is parked at FILE
//!   +0x25 (see the getc core); the flush core clears it together with
//!   `stream_file.rs`'s `FLAG_BUF_DIRTY` (0x200000) on entry.
//!
//! The +0x08 word (`field_08` in [`AdsStream`]) is the write-side count
//! twin of `count` (+0x00): the flush core zeroes it for non-string
//! streams once the buffer is drained.
//!
//! Deviations: none beyond the house ones — the original's nop'd
//! lock/unlock hook sites are omitted, and its incidental r0 residue is
//! replaced by the documented 0/-1 result (which every caller does use
//! here, unlike the lock residues elsewhere).

use crate::fread::{AdsStream, FLAG_ALT_OFFSET, FLAG_ERROR, FLAG_STRING_MODE};
use crate::stream_file::{
    stdio_writeback, AdsFile, FLAG_BUF_DIRTY, FLAG_EOF_REACHED, FLAG_ERROR_SET,
};

/// flags bit 0: stream open for reading.
pub const MODE_READ: u32 = 1;
/// flags bit 1: stream open for writing.
pub const MODE_WRITE: u32 = 2;
/// flags bit: the buffer currently holds pending write data (the flush
/// core drains only such streams; the getc core flushes them before
/// turning the buffer around for reading).
pub const FLAG_WRITE_ACTIVE: u32 = 0x0001_0000;
/// flags bit: an ungetc pushback byte is pending at FILE +0x25.
pub const FLAG_UNGETC_PENDING: u32 = 0x0008_0000;
/// flags bit: the next physical read/write must reposition the handle
/// first (raised by [`stdio_sync_alt_offset`]; 0x10 is also the
/// unidentified half of `stream_file.rs`'s `SEEK_BEFORE_WRITE_MASK`).
pub const FLAG_SEEK_PENDING: u32 = 0x10;
/// flags bit: the buffer holds live (readable) data — set by the getc
/// core after a successful refill, dropped on EOF and by
/// [`stdio_sync_alt_offset`].
pub const FLAG_BUF_LIVE: u32 = 0x1000;
/// flags bit: inferred write-side twin of [`FLAG_BUF_LIVE`] (dropped
/// together with it by the sync; tested alongside [`FLAG_WRITE_ACTIVE`]
/// in the getc core's ungetc write-count recompute).
pub const FLAG_WRITE_BUF_LIVE: u32 = 0x2000;

/// The unsigned-higher of two buffer pointers (the originals' recurring
/// `cmp lim, ptr; movls ..., ptr` idiom for the live buffer end).
#[inline]
fn max_ptr(a: *mut u8, b: *mut u8) -> *mut u8 {
    if (a as usize) <= (b as usize) {
        b
    } else {
        a
    }
}

/// 32-bit pointer difference, exactly as the 32-bit originals compute it
/// (host pointers are wider; same-buffer differences still fit).
#[inline]
fn ptr_diff(a: *mut u8, b: *mut u8) -> i32 {
    (a as usize).wrapping_sub(b as usize) as u32 as i32
}

/// stdio_flush_buffer_core — original @ 0x08030138 (156 bytes).
///
/// The buffered flush core. On entry the live buffer end is computed as
/// `max_u(ptr, lim)` and [`FLAG_BUF_DIRTY`] | [`FLAG_UNGETC_PENDING`]
/// (0x280000) are cleared. A read-only stream (`flags & 3 == 1`) returns
/// 0 untouched; a stream that is not "open for write with no error"
/// (`flags & 0x82 != 2`) returns -1; a write-eligible stream without
/// [`FLAG_WRITE_ACTIVE`] returns 0. Otherwise the live extent (if any) is
/// drained via [`stdio_writeback`] — failure returns -1 with the buffer
/// pointers untouched — then `ptr`/`lim` rewind to `base`, `field_08` is
/// zeroed for non-string streams, [`FLAG_WRITE_ACTIVE`] is cleared and 0
/// is returned. (The flags are reloaded after the writeback, which set
/// `FLAG_LAST_OP_WRITE` and may have cleared the seek-pending bits.)
///
/// (`inline(never)` keeps the in-crate callers' `bl` structure matching
/// the original's.)
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn stdio_flush_buffer_core(file: *mut AdsFile) -> i32 {
    let s: *mut AdsStream = core::ptr::addr_of_mut!((*file).stream);
    let base = (*s).base;
    let live_end = max_ptr((*s).lim, (*s).ptr);
    let flags = (*s).flags & !(FLAG_BUF_DIRTY | FLAG_UNGETC_PENDING);
    (*s).flags = flags;
    if flags & (MODE_READ | MODE_WRITE) == MODE_READ {
        return 0;
    }
    if flags & (MODE_WRITE | FLAG_ERROR_SET) != MODE_WRITE {
        return -1;
    }
    if flags & FLAG_WRITE_ACTIVE == 0 {
        return 0;
    }
    if live_end != base && stdio_writeback(base, ptr_diff(live_end, base), file) != 0 {
        return -1;
    }
    (*s).lim = base;
    (*s).ptr = base;
    let f = (*s).flags;
    if f & FLAG_STRING_MODE == 0 {
        (*s).field_08 = 0;
    }
    (*s).flags = f & !FLAG_WRITE_ACTIVE;
    0
}

/// stdio_sync_alt_offset — original @ 0x080301d4 (100 bytes).
///
/// Reconciles the buffered position with an fseek-style override: clears
/// [`FLAG_ALT_OFFSET`] (0x20), and when `offset_end` (+0x18) differs from
/// `alt_offset` (+0x28) runs [`stdio_flush_buffer_core`] (result
/// ignored — a failed drain still repositions), replaces the buffer-live
/// pair 0x3000 with [`FLAG_SEEK_PENDING`] (0x10), adopts `alt_offset` as
/// the position and rewinds `ptr`/`lim` to `base`. Always finishes by
/// clearing the EOF pair 0x4040 ([`FLAG_EOF_REACHED`] | [`FLAG_ERROR`]).
///
/// (`inline(never)` keeps the getc core's `bl` structure matching the
/// original's.)
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn stdio_sync_alt_offset(file: *mut AdsFile) {
    let s: *mut AdsStream = core::ptr::addr_of_mut!((*file).stream);
    (*s).flags &= !FLAG_ALT_OFFSET;
    if (*s).offset_end != (*s).alt_offset {
        stdio_flush_buffer_core(file);
        (*s).flags = ((*s).flags & !(FLAG_BUF_LIVE | FLAG_WRITE_BUF_LIVE)) | FLAG_SEEK_PENDING;
        (*s).offset_end = (*s).alt_offset;
        (*s).lim = (*s).base;
        (*s).ptr = (*s).base;
    }
    (*s).flags &= !(FLAG_EOF_REACHED | FLAG_ERROR);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::semihost::tests::{restore_swi, SWI_LOCK, SWI_LOG, SWI_RESULTS};
    use crate::semihost::{SYS_SEEK, SYS_WRITE};
    use crate::stream_file::{ADS_FILE_ZERO, FLAG_LAST_OP_WRITE};
    use std::sync::MutexGuard;
    use std::vec::Vec;

    /// Takes the shared SWI lock, installs the recording SWI mock with the
    /// given scripted results, and clears the log.
    fn lock_and_mock(results: &[i32]) -> MutexGuard<'static, ()> {
        let guard = SWI_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            crate::semihost::SEMIHOST_SWI = crate::semihost::tests::recording_swi;
            (*core::ptr::addr_of_mut!(SWI_LOG)).clear();
            *core::ptr::addr_of_mut!(SWI_RESULTS) = results.to_vec();
        }
        guard
    }

    fn swi_log() -> Vec<(usize, Vec<usize>)> {
        unsafe { (*core::ptr::addr_of!(SWI_LOG)).clone() }
    }

    /// A write-mode FILE over `buf` with `ptr` advanced `used` bytes.
    fn write_file(buf: &mut [u8], used: usize, extra_flags: u32) -> AdsFile {
        let mut f = ADS_FILE_ZERO;
        f.stream.flags = MODE_WRITE | FLAG_WRITE_ACTIVE | extra_flags;
        f.stream.handle = 7;
        f.stream.base = buf.as_mut_ptr();
        f.stream.lim = buf.as_mut_ptr();
        f.stream.ptr = unsafe { buf.as_mut_ptr().add(used) };
        f
    }

    #[test]
    fn read_only_stream_is_a_clean_no_op() {
        let _guard = lock_and_mock(&[]);
        let mut f = ADS_FILE_ZERO;
        f.stream.flags = MODE_READ | FLAG_BUF_DIRTY | FLAG_UNGETC_PENDING | FLAG_WRITE_ACTIVE;
        f.stream.count = 5;
        unsafe {
            assert_eq!(stdio_flush_buffer_core(&mut f), 0);
        }
        assert_eq!(
            f.stream.flags,
            MODE_READ | FLAG_WRITE_ACTIVE,
            "dirty + ungetc-pending cleared, nothing else touched"
        );
        assert_eq!(f.stream.count, 5);
        assert!(swi_log().is_empty(), "no physical I/O");
        restore_swi();
    }

    #[test]
    fn non_writable_or_errored_stream_refuses() {
        let _guard = lock_and_mock(&[]);
        // Neither read nor write mode.
        let mut f = ADS_FILE_ZERO;
        unsafe {
            assert_eq!(stdio_flush_buffer_core(&mut f), -1);
        }
        // Write mode with the error bit latched.
        let mut f = ADS_FILE_ZERO;
        f.stream.flags = MODE_WRITE | FLAG_ERROR_SET | FLAG_WRITE_ACTIVE;
        unsafe {
            assert_eq!(stdio_flush_buffer_core(&mut f), -1);
        }
        assert!(swi_log().is_empty());
        restore_swi();
    }

    #[test]
    fn writable_but_not_write_active_succeeds_without_io() {
        let _guard = lock_and_mock(&[]);
        let mut buf = *b"pending!";
        let mut f = write_file(&mut buf, 5, 0);
        f.stream.flags &= !FLAG_WRITE_ACTIVE;
        unsafe {
            assert_eq!(stdio_flush_buffer_core(&mut f), 0);
        }
        assert_eq!(f.stream.ptr, unsafe { buf.as_mut_ptr().add(5) }, "no rewind");
        assert!(swi_log().is_empty());
        restore_swi();
    }

    #[test]
    fn drains_live_extent_and_rewinds() {
        let _guard = lock_and_mock(&[0]); // write succeeds fully
        let mut buf = *b"payload_";
        let mut f = write_file(&mut buf, 7, 0);
        f.stream.field_08 = 42;
        f.stream.offset_end = 100;
        unsafe {
            assert_eq!(stdio_flush_buffer_core(&mut f), 0);
        }
        assert_eq!(
            swi_log(),
            std::vec![(SYS_WRITE, std::vec![7, buf.as_mut_ptr() as usize, 7])],
            "live extent base..ptr drained in one write"
        );
        assert_eq!(f.stream.ptr, buf.as_mut_ptr());
        assert_eq!(f.stream.lim, buf.as_mut_ptr());
        assert_eq!(f.stream.field_08, 0, "write-side count zeroed");
        assert_eq!(f.stream.offset_end, 107, "advanced by the writeback");
        assert_eq!(
            f.stream.flags,
            MODE_WRITE | FLAG_LAST_OP_WRITE,
            "write-active cleared; last-op-write from the writeback kept"
        );
        restore_swi();
    }

    #[test]
    fn live_end_is_the_max_of_ptr_and_lim() {
        let _guard = lock_and_mock(&[0]);
        let mut buf = *b"abcdefgh";
        let mut f = write_file(&mut buf, 2, 0);
        // lim beyond ptr: the extent runs to lim.
        f.stream.lim = unsafe { buf.as_mut_ptr().add(6) };
        unsafe {
            assert_eq!(stdio_flush_buffer_core(&mut f), 0);
        }
        assert_eq!(swi_log()[0].1[2], 6, "length = max(ptr, lim) - base");
        restore_swi();
    }

    #[test]
    fn empty_extent_skips_the_write_but_still_completes() {
        let _guard = lock_and_mock(&[]);
        let mut buf = *b"________";
        let mut f = write_file(&mut buf, 0, 0);
        unsafe {
            assert_eq!(stdio_flush_buffer_core(&mut f), 0);
        }
        assert!(swi_log().is_empty(), "nothing to drain");
        assert_eq!(f.stream.flags, MODE_WRITE, "write-active still cleared");
        restore_swi();
    }

    #[test]
    fn writeback_failure_stops_before_the_rewind() {
        let _guard = lock_and_mock(&[3]); // 3 bytes NOT written -> writeback errors
        let mut buf = *b"payload_";
        let mut f = write_file(&mut buf, 7, 0);
        unsafe {
            assert_eq!(stdio_flush_buffer_core(&mut f), -1);
        }
        assert_eq!(f.stream.ptr, unsafe { buf.as_mut_ptr().add(7) }, "no rewind");
        assert_ne!(f.stream.flags & FLAG_ERROR_SET, 0, "error reset ran inside writeback");
        assert_ne!(f.stream.flags & FLAG_WRITE_ACTIVE, 0, "write-active kept");
        restore_swi();
    }

    #[test]
    fn seek_pending_writeback_reaches_the_flush_result() {
        // A stream with a seek-before-write bit set: the drain seeks first
        // (stdio_writeback behavior, exercised through the flush core).
        let _guard = lock_and_mock(&[0, 0]); // seek ok, write ok
        let mut buf = *b"xy______";
        let mut f = write_file(&mut buf, 2, 0x10);
        f.stream.offset_end = 64;
        unsafe {
            assert_eq!(stdio_flush_buffer_core(&mut f), 0);
        }
        assert_eq!(
            swi_log(),
            std::vec![
                (SYS_SEEK, std::vec![7, 64]),
                (SYS_WRITE, std::vec![7, buf.as_mut_ptr() as usize, 2]),
            ]
        );
        restore_swi();
    }

    // --- stdio_sync_alt_offset --------------------------------------------

    #[test]
    fn sync_aligned_position_only_drops_the_flag_bits() {
        let _guard = lock_and_mock(&[]);
        let mut buf = *b"abcdefgh";
        let mut f = write_file(&mut buf, 4, FLAG_ALT_OFFSET | FLAG_EOF_REACHED | FLAG_ERROR);
        f.stream.offset_end = 300;
        f.stream.alt_offset = 300;
        unsafe {
            stdio_sync_alt_offset(&mut f);
        }
        assert_eq!(
            f.stream.flags,
            MODE_WRITE | FLAG_WRITE_ACTIVE,
            "only 0x20 and the EOF pair 0x4040 cleared"
        );
        assert_eq!(f.stream.ptr, unsafe { buf.as_mut_ptr().add(4) }, "no rewind");
        assert_eq!(f.stream.offset_end, 300);
        assert!(swi_log().is_empty(), "no flush");
        restore_swi();
    }

    #[test]
    fn sync_misaligned_flushes_and_repositions() {
        let _guard = lock_and_mock(&[0]); // drain write succeeds
        let mut buf = *b"dirty___";
        let mut f = write_file(
            &mut buf,
            5,
            FLAG_ALT_OFFSET | FLAG_BUF_LIVE | FLAG_WRITE_BUF_LIVE | FLAG_EOF_REACHED | FLAG_ERROR,
        );
        f.stream.offset_end = 10;
        f.stream.alt_offset = 200;
        unsafe {
            stdio_sync_alt_offset(&mut f);
        }
        assert_eq!(
            swi_log(),
            std::vec![(SYS_WRITE, std::vec![7, buf.as_mut_ptr() as usize, 5])],
            "pending write data drained through the flush core"
        );
        assert_eq!(
            f.stream.flags,
            MODE_WRITE | FLAG_LAST_OP_WRITE | FLAG_SEEK_PENDING,
            "buffer-live pair and EOF pair dropped, seek-pending raised"
        );
        assert_eq!(f.stream.offset_end, 200, "alt_offset adopted");
        assert_eq!(f.stream.ptr, buf.as_mut_ptr());
        assert_eq!(f.stream.lim, buf.as_mut_ptr());
        restore_swi();
    }

    #[test]
    fn sync_read_only_stream_repositions_without_io() {
        let _guard = lock_and_mock(&[]);
        let mut buf = *b"abcdefgh";
        let mut f = ADS_FILE_ZERO;
        f.stream.flags = MODE_READ | FLAG_BUF_LIVE;
        f.stream.base = buf.as_mut_ptr();
        f.stream.ptr = unsafe { buf.as_mut_ptr().add(3) };
        f.stream.lim = unsafe { buf.as_mut_ptr().add(8) };
        f.stream.offset_end = 8;
        f.stream.alt_offset = 64;
        unsafe {
            stdio_sync_alt_offset(&mut f);
        }
        assert!(swi_log().is_empty(), "flush core is a no-op for read-only");
        assert_eq!(f.stream.flags, MODE_READ | FLAG_SEEK_PENDING);
        assert_eq!(f.stream.offset_end, 64);
        assert_eq!(f.stream.ptr, buf.as_mut_ptr());
        assert_eq!(f.stream.lim, buf.as_mut_ptr());
        restore_swi();
    }

    #[test]
    fn sync_ignores_a_failed_flush_and_still_repositions() {
        let _guard = lock_and_mock(&[2]); // 2 bytes NOT written -> drain fails
        let mut buf = *b"dirty___";
        let mut f = write_file(&mut buf, 5, FLAG_ALT_OFFSET);
        f.stream.offset_end = 10;
        f.stream.alt_offset = 90;
        unsafe {
            stdio_sync_alt_offset(&mut f);
        }
        assert_ne!(f.stream.flags & FLAG_ERROR_SET, 0, "error latched by the drain");
        assert_ne!(f.stream.flags & FLAG_SEEK_PENDING, 0);
        assert_eq!(f.stream.offset_end, 90, "repositioned regardless");
        assert_eq!(f.stream.ptr, buf.as_mut_ptr());
        restore_swi();
    }

    #[test]
    fn string_stream_keeps_its_write_count() {
        let _guard = lock_and_mock(&[0]);
        let mut buf = *b"payload_";
        let mut f = write_file(&mut buf, 3, FLAG_STRING_MODE);
        f.stream.field_08 = 9;
        unsafe {
            assert_eq!(stdio_flush_buffer_core(&mut f), 0);
        }
        assert_eq!(f.stream.field_08, 9, "string mode: +0x08 untouched");
        assert_eq!(f.stream.ptr, buf.as_mut_ptr(), "rewind still happens");
        restore_swi();
    }
}
