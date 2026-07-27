//! The ADS 1.0.1 stream sync/seek engine pair from osos — the last two
//! unported pieces of the buffered-stdio cluster:
//!
//! - `stream_sync_core` @ 0x0802fc00 (156 bytes) — the flush/position-sync
//!   core shared by the fflush family (0x0802fcb0/0x0802fcd4 inside fflush
//!   @ 0x0802fc9c), `stdio_foreach_close` (0x08030118) and `fclose_core`
//!   (0x0803026c); all four call sites binary-verified. It is the target
//!   of BOTH `stdio_init.rs`'s [`STREAM_SYNC_CORE`] hook (second argument
//!   `take_lock`) and `stream_file.rs`'s `STREAM_CLOSE_CORE` hook (second
//!   argument `not_excluded` — same routine, the argument only gates the
//!   patched-out lock brackets).
//! - `fseek_core` @ 0x0802fd04 (492 bytes) — the buffered fseek engine
//!   behind the public `fseek` @ 0x0802fef0 ([`crate::stdio_init::
//!   STREAM_SEEK_CORE`]); its only other caller is `stream_sync_core`
//!   (0x0802fc7c). Both call sites binary-verified.
//!
//! All callees are already ported and are called directly
//! (`stdio_sync_alt_offset` / `stdio_flush_buffer_core` @ 0x080301d4 /
//! 0x08030138, `stdio_stream_error_reset` @ 0x08030004, `_sys_istty` /
//! `_sys_flen` @ 0x08031ffc/0x08032034) — except the sync core's tail
//! call into the seek engine, which goes through the [`STREAM_SEEK_CORE`]
//! hook slot (house pattern; the slot's default IS [`fseek_core`], so the
//! firmware build links the original call graph 0x0802fc00 -> 0x0802fd04
//! while tests can still isolate the sync core).
//!
//! The `mov r0, &lock; mov r0, r0` pairs bracketing the originals are the
//! patched-out per-stream lock hooks — omitted, house precedent
//! (stream_flags.rs); this makes `stream_sync_core`'s `take_lock` flag
//! behaviorally dead (it only chose whether to run those brackets).
//!
//! Flag bits: all previously recovered (fread.rs / getc_core.rs /
//! stream_file.rs) except [`SHARED_BUFFER_HI`] (0x400), the upper half of
//! getc_core's `SHARED_BUFFER_MASK` (0x600), which gates `fseek_core`'s
//! in-window `count` update on its own.

use crate::fread::{
    FLAG_ALT_OFFSET, FLAG_ERROR, FLAG_GOT_REFILL, FLAG_STRING_MODE,
};
use crate::getc_core::{
    max_ptr, ptr_add, ptr_diff, stdio_flush_buffer_core, stdio_sync_alt_offset, FLAG_BUF_LIVE,
    FLAG_SEEK_PENDING, FLAG_UNGETC_PENDING, FLAG_WRITE_BUF_LIVE, MODE_READ, MODE_WRITE,
    SHARED_BUFFER_MASK,
};
use crate::semihost::{_sys_flen, _sys_istty};
use crate::stdio_init::STREAM_SEEK_CORE;
use crate::stream_file::{stdio_stream_error_reset, AdsFile, FLAG_BUF_DIRTY};

/// flags bit 0x400: the upper half of getc_core's `SHARED_BUFFER_MASK`
/// (0x600). `fseek_core`'s in-window `count` update requires this bit
/// clear (while the `field_08` update requires the whole 0x600 pair
/// clear).
pub const SHARED_BUFFER_HI: u32 = 0x400;

/// Volatile hook read (keeps runtime swapping alive; house pattern).
#[inline(always)]
unsafe fn hook<T: Copy>(slot: *const T) -> T {
    core::ptr::read_volatile(slot)
}

/// stream_sync_core — original @ 0x0802fc00 (156 bytes).
///
/// The flush/position-sync core: drains any pending buffered write data
/// and re-establishes the stream's logical position as the pending seek
/// target, so the next physical I/O starts from where the buffered view
/// says the stream is.
///
/// - Not-open stream (`flags & 3 == 0`): returns 0 untouched.
/// - The logical position is captured FIRST: `(ptr - base) + offset_end`,
///   or — when `FLAG_ALT_OFFSET` (0x20) is set — the `alt_offset` word,
///   captured BEFORE `stdio_sync_alt_offset` runs (which reconciles the
///   override and may flush).
/// - The buffer-live pair 0x3000 is dropped, the buffer drained through
///   `stdio_flush_buffer_core` (its result is the sync's result), and the
///   captured position re-applied with `fseek_core(file, pos, 0)`
///   (through [`STREAM_SEEK_CORE`]; result ignored, exactly like the
///   original's discarded r0).
///
/// `take_lock` (the original's r1) only gated the patched-out per-stream
/// lock brackets — behaviorally dead, kept for ABI fidelity.
/// `stream_file.rs`'s `stdio_foreach_close` passes its `not_excluded`
/// flag here.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn stream_sync_core(file: *mut AdsFile, take_lock: i32) -> i32 {
    // Nonzero take_lock ran the (patched-out) lock/unlock brackets.
    let _ = take_lock;
    let s = core::ptr::addr_of_mut!((*file).stream);
    let flags = (*s).flags;
    if flags & (MODE_READ | MODE_WRITE) == 0 {
        return 0;
    }
    let pos = if flags & FLAG_ALT_OFFSET == 0 {
        ptr_diff((*s).ptr, (*s).base).wrapping_add((*s).offset_end)
    } else {
        let p = (*s).alt_offset;
        stdio_sync_alt_offset(file);
        p
    };
    (*s).flags &= !(FLAG_BUF_LIVE | FLAG_WRITE_BUF_LIVE);
    let result = stdio_flush_buffer_core(file);
    hook(core::ptr::addr_of!(STREAM_SEEK_CORE))(file, pos, 0);
    result
}

/// fseek_core — original @ 0x0802fd04 (492 bytes).
///
/// The buffered fseek engine. Returns 0 on success, 1 when the
/// `SEEK_END` length query fails (after `stdio_stream_error_reset`), 2
/// for every parameter rejection (stream not open, interactive/tty
/// handle — including a failing `_sys_istty` —, invalid whence, negative
/// target).
///
/// 1. Resolve the target position:
///    - whence 0 (SET): `offset`.
///    - whence 1 (CUR): `offset + cur`, where `cur` is `(ptr - base) +
///      offset_end` (or `alt_offset` under `FLAG_ALT_OFFSET`), minus one
///      when an ungetc byte is parked (`FLAG_UNGETC_PENDING`) and `cur`
///      is positive.
///    - whence 2 (END): `_sys_flen`; `FLAG_SEEK_PENDING` (0x10) is set
///      unconditionally (and survives to the final flags). A negative
///      length is the error-reset exit (return 1). Otherwise the logical
///      end is `max(flen, (max_u(lim, ptr) - base) + offset_end
///      [, alt_offset under FLAG_ALT_OFFSET])` (signed maxima) and the
///      target is `offset + end`.
/// 2. A negative target returns 2.
/// 3. When `lim < ptr` (unsigned — a written-past-lim buffer), `lim`
///    catches up to `ptr` and a set `FLAG_GOT_REFILL` (0x20000) is
///    swapped for `FLAG_SEEK_PENDING`.
/// 4. The target is classified against the buffered window: IN the
///    window iff `offset_end <= target`, `(max_u(lim, ptr) - base) +
///    offset_end >= target` and `offset_end + size > target` (size =
///    the FILE's +0x30 word, the buffer size recorded by the getc core).
///    - In-window: `ptr = base + (target - offset_end)`; for non-string
///      streams `field_08` becomes `delta - size` (write-mode stream
///      with no 0x600 shared-buffer bit; else 0) and `count` becomes
///      `delta - (max_u(lim, ptr) - base)` (read-mode stream without
///      [`SHARED_BUFFER_HI`]; else 0) — a negative `count` encoding the
///      still-valid bytes below `lim`, which the getc core's walkback
///      path delivers without I/O. `FLAG_ALT_OFFSET` is cleared.
///    - Out-of-window: `count`/`field_08` are zeroed (non-string),
///      `alt_offset = target` and `FLAG_ALT_OFFSET` is set (the lazy
///      reposition the getc core / sync reconcile later).
/// 5. The final flags drop 0x280000 (`FLAG_BUF_DIRTY` +
///    `FLAG_UNGETC_PENDING`) and 0x3040 (the buffer-live pair +
///    `FLAG_ERROR`, the sticky-EOF latch) — a seek un-sticks EOF.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn fseek_core(file: *mut AdsFile, offset: i32, whence: i32) -> i32 {
    let s = core::ptr::addr_of_mut!((*file).stream);
    let flags = (*s).flags;
    let handle = (*s).handle;
    if flags & (MODE_READ | MODE_WRITE) == 0 {
        return 2;
    }
    if _sys_istty(handle) != 0 {
        return 2;
    }
    let target = match whence {
        0 => offset,
        1 => {
            let mut cur = if flags & FLAG_ALT_OFFSET == 0 {
                ptr_diff((*s).ptr, (*s).base).wrapping_add((*s).offset_end)
            } else {
                (*s).alt_offset
            };
            if flags & FLAG_UNGETC_PENDING != 0 && cur > 0 {
                cur -= 1;
            }
            offset.wrapping_add(cur)
        }
        2 => {
            let flen = _sys_flen(handle);
            let f = (*s).flags | FLAG_SEEK_PENDING;
            (*s).flags = f;
            if flen < 0 {
                stdio_stream_error_reset(file);
                return 1;
            }
            let mut end = ptr_diff(max_ptr((*s).lim, (*s).ptr), (*s).base)
                .wrapping_add((*s).offset_end);
            if f & FLAG_ALT_OFFSET != 0 && (*s).alt_offset > end {
                end = (*s).alt_offset;
            }
            if flen > end {
                end = flen;
            }
            offset.wrapping_add(end)
        }
        _ => return 2,
    };
    if target < 0 {
        return 2;
    }
    let orig_flags = (*s).flags;
    let mut wf = orig_flags;
    let ptr = (*s).ptr;
    if ((*s).lim as usize) < (ptr as usize) {
        if wf & FLAG_GOT_REFILL != 0 {
            wf = (wf & !FLAG_GOT_REFILL) | FLAG_SEEK_PENDING;
        }
        (*s).lim = ptr;
    }
    let pos = (*s).offset_end;
    let base = (*s).base;
    let buf_end = max_ptr((*s).lim, ptr);
    let size = (*file).field_30 as i32;
    let in_window = pos <= target
        && ptr_diff(buf_end, base).wrapping_add(pos) >= target
        && pos.wrapping_add(size) > target;
    if in_window {
        let delta = target.wrapping_sub(pos);
        if orig_flags & FLAG_STRING_MODE == 0 {
            (*s).field_08 = if wf & SHARED_BUFFER_MASK == 0 && wf & MODE_WRITE != 0 {
                delta.wrapping_sub(size)
            } else {
                0
            };
            (*s).count = if wf & SHARED_BUFFER_HI == 0 && wf & MODE_READ != 0 {
                delta.wrapping_sub(ptr_diff(buf_end, base))
            } else {
                0
            };
        }
        (*s).ptr = ptr_add(base, delta);
        wf &= !FLAG_ALT_OFFSET;
    } else {
        if orig_flags & FLAG_STRING_MODE == 0 {
            (*s).field_08 = 0;
            (*s).count = 0;
        }
        wf |= FLAG_ALT_OFFSET;
        (*s).alt_offset = target;
    }
    (*s).flags = wf
        & !(FLAG_BUF_DIRTY | FLAG_UNGETC_PENDING | FLAG_BUF_LIVE | FLAG_WRITE_BUF_LIVE | FLAG_ERROR);
    0
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::getc_core::FLAG_WRITE_ACTIVE;
    use crate::semihost::tests::{mock_swi, restore_swi, SWI_LOG};
    use crate::semihost::{SYS_FLEN, SYS_ISTTY, SYS_WRITE};
    use crate::stream_file::{ADS_FILE_ZERO, FLAG_EOF_REACHED, FLAG_ERROR_SET, FLAG_LAST_OP_WRITE};
    use std::sync::MutexGuard;
    use std::vec::Vec;

    /// Recorded (offset, whence) pairs from the seek-core mock.
    static mut SEEK_CALLS: Vec<(i32, i32)> = Vec::new();

    unsafe extern "C" fn recording_seek(_file: *mut AdsFile, offset: i32, whence: i32) -> i32 {
        (*core::ptr::addr_of_mut!(SEEK_CALLS)).push((offset, whence));
        0
    }

    /// Locks the SWI boundary with scripted results and installs the
    /// recording seek mock into [`STREAM_SEEK_CORE`] (restored by the
    /// next lock holder's reset).
    fn lock_and_mock(results: &[i32]) -> MutexGuard<'static, ()> {
        let guard = mock_swi(results);
        unsafe {
            STREAM_SEEK_CORE = recording_seek;
            (*core::ptr::addr_of_mut!(SEEK_CALLS)).clear();
        }
        guard
    }

    fn seek_calls() -> Vec<(i32, i32)> {
        unsafe { (*core::ptr::addr_of!(SEEK_CALLS)).clone() }
    }

    fn swi_log() -> Vec<(usize, Vec<usize>)> {
        unsafe { (*core::ptr::addr_of!(SWI_LOG)).clone() }
    }

    /// Restores the seek hook and the SWI mock. Takes the lock guard by
    /// value: several tests run multiple sub-cases, and `let _guard =`
    /// shadowing does NOT drop the previous guard — re-locking while
    /// still holding it deadlocks the test thread. Consuming it here
    /// makes that mistake unrepresentable.
    fn restore(guard: MutexGuard<'static, ()>) {
        unsafe {
            STREAM_SEEK_CORE = fseek_core;
        }
        restore_swi();
        drop(guard);
    }

    /// A FILE over `buf` with `used` bytes pending (ptr past base).
    fn file_over(buf: &mut [u8], flags: u32, used: usize) -> AdsFile {
        let mut f = ADS_FILE_ZERO;
        f.stream.flags = flags;
        f.stream.handle = 7;
        f.stream.base = buf.as_mut_ptr();
        f.stream.lim = buf.as_mut_ptr();
        f.stream.ptr = unsafe { buf.as_mut_ptr().add(used) };
        f
    }

    // --- stream_sync_core ------------------------------------------------

    #[test]
    fn sync_not_open_stream_returns_zero_untouched() {
        let _guard = lock_and_mock(&[]);
        let mut f = ADS_FILE_ZERO;
        f.stream.flags = FLAG_BUF_LIVE | FLAG_WRITE_BUF_LIVE; // no open bit
        f.stream.count = 9;
        unsafe {
            assert_eq!(stream_sync_core(&mut f, 0), 0);
        }
        assert_eq!(f.stream.flags, FLAG_BUF_LIVE | FLAG_WRITE_BUF_LIVE, "untouched");
        assert_eq!(f.stream.count, 9);
        assert!(seek_calls().is_empty(), "no reposition");
        assert!(swi_log().is_empty(), "no I/O");
        restore(_guard);
    }

    #[test]
    fn sync_drains_and_reseeks_to_the_logical_position() {
        let _guard = lock_and_mock(&[0]); // the drain's SYS_WRITE
        let mut buf = *b"dirty___";
        let mut f = file_over(
            &mut buf,
            MODE_WRITE | FLAG_WRITE_ACTIVE | FLAG_BUF_LIVE | FLAG_WRITE_BUF_LIVE,
            5,
        );
        f.stream.offset_end = 100;
        unsafe {
            assert_eq!(stream_sync_core(&mut f, 0), 0);
        }
        assert_eq!(
            swi_log(),
            std::vec![(SYS_WRITE, std::vec![7, buf.as_mut_ptr() as usize, 5])],
            "pending bytes drained through the flush core"
        );
        // Logical position captured BEFORE the drain: (ptr - base) + pos.
        assert_eq!(seek_calls(), std::vec![(105, 0)]);
        assert_eq!(f.stream.offset_end, 105, "advanced by the drain");
        assert_eq!(
            f.stream.flags,
            MODE_WRITE | FLAG_LAST_OP_WRITE,
            "0x3000 pair and write-active dropped"
        );
        assert_eq!(f.stream.ptr, buf.as_mut_ptr(), "rewound by the flush core");
        restore(_guard);
    }

    #[test]
    fn sync_alt_offset_position_is_captured_before_the_reconcile() {
        let _guard = lock_and_mock(&[]);
        let mut buf = *b"abcdefgh";
        let mut f = file_over(&mut buf, MODE_READ | FLAG_ALT_OFFSET, 3);
        f.stream.offset_end = 10;
        f.stream.alt_offset = 200; // mismatched: the reconcile repositions
        unsafe {
            assert_eq!(stream_sync_core(&mut f, 0), 0);
        }
        // The seek target is the alt_offset read before the reconcile.
        assert_eq!(seek_calls(), std::vec![(200, 0)]);
        assert_eq!(f.stream.offset_end, 200, "reconcile adopted alt_offset");
        assert_ne!(f.stream.flags & FLAG_SEEK_PENDING, 0);
        assert_eq!(f.stream.ptr, buf.as_mut_ptr(), "reconcile rewound the buffer");
        assert!(swi_log().is_empty(), "read stream: nothing drained");
        restore(_guard);
    }

    #[test]
    fn sync_flush_failure_propagates_but_still_reseeks() {
        let _guard = lock_and_mock(&[3]); // 3 bytes NOT written: drain fails
        let mut buf = *b"dirty___";
        let mut f = file_over(&mut buf, MODE_WRITE | FLAG_WRITE_ACTIVE, 5);
        f.stream.offset_end = 40;
        unsafe {
            assert_eq!(stream_sync_core(&mut f, 0), -1, "flush result passes through");
        }
        assert_eq!(seek_calls(), std::vec![(45, 0)], "reposition still attempted");
        assert_ne!(f.stream.flags & FLAG_ERROR_SET, 0, "error latched by the drain");
        restore(_guard);
    }

    #[test]
    fn sync_take_lock_flag_is_behaviorally_dead() {
        for take_lock in [0, 1, -5] {
            let _guard = lock_and_mock(&[]);
            let mut buf = *b"abcdefgh";
            let mut f = file_over(&mut buf, MODE_READ | FLAG_BUF_LIVE, 2);
            f.stream.offset_end = 8;
            unsafe {
                assert_eq!(stream_sync_core(&mut f, take_lock), 0);
            }
            assert_eq!(seek_calls(), std::vec![(10, 0)]);
            assert_eq!(f.stream.flags, MODE_READ, "buffer-live pair dropped");
            restore(_guard);
        }
    }

    #[test]
    fn sync_satisfies_both_hook_contracts() {
        // The same routine backs STREAM_SYNC_CORE and STREAM_CLOSE_CORE.
        let _a: crate::stdio_init::StreamSyncFn = stream_sync_core;
        let _b: crate::stream_file::StreamCloseFn = stream_sync_core;
    }

    // --- fseek_core ------------------------------------------------------

    #[test]
    fn seek_not_open_stream_rejects_without_io() {
        let _guard = lock_and_mock(&[]);
        let mut f = ADS_FILE_ZERO;
        unsafe {
            assert_eq!(fseek_core(&mut f, 0, 0), 2);
        }
        assert!(swi_log().is_empty(), "not even the istty query");
        restore(_guard);
    }

    #[test]
    fn seek_tty_or_failing_istty_rejects() {
        // istty answers 1 (interactive): reject.
        let _guard = lock_and_mock(&[1]);
        let mut buf = *b"abcdefgh";
        let mut f = file_over(&mut buf, MODE_READ, 0);
        unsafe {
            assert_eq!(fseek_core(&mut f, 4, 0), 2);
        }
        assert_eq!(swi_log(), std::vec![(SYS_ISTTY, std::vec![7])]);
        restore(_guard);
        // istty fails (-1, empty script): also nonzero, also reject.
        let _guard = lock_and_mock(&[]);
        let mut f = file_over(&mut buf, MODE_READ, 0);
        unsafe {
            assert_eq!(fseek_core(&mut f, 4, 0), 2);
        }
        restore(_guard);
    }

    #[test]
    fn seek_invalid_whence_and_negative_target_reject() {
        let _guard = lock_and_mock(&[0, 0]);
        let mut buf = *b"abcdefgh";
        let mut f = file_over(&mut buf, MODE_READ, 0);
        unsafe {
            assert_eq!(fseek_core(&mut f, 0, 3), 2, "whence 3 invalid");
            assert_eq!(fseek_core(&mut f, -1, 0), 2, "negative target");
        }
        restore(_guard);
    }

    #[test]
    fn seek_set_out_of_window_arms_the_lazy_reposition() {
        let _guard = lock_and_mock(&[0]); // istty: not a tty
        let mut buf = *b"abcdefgh";
        let mut f = file_over(
            &mut buf,
            MODE_READ | FLAG_BUF_LIVE | FLAG_ERROR | FLAG_EOF_REACHED | FLAG_BUF_DIRTY,
            3,
        );
        f.stream.lim = unsafe { buf.as_mut_ptr().add(8) };
        f.stream.offset_end = 100;
        f.field_30 = 8;
        f.stream.count = 5;
        f.stream.field_08 = 9;
        unsafe {
            assert_eq!(fseek_core(&mut f, 300, 0), 0);
        }
        assert_eq!(f.stream.alt_offset, 300, "target parked in alt_offset");
        assert_eq!(
            f.stream.flags,
            MODE_READ | FLAG_ALT_OFFSET | FLAG_EOF_REACHED,
            "alt-offset armed; dirty/buf-live/sticky-EOF dropped (0x4000 survives)"
        );
        assert_eq!(f.stream.count, 0);
        assert_eq!(f.stream.field_08, 0);
        assert_eq!(f.stream.ptr, unsafe { buf.as_mut_ptr().add(3) }, "ptr untouched");
        restore(_guard);
    }

    #[test]
    fn seek_set_in_window_walks_the_buffer_without_io() {
        let _guard = lock_and_mock(&[0]);
        let mut buf = *b"abcdefgh";
        let mut f = file_over(&mut buf, MODE_READ | FLAG_BUF_LIVE | FLAG_ALT_OFFSET, 3);
        f.stream.lim = unsafe { buf.as_mut_ptr().add(8) };
        f.stream.offset_end = 100; // window: targets 100..108
        f.field_30 = 8;
        unsafe {
            assert_eq!(fseek_core(&mut f, 104, 0), 0);
        }
        assert_eq!(f.stream.ptr, unsafe { buf.as_mut_ptr().add(4) }, "base + delta");
        // count = delta - (buf_end - base): the negative walkback encoding
        // the 4 still-valid bytes below lim.
        assert_eq!(f.stream.count, 4 - 8);
        assert_eq!(f.stream.field_08, 0, "not a write stream");
        assert_eq!(f.stream.flags, MODE_READ, "alt-offset and buf-live dropped");
        assert_eq!(swi_log(), std::vec![(SYS_ISTTY, std::vec![7])], "no physical seek");
        restore(_guard);
    }

    #[test]
    fn seek_set_window_boundaries() {
        // In iff pos <= target, buffered_end >= target, pos + size > target.
        let cases = [
            (100, true, "pos itself"),
            (108, false, "pos + size: first out"),
            (107, true, "last inside"),
            (99, false, "before pos"),
        ];
        for (target, expect_in, why) in cases {
            let _guard = lock_and_mock(&[0]);
            let mut buf = *b"abcdefgh";
            let mut f = file_over(&mut buf, MODE_READ, 0);
            f.stream.lim = unsafe { buf.as_mut_ptr().add(8) };
            f.stream.offset_end = 100;
            f.field_30 = 8;
            unsafe {
                assert_eq!(fseek_core(&mut f, target, 0), 0, "{}", why);
            }
            assert_eq!(f.stream.flags & FLAG_ALT_OFFSET == 0, expect_in, "{}", why);
            restore(_guard);
        }
    }

    #[test]
    fn seek_set_in_window_write_stream_counts() {
        let _guard = lock_and_mock(&[0]);
        let mut buf = *b"abcdefgh";
        // Write-only stream: field_08 = delta - size, count = 0.
        let mut f = file_over(&mut buf, MODE_WRITE, 0);
        f.stream.lim = unsafe { buf.as_mut_ptr().add(8) };
        f.stream.offset_end = 100;
        f.field_30 = 8;
        unsafe {
            assert_eq!(fseek_core(&mut f, 105, 0), 0);
        }
        assert_eq!(f.stream.field_08, 5 - 8);
        assert_eq!(f.stream.count, 0, "no read bit: count zeroed");
        restore(_guard);
        // A 0x600 shared-buffer bit forces field_08 = 0 too; 0x400 also
        // kills the count update on a readable stream.
        let _guard = lock_and_mock(&[0]);
        let mut f = file_over(&mut buf, MODE_READ | MODE_WRITE | SHARED_BUFFER_HI, 0);
        f.stream.lim = unsafe { buf.as_mut_ptr().add(8) };
        f.stream.offset_end = 100;
        f.field_30 = 8;
        unsafe {
            assert_eq!(fseek_core(&mut f, 105, 0), 0);
        }
        assert_eq!(f.stream.field_08, 0);
        assert_eq!(f.stream.count, 0);
        restore(_guard);
    }

    #[test]
    fn seek_lim_catches_up_and_refill_flag_becomes_seek_pending() {
        let _guard = lock_and_mock(&[0]);
        let mut buf = *b"abcdefgh";
        let mut f = file_over(&mut buf, MODE_WRITE | FLAG_GOT_REFILL, 6); // lim < ptr
        f.stream.offset_end = 100;
        f.field_30 = 8;
        unsafe {
            assert_eq!(fseek_core(&mut f, 300, 0), 0);
        }
        assert_eq!(f.stream.lim, unsafe { buf.as_mut_ptr().add(6) }, "lim = ptr");
        assert_eq!(
            f.stream.flags,
            MODE_WRITE | FLAG_SEEK_PENDING | FLAG_ALT_OFFSET,
            "0x20000 swapped for the seek-pending bit"
        );
        restore(_guard);
    }

    #[test]
    fn seek_cur_offsets_from_the_logical_position() {
        let _guard = lock_and_mock(&[0]);
        let mut buf = *b"abcdefgh";
        let mut f = file_over(&mut buf, MODE_READ, 3);
        f.stream.offset_end = 100; // logical position 103
        f.field_30 = 8;
        unsafe {
            assert_eq!(fseek_core(&mut f, 200, 1), 0);
        }
        assert_eq!(f.stream.alt_offset, 303, "offset + (ptr - base) + pos");
        restore(_guard);
        // Ungetc pending: the parked byte backs the position up by one.
        let _guard = lock_and_mock(&[0]);
        let mut f = file_over(&mut buf, MODE_READ | FLAG_UNGETC_PENDING, 3);
        f.stream.offset_end = 100;
        unsafe {
            assert_eq!(fseek_core(&mut f, 200, 1), 0);
        }
        assert_eq!(f.stream.alt_offset, 302);
        restore(_guard);
        // Alt-offset override wins as the current position.
        let _guard = lock_and_mock(&[0]);
        let mut f = file_over(&mut buf, MODE_READ | FLAG_ALT_OFFSET, 3);
        f.stream.offset_end = 100;
        f.stream.alt_offset = 50;
        unsafe {
            assert_eq!(fseek_core(&mut f, 200, 1), 0);
        }
        assert_eq!(f.stream.alt_offset, 250);
        restore(_guard);
    }

    #[test]
    fn seek_end_uses_the_larger_of_flen_and_the_buffered_end() {
        // flen (500) beyond the buffered view: end = flen.
        let _guard = lock_and_mock(&[0, 500]);
        let mut buf = *b"abcdefgh";
        let mut f = file_over(&mut buf, MODE_READ, 0);
        f.stream.offset_end = 100;
        unsafe {
            assert_eq!(fseek_core(&mut f, -2, 2), 0);
        }
        assert_eq!(
            swi_log(),
            std::vec![(SYS_ISTTY, std::vec![7]), (SYS_FLEN, std::vec![7])]
        );
        assert_eq!(f.stream.alt_offset, 498, "offset + flen");
        assert_ne!(f.stream.flags & FLAG_SEEK_PENDING, 0, "always set by SEEK_END");
        restore(_guard);
        // Buffered write data past flen: end = (max(lim,ptr) - base) + pos.
        let _guard = lock_and_mock(&[0, 500]);
        let mut f = file_over(&mut buf, MODE_WRITE, 8);
        f.stream.offset_end = 600;
        unsafe {
            assert_eq!(fseek_core(&mut f, 0, 2), 0);
        }
        assert_eq!(f.stream.alt_offset, 608);
        restore(_guard);
        // Alt-offset override beyond both: end = alt_offset.
        let _guard = lock_and_mock(&[0, 500]);
        let mut f = file_over(&mut buf, MODE_WRITE | FLAG_ALT_OFFSET, 0);
        f.stream.offset_end = 0;
        f.stream.alt_offset = 700;
        unsafe {
            assert_eq!(fseek_core(&mut f, 0, 2), 0);
        }
        assert_eq!(f.stream.alt_offset, 700);
        restore(_guard);
    }

    #[test]
    fn seek_end_flen_failure_error_resets_and_returns_one() {
        let _guard = lock_and_mock(&[0]); // istty ok; flen -1 (script empty)
        let mut buf = *b"abcdefgh";
        let mut f = file_over(&mut buf, MODE_READ, 0);
        f.stream.count = 4;
        unsafe {
            assert_eq!(fseek_core(&mut f, 0, 2), 1);
        }
        assert_ne!(f.stream.flags & FLAG_SEEK_PENDING, 0, "set before the check");
        assert_ne!(f.stream.flags & FLAG_ERROR_SET, 0, "error reset ran");
        assert_eq!(f.stream.count, 0, "cleared by the error reset");
        restore(_guard);
    }

    #[test]
    fn seek_string_mode_never_touches_the_count_words() {
        for target in [104, 300] {
            // In-window and out-of-window.
            let _guard = lock_and_mock(&[0]);
            let mut buf = *b"abcdefgh";
            let mut f = file_over(&mut buf, MODE_READ | MODE_WRITE | FLAG_STRING_MODE, 0);
            f.stream.lim = unsafe { buf.as_mut_ptr().add(8) };
            f.stream.offset_end = 100;
            f.field_30 = 8;
            f.stream.count = 41;
            f.stream.field_08 = 42;
            unsafe {
                assert_eq!(fseek_core(&mut f, target, 0), 0);
            }
            assert_eq!(f.stream.count, 41);
            assert_eq!(f.stream.field_08, 42);
            restore(_guard);
        }
    }

    #[test]
    fn seek_clears_the_sticky_eof_latch() {
        let _guard = lock_and_mock(&[0]);
        let mut buf = *b"abcdefgh";
        let mut f = file_over(&mut buf, MODE_READ | FLAG_ERROR | FLAG_UNGETC_PENDING, 0);
        f.stream.offset_end = 0;
        unsafe {
            assert_eq!(fseek_core(&mut f, 50, 0), 0);
        }
        assert_eq!(
            f.stream.flags & (FLAG_ERROR | FLAG_UNGETC_PENDING | FLAG_BUF_DIRTY),
            0,
            "0x280000 and 0x40 dropped by the final mask"
        );
        restore(_guard);
    }

    /// End-to-end: fseek past the buffer, then getc through the real core
    /// repositions the handle and refills from the seek target.
    #[test]
    fn seek_then_getc_repositions_through_the_real_cores() {
        use crate::semihost::{SYS_READ, SYS_SEEK};
        // istty ok; then the getc core: SYS_SEEK ok, SYS_READ full.
        let _guard = lock_and_mock(&[0, 0, 0]);
        let mut buf = *b"abcdefgh";
        let mut f = file_over(&mut buf, MODE_READ, 0);
        f.stream.lim = unsafe { buf.as_mut_ptr().add(8) };
        f.stream.offset_end = 0;
        f.stream.bulk_threshold = 8;
        f.field_30 = 8;
        unsafe {
            assert_eq!(fseek_core(&mut f, 0x40, 0), 0, "out of window: lazy");
            let c = crate::getc_core::stdio_fill_or_flush_core(
                core::ptr::addr_of_mut!(f.stream),
                0,
            );
            assert_eq!(c, b'a' as i32, "refilled buffer's first byte");
        }
        let log = swi_log();
        assert_eq!(log[1], (SYS_SEEK, std::vec![7, 0x40]), "handle moved to the target");
        assert_eq!(log[2].0, SYS_READ);
        assert_eq!(f.stream.offset_end, 0x40);
        restore(_guard);
    }
}
