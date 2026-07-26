//! The ADS 1.0.1 buffered-stream core trio from osos: the buffered flush
//! core, the alt-offset reconciler, and the __filbuf-scale getc core.
//! Everything operates on the ADS FILE object ([`AdsFile`], see
//! `stream_file.rs`) whose 48-byte [`AdsStream`] prefix is documented in
//! `fread.rs`.
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
//! - `stdio_fill_or_flush_core` @ 0x08034fec (1156 bytes) — the getc
//!   core behind `fread.rs`'s `STREAM_GETC` contract (returns the next
//!   char 0..=255, -1 on EOF/error, -2 when the caller set
//!   `FLAG_BULK_WANTED` and should bulk-refill itself). See the function
//!   docs for the full path map.
//!
//! Correction to the earlier scouting notes (asm-verified): the entry
//! "fast path" only exists for STRING-MODE streams, and even there the
//! available count comes out as `min(0, ptr - lim)` — never positive —
//! so on entry it always falls through; normal streams branch straight
//! past it (`beq 0x08035094`) carrying `count` as the `avail` value. The
//! in-function delivery label the fast path shares is really reached via
//! the negative-`avail` ungetc walkback inside the read-eligible section.
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

use crate::fread::{
    AdsStream, FLAG_ALT_OFFSET, FLAG_BULK_WANTED, FLAG_ERROR, FLAG_GOT_REFILL, FLAG_STRING_MODE,
    STRING_MODE_MASK, STRING_MODE_VALUE,
};
use crate::semihost::{_sys_seek, sys_stub_ret0};
use crate::stream_file::{
    stdio_foreach_close, stdio_stream_error_reset, stdio_writeback, stream_raw_read, AdsFile,
    FLAG_BUF_DIRTY, FLAG_EOF_REACHED, FLAG_ERROR_SET, FLAG_LAST_OP_WRITE, STDIO_ALLOC,
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
/// flags bit: set by the getc core for the duration of (and after) a
/// getc — never cleared by it. Part of the string-mode and write-state
/// masked pairs below.
pub const FLAG_IN_GETC: u32 = 0x0040_0000;
/// flags bit: the buffer was lazily malloc'd by the getc core (the
/// fclose engine @ 0x08030238 frees it on this bit).
pub const FLAG_BUF_ALLOCATED: u32 = 0x800;
/// flags bits: explicit buffering mode (setvbuf-style); when none is
/// set, the lazy allocation defaults the stream to [`FLAG_FULL_BUFFERING`].
pub const BUFFERING_MODE_MASK: u32 = 0x300;
/// See [`BUFFERING_MODE_MASK`].
pub const FLAG_FULL_BUFFERING: u32 = 0x100;
/// flags bits: the stream shares its buffer; before a refill the getc
/// core flushes every other live stream via `stdio_foreach_close`.
pub const SHARED_BUFFER_MASK: u32 = 0x600;
/// Masked test for "may read now": `flags & 0x60c9 == MODE_READ` — open
/// for read with none of 0x8, the EOF pair 0x4040, [`FLAG_WRITE_BUF_LIVE`]
/// or [`FLAG_EOF_REACHED`]'s neighbors set. Literal pool @ 0x0803547c.
pub const READ_ELIGIBLE_MASK: u32 = 0x60c9;
/// Masked pair identifying the writable buffer state in the ungetc
/// variant's write-count recompute: `flags & 0x4816a2 == 0x400002`
/// (write mode + [`FLAG_IN_GETC`], none of the error/live/shared bits).
/// Literal pool @ 0x08035478.
pub const WRITE_STATE_MASK: u32 = 0x0048_16a2;
/// See [`WRITE_STATE_MASK`].
pub const WRITE_STATE_VALUE: u32 = 0x0040_0002;

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

/// Byte-offset pointer arithmetic with the original's 32-bit wrapping
/// semantics (`n` may be negative — the raw-read error path really does
/// compute `lim = dest - 1`).
#[inline]
fn ptr_add(p: *mut u8, n: i32) -> *mut u8 {
    (p as usize).wrapping_add(n as isize as usize) as *mut u8
}

/// The string-mode available count, as the getc core computes it twice
/// (entry and the ungetc variant): 0 unless the masked flags identify
/// the readable string-mode state, else `min(0, ptr - lim)` — a negative
/// value encodes ungetc lookahead below `lim`. The original's
/// `flags & 0x1000` sub-branch computes the same value as its
/// fall-through and is collapsed (the same simplification `fread.rs`
/// documents for its `buffered_remaining`).
#[inline]
unsafe fn string_avail(flags: u32, s: *const AdsStream) -> i32 {
    if flags & STRING_MODE_MASK != STRING_MODE_VALUE {
        return 0;
    }
    let ptr = (*s).ptr as usize;
    let lim = (*s).lim as usize;
    if lim <= ptr {
        0
    } else {
        ptr.wrapping_sub(lim) as u32 as i32
    }
}

/// `*ptr++` — the delivery tail shared by the (string-mode-only) entry
/// fast path and the negative-count ungetc walkback.
#[inline]
unsafe fn deliver_from_ptr(s: *mut AdsStream) -> i32 {
    let p = (*s).ptr;
    (*s).ptr = ptr_add(p, 1);
    *p as i32
}

/// stdio_fill_or_flush_core — original @ 0x08034fec (1156 bytes).
///
/// The buffered getc core behind `fread.rs`'s `STREAM_GETC` contract:
/// returns the next character (0..=255), -1 on EOF or error, or -2 when
/// the caller set [`FLAG_BULK_WANTED`] and should refill its own buffer
/// through `STREAM_REFILL` instead. `lock_mode` only gates the original's
/// patched-out per-stream lock/unlock hooks (`mov r0, r0` pairs fed
/// `&file.lock`) and is behaviorally dead; both callers pass 0.
///
/// Path map (all asm-verified):
/// - Entry sets [`FLAG_IN_GETC`] (never cleared) and computes `avail`:
///   `count` for normal streams, [`string_avail`] (≤ 0) for string mode —
///   a positive string `avail` would deliver `*ptr++` directly, but the
///   computation can't produce one at entry (see the module docs).
/// - [`FLAG_UNGETC_PENDING`] set: the variant clears the bit and — for
///   normal streams — recomputes `count` from `ptr`/`lim` (negative =
///   pushback lookahead) and the write-side count `field_08` from the
///   [`WRITE_STATE_MASK`] pair (`size - used` for a full live write
///   buffer, `used - size` otherwise, 0 when not in write state, where
///   `size` is the FILE's +0x30 word), then sets `FLAG_BUF_DIRTY` and
///   returns the pushback byte parked at FILE +0x25.
/// - Main path: drops `FLAG_BUF_DIRTY`; [`FLAG_ALT_OFFSET`] runs
///   [`stdio_sync_alt_offset`]. Streams failing the [`READ_ELIGIBLE_MASK`]
///   test zero `count` and either report the latched EOF (rewriting the
///   0x5000 pair to [`FLAG_ERROR`], `field_08 = used - size`) or run
///   `stdio_stream_error_reset`; both return -1.
/// - Read-eligible: a missing buffer is lazily allocated
///   ([`STDIO_ALLOC`], size +0x1c; result unchecked, as in the original)
///   setting [`FLAG_BUF_ALLOCATED`] (+[`FLAG_FULL_BUFFERING`] when no
///   mode bit is set). Negative `avail` is the ungetc walkback:
///   `count = -(count + 1)`, [`FLAG_BUF_LIVE`] on, `field_08 = 0`,
///   deliver `*ptr++`.
/// - Otherwise the refill window is prepared. [`FLAG_SEEK_PENDING`]
///   first flushes (write-active) or seeks the handle to
///   `pos + (ptr - base)` (after the `_sys_ensure` stub @ 0x0803202c
///   when [`FLAG_LAST_OP_WRITE`] is set) — a failed seek error-resets.
///   A write-active buffer is drained through the flush core: full
///   buffers refill from `base` for the whole size; partially-used ones
///   restore the position the drain advanced, re-seek past the drained
///   bytes, set [`FLAG_GOT_REFILL`] and refill only the unused tail
///   (under [`FLAG_BULK_WANTED`] the position also advances past the
///   drained bytes). Read-state buffers advance `pos` by the consumed
///   `ptr - base` and refill the whole buffer from `base`.
/// - [`SHARED_BUFFER_MASK`] streams flush everyone else via
///   `stdio_foreach_close(self)`. [`FLAG_BULK_WANTED`] answers -2 here
///   (pointers rewound to `base`) instead of refilling.
/// - The refill goes through `stream_raw_read` @ 0x08034f88;
///   `lim = dest + n`, the FILE's +0x30 size word becomes the buffer
///   size. Nonzero `n` delivers `dest[0]` (`count = n - 1`,
///   `ptr = dest + 1`, [`FLAG_GOT_REFILL`]) — NOTE this includes the
///   raw-read error result -1, faithfully reproduced (`count` becomes
///   -2 and a stale byte is returned; the error reset already ran
///   inside the raw read). `n == 0` is clean EOF: [`FLAG_BUF_LIVE`]
///   drops, [`FLAG_ERROR`] latches, `count = 0`, `ptr = dest`,
///   `field_08 = (dest - base) - size` for plain normal streams, -1.
///
/// Deviations:
/// - The lazy malloc goes through `stream_file.rs`'s [`STDIO_ALLOC`]
///   slot (defaults to the ported `malloc` @ 0x0802edac — the firmware
///   build links the original call graph; host tests inject buffers).
/// - The ensure stub 0x0803202c receives the handle in r0 in the
///   original; the ported [`sys_stub_ret0`] takes no arguments (it
///   ignored r0 anyway — ABI-identical for a no-arg callee).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn stdio_fill_or_flush_core(stream: *mut AdsStream, _lock_mode: i32) -> i32 {
    let file = stream as *mut AdsFile;
    let s = stream;

    // Entry: raise the in-getc marker, compute the available count.
    let f = (*s).flags | FLAG_IN_GETC;
    (*s).flags = f;
    let avail: i32;
    if f & FLAG_STRING_MODE == 0 {
        avail = (*s).count;
    } else {
        avail = string_avail(f, s);
        if avail > 0 {
            return deliver_from_ptr(s);
        }
    }

    if f & FLAG_UNGETC_PENDING != 0 {
        // === ungetc-pending variant: hand back the parked byte ===
        let f = f & !FLAG_UNGETC_PENDING;
        (*s).flags = f;
        if f & FLAG_STRING_MODE == 0 {
            (*s).count = string_avail(f, s);
            let used = ptr_diff((*s).ptr, (*s).base);
            let size = (*file).field_30 as i32;
            (*s).field_08 = if f & WRITE_STATE_MASK != WRITE_STATE_VALUE {
                0
            } else if f & FLAG_WRITE_BUF_LIVE != 0 && f & FLAG_WRITE_ACTIVE != 0 && used >= size {
                size - used
            } else {
                used - size
            };
        }
        (*s).flags = f | FLAG_BUF_DIRTY;
        return *(core::ptr::addr_of!((*s).field_24) as *const u8).add(1) as i32;
    }

    // === main path ===
    let f = f & !FLAG_BUF_DIRTY;
    (*s).flags = f;
    if f & FLAG_ALT_OFFSET != 0 {
        stdio_sync_alt_offset(file);
    }
    let f = (*s).flags;
    if f & READ_ELIGIBLE_MASK != MODE_READ {
        if f & FLAG_STRING_MODE == 0 {
            (*s).count = 0;
        }
        if f & (FLAG_EOF_REACHED | FLAG_ERROR) == 0 {
            stdio_stream_error_reset(file);
            return -1;
        }
        // A latched EOF re-reports: the 0x5000 pair collapses to the
        // sticky EOF bit, field_08 reflects the consumed buffer.
        (*s).flags = (f & !(FLAG_BUF_LIVE | FLAG_EOF_REACHED)) | FLAG_ERROR;
        (*s).field_08 = ptr_diff((*s).ptr, (*s).base) - (*file).field_30 as i32;
        return -1;
    }
    if (*s).base.is_null() && f & FLAG_WRITE_ACTIVE == 0 {
        // Lazy buffer allocation (result unchecked, as in the original).
        let alloc = core::ptr::read_volatile(core::ptr::addr_of!(STDIO_ALLOC));
        let buf = alloc((*s).bulk_threshold as usize);
        (*s).base = buf;
        (*s).ptr = buf;
        let f = (*s).flags | FLAG_BUF_ALLOCATED;
        (*s).flags = f;
        if f & BUFFERING_MODE_MASK == 0 {
            (*s).flags = f | FLAG_FULL_BUFFERING;
        }
    }
    if avail < 0 {
        // Ungetc walkback: deliver the lookahead byte below lim.
        let f = (*s).flags;
        if f & FLAG_STRING_MODE == 0 {
            (*s).count = -((*s).count + 1);
        }
        (*s).flags = f | FLAG_BUF_LIVE;
        (*s).field_08 = 0;
        return deliver_from_ptr(s);
    }

    // Reposition the handle when an fseek override left a seek pending.
    let f = (*s).flags;
    let handle = (*s).handle;
    if f & FLAG_SEEK_PENDING != 0 {
        if f & FLAG_WRITE_ACTIVE != 0 {
            stdio_flush_buffer_core(file);
        } else {
            if f & FLAG_LAST_OP_WRITE != 0 {
                sys_stub_ret0();
                (*s).flags &= !FLAG_LAST_OP_WRITE;
            }
            let target = ptr_diff((*s).ptr, (*s).base).wrapping_add((*s).offset_end);
            if _sys_seek(handle, target) < 0 {
                stdio_stream_error_reset(file);
                return -1;
            }
        }
    }

    // Choose the refill window (dest, len).
    let dest: *mut u8;
    let len: i32;
    let f = (*s).flags;
    if f & FLAG_WRITE_ACTIVE != 0 {
        // Turn a write buffer around for reading.
        let used = ptr_diff(max_ptr((*s).lim, (*s).ptr), (*s).base);
        let space = (*s).bulk_threshold.wrapping_sub(used);
        if space == 0 {
            stdio_flush_buffer_core(file);
            len = (*s).bulk_threshold;
        } else {
            let saved_pos = (*s).offset_end;
            stdio_flush_buffer_core(file);
            (*s).offset_end = saved_pos;
            if (*s).flags & FLAG_LAST_OP_WRITE != 0 {
                sys_stub_ret0();
                (*s).flags &= !FLAG_LAST_OP_WRITE;
            }
            if _sys_seek(handle, (*s).offset_end.wrapping_add(used)) < 0 {
                stdio_stream_error_reset(file);
                return -1;
            }
            let f = (*s).flags | FLAG_GOT_REFILL;
            (*s).flags = f;
            if f & FLAG_BULK_WANTED != 0 {
                (*s).offset_end = (*s).offset_end.wrapping_add(used);
            }
            len = space;
        }
        dest = ptr_add((*s).base, (*s).bulk_threshold.wrapping_sub(len));
    } else {
        let base = (*s).base;
        (*s).offset_end = (*s).offset_end.wrapping_add(ptr_diff((*s).ptr, base));
        len = (*s).bulk_threshold;
        (*s).lim = base;
        (*s).ptr = base;
        dest = base;
    }

    let f = (*s).flags & !FLAG_SEEK_PENDING;
    (*s).flags = f;
    if f & SHARED_BUFFER_MASK != 0 {
        stdio_foreach_close(file);
    }
    let f = (*s).flags | FLAG_BUF_LIVE;
    (*s).flags = f;
    if f & FLAG_STRING_MODE == 0 {
        (*s).field_08 = 0;
    }
    if f & FLAG_BULK_WANTED != 0 {
        // The caller wants a bulk refill into its own buffer: answer -2.
        let base = (*s).base;
        (*s).lim = base;
        (*s).ptr = base;
        return -2;
    }

    let n = stream_raw_read(dest, len, s);
    (*s).lim = ptr_add(dest, n);
    (*file).field_30 = (*s).bulk_threshold as u32;
    if n != 0 {
        // Includes the raw-read error result -1 (see the doc header).
        let f = (*s).flags;
        if f & FLAG_STRING_MODE == 0 {
            (*s).count = n - 1;
        }
        (*s).ptr = ptr_add(dest, 1);
        (*s).flags = f | FLAG_GOT_REFILL;
        return *dest as i32;
    }
    // Clean EOF.
    let f = ((*s).flags & !FLAG_BUF_LIVE) | FLAG_ERROR;
    (*s).flags = f;
    if f & FLAG_STRING_MODE == 0 {
        (*s).count = 0;
    }
    (*s).ptr = dest;
    if f & FLAG_STRING_MODE != 0 {
        return -1;
    }
    if f & SHARED_BUFFER_MASK != 0 {
        (*s).field_08 = 0;
        return -1;
    }
    (*s).field_08 = ptr_diff(dest, (*s).base) - (*s).bulk_threshold;
    -1
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

    // --- stdio_fill_or_flush_core -----------------------------------------

    use crate::semihost::SYS_READ;
    use crate::stream_file::{
        stderr_file, stdin_file, stdout_file, CLOSE_LIVE_MASK, STDIO_ALLOC, STREAM_CLOSE_CORE,
    };

    /// A read-mode FILE over `buf` (base = ptr = lim = buf, buffer size =
    /// the whole slice).
    fn read_file(buf: &mut [u8], handle: i32) -> AdsFile {
        let mut f = ADS_FILE_ZERO;
        f.stream.flags = MODE_READ;
        f.stream.handle = handle;
        f.stream.base = buf.as_mut_ptr();
        f.stream.ptr = buf.as_mut_ptr();
        f.stream.lim = buf.as_mut_ptr();
        f.stream.bulk_threshold = buf.len() as i32;
        f
    }

    unsafe fn getc(f: &mut AdsFile) -> i32 {
        stdio_fill_or_flush_core(core::ptr::addr_of_mut!(f.stream), 0)
    }

    #[test]
    fn getc_refills_and_delivers_the_first_byte() {
        let _guard = lock_and_mock(&[0]); // SYS_READ: everything read
        let mut buf = *b"abcdefgh";
        let mut f = read_file(&mut buf, 3);
        f.stream.ptr = unsafe { buf.as_mut_ptr().add(2) }; // 2 bytes consumed
        f.stream.offset_end = 10;
        unsafe {
            assert_eq!(getc(&mut f), b'a' as i32);
        }
        let base = buf.as_mut_ptr();
        assert_eq!(
            swi_log(),
            std::vec![(
                SYS_READ,
                std::vec![
                    3,
                    base as usize,
                    8,
                    (MODE_READ | FLAG_IN_GETC | FLAG_BUF_LIVE) as usize
                ]
            )],
            "whole-buffer refill from base, flags riding as the mode word"
        );
        assert_eq!(f.stream.count, 7, "n - 1 buffered after the delivery");
        assert_eq!(f.stream.ptr, unsafe { base.add(1) });
        assert_eq!(f.stream.lim, unsafe { base.add(8) });
        assert_eq!(f.field_30, 8, "+0x30 becomes the buffer size");
        assert_eq!(f.stream.offset_end, 12, "position advanced by the consumed bytes");
        assert_eq!(
            f.stream.flags,
            MODE_READ | FLAG_IN_GETC | FLAG_BUF_LIVE | FLAG_GOT_REFILL
        );
        restore_swi();
    }

    /// Scripted allocator for the lazy-malloc path.
    static mut GETC_ALLOC_BUF: [u8; 16] = *b"QRSTUVWXYZ012345";
    static mut GETC_ALLOC_SIZES: Vec<usize> = Vec::new();
    unsafe extern "C" fn getc_buf_alloc(size: usize) -> *mut u8 {
        (*core::ptr::addr_of_mut!(GETC_ALLOC_SIZES)).push(size);
        core::ptr::addr_of_mut!(GETC_ALLOC_BUF) as *mut u8
    }

    #[test]
    fn getc_lazily_allocates_the_missing_buffer() {
        let _guard = lock_and_mock(&[0]);
        unsafe {
            STDIO_ALLOC = getc_buf_alloc;
            (*core::ptr::addr_of_mut!(GETC_ALLOC_SIZES)).clear();
        }
        let mut f = ADS_FILE_ZERO;
        f.stream.flags = MODE_READ;
        f.stream.handle = 4;
        f.stream.bulk_threshold = 16;
        unsafe {
            assert_eq!(getc(&mut f), b'Q' as i32);
            assert_eq!(*core::ptr::addr_of!(GETC_ALLOC_SIZES), std::vec![16]);
            assert_eq!(f.stream.base, core::ptr::addr_of_mut!(GETC_ALLOC_BUF) as *mut u8);
        }
        assert_ne!(f.stream.flags & FLAG_BUF_ALLOCATED, 0);
        assert_ne!(
            f.stream.flags & FLAG_FULL_BUFFERING,
            0,
            "no explicit buffering mode: defaults to fully buffered"
        );
        assert_eq!(f.stream.count, 15);
        unsafe {
            STDIO_ALLOC = crate::malloc_rt::malloc;
        }
        restore_swi();
    }

    #[test]
    fn getc_bulk_wanted_answers_minus_two_without_reading() {
        let _guard = lock_and_mock(&[]);
        let mut buf = *b"abcdefgh";
        let mut f = read_file(&mut buf, 3);
        f.stream.flags |= FLAG_BULK_WANTED;
        f.stream.ptr = unsafe { buf.as_mut_ptr().add(3) };
        unsafe {
            assert_eq!(getc(&mut f), -2);
        }
        assert!(swi_log().is_empty(), "no physical read");
        assert_eq!(f.stream.ptr, buf.as_mut_ptr(), "rewound to base");
        assert_eq!(f.stream.lim, buf.as_mut_ptr());
        assert_eq!(f.stream.offset_end, 3, "consumed bytes still advance the position");
        assert_ne!(f.stream.flags & FLAG_BUF_LIVE, 0);
        restore_swi();
    }

    #[test]
    fn getc_clean_eof_latches_and_reports() {
        // Bit 31 + all 8 not read: clean EOF from the raw read.
        let _guard = lock_and_mock(&[0x8000_0008u32 as i32]);
        let mut buf = *b"abcdefgh";
        let mut f = read_file(&mut buf, 3);
        unsafe {
            assert_eq!(getc(&mut f), -1);
        }
        assert_eq!(
            f.stream.flags,
            MODE_READ | FLAG_IN_GETC | FLAG_EOF_REACHED | FLAG_ERROR,
            "buffer-live dropped, EOF latched (0x4000 from the raw read)"
        );
        assert_eq!(f.stream.count, 0);
        assert_eq!(f.stream.ptr, buf.as_mut_ptr());
        assert_eq!(f.stream.field_08, -8, "(dest - base) - buffer size");
        restore_swi();
    }

    #[test]
    fn getc_not_read_eligible_runs_the_error_reset() {
        let _guard = lock_and_mock(&[]);
        let mut f = ADS_FILE_ZERO;
        f.stream.flags = MODE_WRITE;
        f.stream.count = 5;
        unsafe {
            assert_eq!(getc(&mut f), -1);
        }
        assert_eq!(
            f.stream.flags,
            MODE_WRITE | FLAG_IN_GETC | FLAG_ERROR_SET,
            "error reset latched the error bit"
        );
        assert_eq!(f.stream.count, 0);
        assert!(swi_log().is_empty());
        restore_swi();
    }

    #[test]
    fn getc_latched_eof_re_reports_without_resetting() {
        let _guard = lock_and_mock(&[]);
        let mut buf = *b"abcdefgh";
        let mut f = read_file(&mut buf, 3);
        f.stream.flags |= FLAG_ERROR | FLAG_EOF_REACHED | FLAG_BUF_LIVE;
        f.stream.ptr = unsafe { buf.as_mut_ptr().add(2) };
        f.field_30 = 5;
        unsafe {
            assert_eq!(getc(&mut f), -1);
        }
        assert_eq!(
            f.stream.flags,
            MODE_READ | FLAG_IN_GETC | FLAG_ERROR,
            "the 0x5000 pair collapses to the sticky EOF bit"
        );
        assert_eq!(f.stream.count, 0);
        assert_eq!(f.stream.field_08, 2 - 5, "(ptr - base) - the +0x30 size");
        assert!(swi_log().is_empty(), "no error reset, no I/O");
        restore_swi();
    }

    #[test]
    fn getc_ungetc_pending_returns_the_parked_byte() {
        let _guard = lock_and_mock(&[]);
        let mut buf = *b"abcdefgh";
        let mut f = read_file(&mut buf, 3);
        f.stream.flags |= FLAG_UNGETC_PENDING;
        f.stream.field_24 = 0x5a00; // little-endian byte 1 = FILE +0x25
        f.stream.ptr = unsafe { buf.as_mut_ptr().add(2) };
        f.stream.lim = unsafe { buf.as_mut_ptr().add(5) };
        unsafe {
            assert_eq!(getc(&mut f), 0x5a);
        }
        assert_eq!(
            f.stream.flags,
            MODE_READ | FLAG_IN_GETC | FLAG_BUF_DIRTY,
            "pending bit swapped for buf-dirty"
        );
        assert_eq!(f.stream.count, -3, "ptr - lim: negative lookahead below lim");
        assert_eq!(f.stream.field_08, 0, "not in write state");
        assert!(swi_log().is_empty());
        restore_swi();
    }

    #[test]
    fn getc_ungetc_pending_write_state_counts() {
        let _guard = lock_and_mock(&[]);
        let mut buf = *b"abcdefgh";
        // Full live write buffer: field_08 = size - used (negative).
        let mut f = read_file(&mut buf, 3);
        f.stream.flags =
            MODE_WRITE | FLAG_UNGETC_PENDING | FLAG_WRITE_BUF_LIVE | FLAG_WRITE_ACTIVE;
        f.stream.ptr = unsafe { buf.as_mut_ptr().add(6) };
        f.field_30 = 4;
        unsafe {
            getc(&mut f);
        }
        assert_eq!(f.stream.field_08, 4 - 6, "size - used for the full live buffer");
        assert_eq!(f.stream.count, 0, "masked pair fails: count cleared");
        // Without the live bit the other leg runs: used - size.
        let mut f = read_file(&mut buf, 3);
        f.stream.flags = MODE_WRITE | FLAG_UNGETC_PENDING | FLAG_WRITE_ACTIVE;
        f.stream.ptr = unsafe { buf.as_mut_ptr().add(6) };
        f.field_30 = 4;
        unsafe {
            getc(&mut f);
        }
        assert_eq!(f.stream.field_08, 6 - 4, "used - size otherwise");
        restore_swi();
    }

    #[test]
    fn getc_ungetc_pending_string_stream_touches_only_flags() {
        let _guard = lock_and_mock(&[]);
        let mut f = ADS_FILE_ZERO;
        f.stream.flags = FLAG_STRING_MODE | MODE_READ | FLAG_UNGETC_PENDING;
        f.stream.count = 77;
        f.stream.field_08 = 55;
        f.stream.field_24 = 0xcc00;
        unsafe {
            assert_eq!(getc(&mut f), 0xcc);
        }
        assert_eq!(
            f.stream.flags,
            FLAG_STRING_MODE | MODE_READ | FLAG_IN_GETC | FLAG_BUF_DIRTY
        );
        assert_eq!(f.stream.count, 77, "string mode: counts untouched");
        assert_eq!(f.stream.field_08, 55);
        restore_swi();
    }

    #[test]
    fn getc_string_mode_negative_avail_walks_the_lookahead_back() {
        let _guard = lock_and_mock(&[]);
        let mut buf = *b"abcdefgh";
        let mut f = read_file(&mut buf, 0);
        f.stream.flags = FLAG_STRING_MODE | MODE_READ;
        f.stream.count = 99;
        f.stream.ptr = unsafe { buf.as_mut_ptr().add(1) };
        f.stream.lim = unsafe { buf.as_mut_ptr().add(4) };
        unsafe {
            assert_eq!(getc(&mut f), b'b' as i32, "delivered from ptr");
        }
        assert_eq!(f.stream.ptr, unsafe { buf.as_mut_ptr().add(2) });
        assert_eq!(f.stream.count, 99, "string mode: count untouched");
        assert_eq!(f.stream.field_08, 0);
        assert_ne!(f.stream.flags & FLAG_BUF_LIVE, 0);
        assert!(swi_log().is_empty());
        restore_swi();
    }

    #[test]
    fn getc_normal_negative_count_walkback_negates_the_count() {
        let _guard = lock_and_mock(&[]);
        let mut buf = *b"abcdefgh";
        let mut f = read_file(&mut buf, 0);
        f.stream.count = -3; // ungetc-encoded lookahead
        f.stream.ptr = unsafe { buf.as_mut_ptr().add(2) };
        unsafe {
            assert_eq!(getc(&mut f), b'c' as i32);
        }
        assert_eq!(f.stream.count, 2, "-(count + 1)");
        assert_eq!(f.stream.ptr, unsafe { buf.as_mut_ptr().add(3) });
        assert_eq!(f.stream.field_08, 0);
        assert!(swi_log().is_empty());
        restore_swi();
    }

    #[test]
    fn getc_seek_pending_read_repositions_first() {
        let _guard = lock_and_mock(&[0, 0]); // seek ok, read ok
        let mut buf = *b"abcdefgh";
        let mut f = read_file(&mut buf, 3);
        f.stream.flags |= FLAG_SEEK_PENDING | FLAG_LAST_OP_WRITE;
        f.stream.ptr = unsafe { buf.as_mut_ptr().add(2) };
        f.stream.offset_end = 10;
        unsafe {
            assert_eq!(getc(&mut f), b'a' as i32);
        }
        let log = swi_log();
        assert_eq!(log.len(), 2);
        assert_eq!(log[0], (SYS_SEEK, std::vec![3, 12]), "seek to pos + (ptr - base)");
        assert_eq!(log[1].0, SYS_READ);
        assert_eq!(f.stream.flags & (FLAG_SEEK_PENDING | FLAG_LAST_OP_WRITE), 0);
        assert_eq!(f.stream.offset_end, 12);
        restore_swi();
    }

    #[test]
    fn getc_seek_failure_is_an_error() {
        let _guard = lock_and_mock(&[-1]);
        let mut buf = *b"abcdefgh";
        let mut f = read_file(&mut buf, 3);
        f.stream.flags |= FLAG_SEEK_PENDING;
        unsafe {
            assert_eq!(getc(&mut f), -1);
        }
        assert_ne!(f.stream.flags & FLAG_ERROR_SET, 0, "error reset ran");
        assert_eq!(swi_log().len(), 1, "nothing after the failed seek");
        restore_swi();
    }

    #[test]
    fn getc_full_write_buffer_drains_then_refills_from_base() {
        let _guard = lock_and_mock(&[0, 0]); // write ok, read ok
        let mut buf = *b"12345678";
        let mut f = read_file(&mut buf, 7);
        f.stream.flags = MODE_READ | MODE_WRITE | FLAG_WRITE_ACTIVE;
        f.stream.ptr = unsafe { buf.as_mut_ptr().add(8) }; // buffer full
        f.stream.offset_end = 50;
        unsafe {
            assert_eq!(getc(&mut f), b'1' as i32);
        }
        let base = buf.as_mut_ptr() as usize;
        let log = swi_log();
        assert_eq!(log[0], (SYS_WRITE, std::vec![7, base, 8]), "whole buffer drained");
        assert_eq!(log[1].0, SYS_READ);
        assert_eq!(log[1].1[1..3], [base, 8], "refill of the whole buffer from base");
        assert_eq!(f.stream.offset_end, 58, "advanced by the drain, kept");
        assert_eq!(f.stream.count, 7);
        assert_eq!(f.stream.flags & FLAG_WRITE_ACTIVE, 0);
        restore_swi();
    }

    #[test]
    fn getc_partial_write_buffer_drains_seeks_and_fills_the_tail() {
        let _guard = lock_and_mock(&[0, 0, 0]); // write, seek, read
        let mut buf = *b"12345678";
        let mut f = read_file(&mut buf, 7);
        f.stream.flags = MODE_READ | MODE_WRITE | FLAG_WRITE_ACTIVE;
        f.stream.ptr = unsafe { buf.as_mut_ptr().add(5) }; // 5 of 8 used
        f.stream.offset_end = 100;
        unsafe {
            assert_eq!(getc(&mut f), b'6' as i32, "delivered from the tail window");
        }
        let base = buf.as_mut_ptr() as usize;
        assert_eq!(
            swi_log(),
            std::vec![
                (SYS_WRITE, std::vec![7, base, 5]),
                (SYS_SEEK, std::vec![7, 105]),
                (
                    SYS_READ,
                    std::vec![
                        7,
                        base + 5,
                        3,
                        (MODE_READ | MODE_WRITE | FLAG_IN_GETC | FLAG_GOT_REFILL | FLAG_BUF_LIVE)
                            as usize
                    ]
                ),
            ],
            "drain, re-seek past the drained bytes, fill only the unused tail"
        );
        assert_eq!(f.stream.offset_end, 100, "restored after the drain (no bulk flag)");
        assert_eq!(f.stream.count, 2);
        assert_eq!(f.stream.ptr, unsafe { buf.as_mut_ptr().add(6) });
        assert_eq!(f.stream.lim, unsafe { buf.as_mut_ptr().add(8) });
        assert_ne!(f.stream.flags & FLAG_GOT_REFILL, 0);
        restore_swi();
    }

    static mut CLOSE_EVENTS: Vec<(usize, i32)> = Vec::new();
    unsafe extern "C" fn logging_close(file: *mut AdsFile, not_excluded: i32) -> i32 {
        (*core::ptr::addr_of_mut!(CLOSE_EVENTS)).push((file as usize, not_excluded));
        0
    }

    #[test]
    fn getc_shared_buffer_flushes_the_other_streams() {
        let _guard = lock_and_mock(&[0x8000_0008u32 as i32]); // clean EOF
        unsafe {
            *stdin_file() = ADS_FILE_ZERO;
            *stdout_file() = ADS_FILE_ZERO;
            *stderr_file() = ADS_FILE_ZERO;
            (*stdin_file()).stream.flags = CLOSE_LIVE_MASK;
            STREAM_CLOSE_CORE = logging_close;
            (*core::ptr::addr_of_mut!(CLOSE_EVENTS)).clear();
        }
        let mut buf = *b"abcdefgh";
        let mut f = read_file(&mut buf, 3);
        f.stream.flags |= 0x200; // shared-buffer bit
        unsafe {
            assert_eq!(getc(&mut f), -1);
            assert_eq!(
                *core::ptr::addr_of!(CLOSE_EVENTS),
                std::vec![(stdin_file() as usize, 1)],
                "live static flushed via foreach_close; self is not in the chain"
            );
            (*stdin_file()).stream.flags = 0;
        }
        assert_eq!(f.stream.field_08, 0, "shared-buffer EOF leg: 0, not (dest-base)-size");
        restore_swi();
    }

    #[test]
    fn getc_raw_read_error_result_is_reproduced_faithfully() {
        // The original treats ANY nonzero raw-read result as a delivery,
        // including the error result -1 (the error reset already ran
        // inside the raw read). Pin that quirk.
        let _guard = lock_and_mock(&[-1]);
        let mut buf = *b"abcdefgh";
        let mut f = read_file(&mut buf, 3);
        unsafe {
            assert_eq!(getc(&mut f), b'a' as i32, "stale byte delivered");
        }
        assert_eq!(f.stream.count, -2, "n - 1 with n = -1");
        assert_ne!(f.stream.flags & FLAG_ERROR_SET, 0, "error latched by the raw read");
        assert_eq!(f.stream.lim, unsafe { buf.as_mut_ptr().sub(1) }, "lim = dest + (-1)");
        restore_swi();
    }

    #[test]
    fn getc_satisfies_the_stream_getc_contract_type() {
        let _f: crate::fread::StreamGetcFn = stdio_fill_or_flush_core;
    }

    /// End-to-end: fread through the real getc core and raw read — the
    /// per-char path and the -2 bulk-refill handshake.
    #[test]
    fn fread_end_to_end_through_the_real_core() {
        let _swi = lock_and_mock(&[0]); // one whole-buffer refill
        let _hooks = crate::fread::tests::HOOK_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        unsafe {
            crate::fread::STREAM_GETC = stdio_fill_or_flush_core;
            crate::fread::STREAM_REFILL = stream_raw_read;
        }
        // Per-char + buffer drain: total (5) <= buffer size (8).
        let mut buf = *b"abcdefgh";
        let mut f = read_file(&mut buf, 5);
        let mut dest = [0u8; 16];
        unsafe {
            assert_eq!(
                crate::fread::fread(dest.as_mut_ptr(), 1, 5, core::ptr::addr_of_mut!(f.stream)),
                5
            );
        }
        assert_eq!(&dest[..5], b"abcde");
        assert_eq!(f.stream.count, 3);
        assert_eq!(swi_log().len(), 1, "single refill served everything");

        // Bulk handshake: total (12) > buffer size (8) -> fread sets
        // FLAG_BULK_WANTED, the core answers -2, fread refills directly.
        unsafe {
            (*core::ptr::addr_of_mut!(SWI_LOG)).clear();
            *core::ptr::addr_of_mut!(SWI_RESULTS) = std::vec![0];
        }
        let mut buf = *b"abcdefgh";
        let mut f = read_file(&mut buf, 5);
        let mut dest = [0u8; 16];
        unsafe {
            assert_eq!(
                crate::fread::fread(dest.as_mut_ptr(), 1, 12, core::ptr::addr_of_mut!(f.stream)),
                12
            );
        }
        let log = swi_log();
        assert_eq!(log.len(), 1, "one direct bulk read, none from the core");
        assert_eq!(log[0].0, SYS_READ);
        assert_eq!(
            log[0].1[1..3],
            [dest.as_mut_ptr() as usize, 12],
            "refilled straight into the caller's buffer"
        );
        unsafe {
            crate::fread::STREAM_GETC = stdio_fill_or_flush_core;
            crate::fread::STREAM_REFILL = stream_raw_read;
        }
        restore_swi();
    }
}
