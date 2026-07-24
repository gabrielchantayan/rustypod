//! Buffered-stream block readers from the ARM ADS 1.0.1 stdio layer.
//!
//! NOTE ON THE BATCH LABEL: this file was assigned as "scanf string/char/
//! scanset converters" on the assumption that 0x0803677c / 0x08036a10 were
//! the `_scanf` `%s` / `%c` / `%[...]` routines. Disassembly proves
//! otherwise: there is no scanset bitmap, no `ctype` whitespace skip and no
//! `'['`/`'^'`/`']'` parsing anywhere in these functions. They are the ADS
//! stdio *buffered read* pair operating on the 48-byte ADS stream struct
//! (flags word at +0x0c with the classic `0x1000000` "string/pseudo stream"
//! bit, a semihosting `SYS_READ` handle at +0x14 — see the refill helper
//! `FUN_08034f88`, which issues Angel `svc 0x123456` reason 6 via
//! `FUN_08031fdc`). `FUN_0803677c` is `fread` in everything but name
//! (`(dest, size, nitems, stream)`, returns whole items = bytes/size). Its
//! only call sites are firmware header parsers in the 0x08028xxx-0x08029xxx
//! range; `FUN_08036a10` has no callers in the image at all (dead-linked
//! library code). The port below mirrors the machine code at the assigned
//! addresses exactly; the scanf-converter semantics from the batch
//! description simply do not exist here. Nothing in this file uses the
//! `ScanfState` front-end from `scanf_helpers` — that is a different
//! (retailOS-custom) scanf subsystem.
//!
//! Ports:
//! - `fread`             @ 0x0803677c (656 bytes) — reads `size * nitems`
//!   bytes into `dest`, returning whole items (`done / size` on early EOF,
//!   `nitems` on completion). Fast path bulk-copies out of the stream
//!   buffer; when the buffer runs dry it either fetches char-by-char
//!   through [`STREAM_GETC`] or — once the getc helper has answered -2
//!   ("bulk refill preferred", see below) and the stream's
//!   `bulk_threshold` field is below the byte count wanted — refills
//!   straight into the user's buffer through [`STREAM_REFILL`]. Register
//!   usage: r0 = dest, r1 = size, r2 = nitems, r3 = stream.
//! - `stream_read_chars` @ 0x08036a10 (360 bytes) — reads up to `n` bytes
//!   into `dest` and returns how many were stored: if the buffer is empty,
//!   one char is pulled through [`STREAM_GETC`] (EOF = -1 returns 0) and
//!   stored, then `min_u(n - stored, buffered)` more are bulk-copied from
//!   the buffer (note the UNSIGNED minimum — see below). The original also
//!   takes a fourth argument in r3 which it never reads; it is dropped
//!   from the Rust signature. Register usage: r0 = dest, r1 = n,
//!   r2 = stream.
//!
//! Stream layout ([`AdsStream`], 48 bytes on the 32-bit target) is the ABI
//! contract with the ADS stdio layer; offsets were recovered from the
//! original machine code and must not change. See the struct docs.
//!
//! The getc helper (`FUN_08034fec`, 1156 bytes) and the refill helper
//! (`FUN_08034f88`, 100 bytes) are separate future ports (the latter does
//! semihosting I/O); both are reached through the [`STREAM_GETC`] /
//! [`STREAM_REFILL`] function pointers, the same pattern `scanf_helpers`
//! uses for `SCANF_ENGINE`. Default stubs report EOF/-1, which makes both
//! readers take their early-EOF exits.
//!
//! Flag bits used here (in `flags` at +0x0c):
//! - [`FLAG_STRING_MODE`] (0x1000000): clear = normal buffered file, the
//!   +0x00 word is the buffered-byte count (may go negative for ungetc
//!   pushback); set = string/pseudo stream, buffer state is derived from
//!   `ptr`/`lim` instead and the count word is never read or written.
//! - [`STRING_MODE_MASK`]/[`STRING_MODE_VALUE`] (0x4820e1 / 0x400001): the
//!   masked flag test that identifies the readable string-mode state.
//! - [`FLAG_BULK_WANTED`] (0x800000): set by `fread` around the getc call
//!   when `bulk_threshold < bytes wanted`; the getc helper answers -2
//!   instead of a char, asking the caller to do a bulk refill.
//! - [`FLAG_ALT_OFFSET`] (0x20): refill offset bookkeeping uses
//!   `alt_offset` (+0x28) instead of `(ptr + offset_end) - base`.
//! - [`FLAG_ERROR`] (0x40): checked after a refill; forces the EOF exit.
//! - [`FLAG_GOT_REFILL`] (0x20000): set by `fread` after a direct refill.
//!
//! Simplifications / deviations vs. the originals:
//! - Both originals bulk-copy with the ADS memcpy living at 0x22000020
//!   (reached via the thunk @ 0x08037db0), which is OUTSIDE the osos
//!   image and therefore not portable. The ranges never overlap, so a
//!   plain byte-copy loop is used ([`copy_bytes`]).
//! - The original `fread` computes items via `__rt_udiv` @ 0x08036f14;
//!   the port calls [`__rt_udiv`] from `crate::rt_div` — the same routine,
//!   already ported in batch 2.
//! - The "buffered bytes remaining" computation appears three times in
//!   the originals with a `(flags & 0x1000)` branch that always yields the
//!   same value as its fall-through (both compute `min(0, ptr - lim)` in
//!   string mode); it is collapsed into [`buffered_remaining`].
//! - Both originals compute `stream + 0x3c` on entry and never use the
//!   result (ADS codegen relic); omitted.
//! - `stream_read_chars`' unsigned minimum (`movcc`) is kept bit-exact:
//!   after a successful getc in string mode, "remaining" is negative and
//!   compares as huge, so `n - 1` bytes are copied from `ptr` regardless.
//!   Likewise `fread`'s fast-path minimum is signed (`movlt`) as in the
//!   original.

use crate::rt_div::__rt_udiv;

/// flags bit: stream is a string/pseudo stream (count word unused).
pub const FLAG_STRING_MODE: u32 = 0x0100_0000;
/// Mask/value pair identifying the readable string-mode state.
pub const STRING_MODE_MASK: u32 = 0x0048_20e1;
/// See [`STRING_MODE_MASK`].
pub const STRING_MODE_VALUE: u32 = 0x0040_0001;
/// flags bit: caller prefers a bulk refill; getc answers -2.
pub const FLAG_BULK_WANTED: u32 = 0x0080_0000;
/// flags bit: refill offset base is `alt_offset`, not `ptr + offset_end - base`.
pub const FLAG_ALT_OFFSET: u32 = 0x20;
/// flags bit: stream error; after a refill forces the EOF exit.
pub const FLAG_ERROR: u32 = 0x40;
/// flags bit: set by `fread` after a successful direct refill.
pub const FLAG_GOT_REFILL: u32 = 0x0002_0000;

/// The 48-byte ADS stream struct (offsets recovered from the machine
/// code; the layout test below pins them on the 32-bit target — on a
/// 64-bit host the pointer fields widen and all access is by name).
///
/// | off  | field            | evidence |
/// |------|------------------|----------|
/// | 0x00 | `count`          | read/stored only when `FLAG_STRING_MODE` is clear |
/// | 0x04 | `ptr`            | bulk-copy source, advanced by bytes copied |
/// | 0x08 | (unused here)    | |
/// | 0x0c | `flags`          | all flag tests |
/// | 0x10 | `base`           | after a refill, `base[0]` = last byte delivered |
/// | 0x14 | `handle`         | semihosting handle, consumed by the refill helper |
/// | 0x18 | `offset_end`     | refill offset bookkeeping (`= base_off + n - 1`) |
/// | 0x1c | `bulk_threshold` | gates bulk refill vs per-char reads |
/// | 0x20 | (unused here)    | |
/// | 0x24 | (unused here)    | |
/// | 0x28 | `alt_offset`     | offset base when `FLAG_ALT_OFFSET` is set |
/// | 0x2c | `lim`            | string-mode limit pointer |
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AdsStream {
    /// Buffered bytes remaining (normal files); may go negative for
    /// ungetc pushback. Unused in string mode.
    pub count: i32,
    /// Current read pointer.
    pub ptr: *mut u8,
    /// Not touched by these two functions.
    pub field_08: u32,
    /// Flag word (see the `FLAG_*` constants).
    pub flags: u32,
    /// Buffer base; after a direct refill, `base[0]` holds the last byte.
    pub base: *mut u8,
    /// File handle for the refill helper (Angel `SYS_READ`).
    pub handle: i32,
    /// Offset bookkeeping, updated on refill.
    pub offset_end: i32,
    /// When `>=` the byte count wanted, `fread` stays on the per-char
    /// path; below it, bulk refills are allowed once requested.
    pub bulk_threshold: i32,
    /// Not touched by these two functions.
    pub field_20: u32,
    /// Not touched by these two functions.
    pub field_24: u32,
    /// Alternate refill offset base (`FLAG_ALT_OFFSET`).
    pub alt_offset: i32,
    /// String-mode limit pointer; `min(0, ptr - lim)` is the string-mode
    /// "bytes remaining" value.
    pub lim: *mut u8,
}

/// getc helper (`FUN_08034fec`): returns the next char (0..=255), -1 on
/// EOF, or -2 when `FLAG_BULK_WANTED` was set and it wants the caller to
/// do a bulk refill instead. The second argument is 0 at both call sites
/// in the originals.
pub type StreamGetcFn = unsafe extern "C" fn(stream: *mut AdsStream, mode: i32) -> i32;

/// Refill helper (`FUN_08034f88`): reads up to `len` bytes straight into
/// `dest` from the stream's underlying handle. Returns the byte count
/// (0 = EOF), or -1 on error.
pub type StreamRefillFn = unsafe extern "C" fn(dest: *mut u8, len: i32, stream: *mut AdsStream) -> i32;

/// Default getc stand-in: always reports EOF (the real helper,
/// `FUN_08034fec`, is a later port).
unsafe extern "C" fn stream_getc_stub(_stream: *mut AdsStream, _mode: i32) -> i32 {
    -1
}

/// Default refill stand-in: always reports the error/EOF result -1 (the
/// real helper, `FUN_08034f88`, is a later port).
unsafe extern "C" fn stream_refill_stub(_dest: *mut u8, _len: i32, _stream: *mut AdsStream) -> i32 {
    -1
}

/// getc entry used by both readers; swap in the real `FUN_08034fec`
/// port when it lands. Defaults to [`stream_getc_stub`].
#[no_mangle]
pub static mut STREAM_GETC: StreamGetcFn = stream_getc_stub;

/// Refill entry used by `fread`; swap in the real `FUN_08034f88` port
/// when it lands. Defaults to [`stream_refill_stub`].
#[no_mangle]
pub static mut STREAM_REFILL: StreamRefillFn = stream_refill_stub;

/// Buffered bytes available for the fast copy path, exactly as computed
/// (three times) in the originals: for a normal stream it is the `count`
/// word; in string mode it is `min(0, ptr - lim)` (a negative value
/// encodes pushback/lookahead); any other flag combination yields 0.
/// The originals' `(flags & 0x1000)` sub-branch computes the same value
/// as its fall-through and is collapsed here.
#[inline]
unsafe fn buffered_remaining(stream: *mut AdsStream) -> i32 {
    let s = &*stream;
    if s.flags & FLAG_STRING_MODE == 0 {
        s.count
    } else if s.flags & STRING_MODE_MASK != STRING_MODE_VALUE {
        0
    } else {
        let ptr = s.ptr as usize;
        let lim = s.lim as usize;
        if lim <= ptr {
            0
        } else {
            (ptr as i32).wrapping_sub(lim as i32)
        }
    }
}

/// Non-overlapping byte copy. The originals call the ADS memcpy at
/// 0x22000020 (outside the osos image, via thunk @ 0x08037db0); the
/// copied ranges never overlap, so a plain byte loop is equivalent.
unsafe fn copy_bytes(mut dst: *mut u8, mut src: *const u8, mut len: usize) {
    while len > 0 {
        *dst = *src;
        dst = dst.add(1);
        src = src.add(1);
        len -= 1;
    }
}

/// `fread` — original: `FUN_0803677c` @ 0x0803677c (656 bytes).
///
/// Reads `size * nitems` bytes into `dest`, returning the number of WHOLE
/// items read: `nitems` when the full count was delivered, `done / size`
/// (via [`__rt_udiv`]) when input ran out early. A `size` of 0 returns 0
/// without touching the stream.
///
/// Loop, mirroring the original control flow:
/// - while `buffered_remaining(stream) > 0`: bulk-copy
///   `min(total - done, remaining)` (signed min) out of the buffer.
/// - otherwise, when `bulk_threshold >= total` or no bulk refill has been
///   requested yet: fetch one char via [`STREAM_GETC`]. The
///   [`FLAG_BULK_WANTED`] bit is set around the call exactly when
///   `bulk_threshold < total`; the helper answers -2 to request a bulk
///   refill (sets the "bulk allowed" latch and loops), -1 means EOF.
/// - otherwise: refill up to `total - done` bytes straight into `dest`
///   via [`STREAM_REFILL`]. On a positive count the original updates the
///   offset bookkeeping (`offset_end = offset_base + n - 1`, where
///   `offset_base` is `alt_offset` under [`FLAG_ALT_OFFSET`] or
///   `(ptr + offset_end) - base` otherwise), parks the last delivered
///   byte at `base[0]`, points `ptr`/`lim` at `base + 1` and sets
///   [`FLAG_GOT_REFILL`]. Refill results -1/0, or [`FLAG_ERROR`] after
///   any refill, take the EOF exit.
/// - on every exit out of a normal (non-string-mode) stream the computed
///   `remaining` is stored back into `count`.
#[no_mangle]
pub unsafe extern "C" fn fread(
    mut dest: *mut u8,
    size: i32,
    nitems: i32,
    stream: *mut AdsStream,
) -> i32 {
    if size == 0 {
        return 0;
    }
    let mut remaining = buffered_remaining(stream);
    let total = nitems.wrapping_mul(size);
    let mut done: i32 = 0;
    // Latch: set once the getc helper answered -2 ("do a bulk refill").
    let mut bulk_allowed = false;
    loop {
        if done >= total {
            if (*stream).flags & FLAG_STRING_MODE == 0 {
                (*stream).count = remaining;
            }
            return nitems;
        }
        if remaining > 0 {
            // Fast path: drain the buffer (signed minimum, `movlt`).
            let mut chunk = remaining;
            if total - done < chunk {
                chunk = total - done;
            }
            copy_bytes(dest, (*stream).ptr, chunk as usize);
            remaining -= chunk;
            dest = dest.add(chunk as usize);
            done += chunk;
            (*stream).ptr = (*stream).ptr.add(chunk as usize);
            continue;
        }
        if (*stream).bulk_threshold < total && bulk_allowed {
            // Bulk refill straight into the user's buffer.
            let offset_base = if (*stream).flags & FLAG_ALT_OFFSET != 0 {
                (*stream).alt_offset
            } else {
                ((*stream).ptr as i32)
                    .wrapping_add((*stream).offset_end)
                    .wrapping_sub((*stream).base as i32)
            };
            let n = STREAM_REFILL(dest, total - done, stream);
            if n > 0 {
                (*stream).offset_end = offset_base + n - 1;
                let last = *dest.add((n - 1) as usize);
                dest = dest.add(n as usize);
                done += n;
                remaining = 0;
                *(*stream).base = last;
                let base_next = (*stream).base.add(1);
                (*stream).lim = base_next;
                (*stream).ptr = base_next;
                (*stream).flags |= FLAG_GOT_REFILL;
            }
            if n == -1 || n == 0 {
                break;
            }
            if (*stream).flags & FLAG_ERROR != 0 {
                break;
            }
            continue;
        }
        // Per-char path.
        if (*stream).bulk_threshold < total {
            (*stream).flags |= FLAG_BULK_WANTED;
        }
        let c = STREAM_GETC(stream, 0);
        (*stream).flags &= !FLAG_BULK_WANTED;
        if c == -1 {
            break;
        }
        if c != -2 {
            remaining = buffered_remaining(stream);
            if c >= 0 {
                *dest = c as u8;
                dest = dest.add(1);
                done += 1;
                continue;
            }
        }
        // c == -2 (bulk refill requested) or an unreachable negative
        // other than -1/-2: latch and loop, as the original does.
        bulk_allowed = true;
    }
    // EOF exit: store the leftover count back, return whole items.
    if (*stream).flags & FLAG_STRING_MODE == 0 {
        (*stream).count = remaining;
    }
    __rt_udiv(done as u32, size as u32) as i32
}

/// `stream_read_chars` — original: `FUN_08036a10` @ 0x08036a10 (360 bytes).
///
/// Reads up to `n` bytes into `dest` and returns how many were stored.
/// If the buffer holds data (`buffered_remaining > 0`), only the bulk
/// copy runs: `min_u(n, remaining)` bytes from `ptr`. Otherwise one char
/// is fetched via [`STREAM_GETC`] (-1 = EOF, returns 0 — any other value,
/// including -2, is stored as a byte), `remaining` is recomputed, and
/// `min_u(n - 1, remaining)` more bytes are bulk-copied. The minimum is
/// UNSIGNED (`movcc`) in the original: a negative `remaining` (string
/// mode) compares as huge, so all `n - 1` bytes are copied from `ptr`
/// regardless. After the copy, `ptr` advances and — for non-string-mode
/// streams only — `count` becomes `remaining - copied` (mod 2^32).
#[no_mangle]
pub unsafe extern "C" fn stream_read_chars(
    mut dest: *mut u8,
    n: i32,
    stream: *mut AdsStream,
) -> i32 {
    let mut stored: i32 = 0;
    let mut remaining = buffered_remaining(stream);
    if remaining <= 0 {
        let c = STREAM_GETC(stream, 0);
        if c == -1 {
            return 0;
        }
        remaining = buffered_remaining(stream);
        stored = 1;
        *dest = c as u8;
        dest = dest.add(1);
    }
    // Unsigned minimum (`movcc`), bit-exact with the original.
    let left = n.wrapping_sub(stored) as u32;
    let mut chunk = remaining as u32;
    if left < chunk {
        chunk = left;
    }
    copy_bytes(dest, (*stream).ptr, chunk as usize);
    (*stream).ptr = (*stream).ptr.add(chunk as usize);
    if (*stream).flags & FLAG_STRING_MODE == 0 {
        (*stream).count = (remaining as u32).wrapping_sub(chunk) as i32;
    }
    stored.wrapping_add(chunk as i32)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::Mutex;
    use std::vec::Vec;

    /// Serializes tests that swap STREAM_GETC / STREAM_REFILL.
    static HOOK_LOCK: Mutex<()> = Mutex::new(());

    fn hook_lock() -> std::sync::MutexGuard<'static, ()> {
        HOOK_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn reset_hooks() {
        unsafe {
            STREAM_GETC = stream_getc_stub;
            STREAM_REFILL = stream_refill_stub;
        }
    }

    fn stream_for(buf: &mut [u8], count: i32) -> AdsStream {
        AdsStream {
            count,
            ptr: buf.as_mut_ptr(),
            field_08: 0,
            flags: 0,
            base: buf.as_mut_ptr(),
            handle: 0,
            offset_end: 0,
            bulk_threshold: 0,
            field_20: 0,
            field_24: 0,
            alt_offset: 0,
            lim: buf.as_mut_ptr(),
        }
    }

    // --- scripted getc/refill hooks -------------------------------------

    static mut GETC_SCRIPT: Vec<i32> = Vec::new();
    /// flags word observed at each getc call.
    static mut GETC_FLAGS: Vec<u32> = Vec::new();

    unsafe extern "C" fn scripted_getc(stream: *mut AdsStream, _mode: i32) -> i32 {
        GETC_FLAGS.push((*stream).flags);
        if GETC_SCRIPT.is_empty() {
            -1
        } else {
            GETC_SCRIPT.remove(0)
        }
    }

    static mut GETC_CHUNKS: Vec<Vec<u8>> = Vec::new();

    /// Emulates the real getc helper's refill contract: writes the next
    /// scripted chunk into the buffer, sets `count = len - 1` and
    /// `ptr = base + 1`, and returns the first byte. EOF when the script
    /// runs out (count forced to 0, as a drained buffer would be).
    unsafe extern "C" fn chunk_refill_getc(stream: *mut AdsStream, _mode: i32) -> i32 {
        GETC_FLAGS.push((*stream).flags);
        if GETC_CHUNKS.is_empty() {
            (*stream).count = 0;
            return -1;
        }
        let chunk = GETC_CHUNKS.remove(0);
        core::ptr::copy_nonoverlapping(chunk.as_ptr(), (*stream).base, chunk.len());
        (*stream).count = chunk.len() as i32 - 1;
        (*stream).ptr = (*stream).base.add(1);
        chunk[0] as i32
    }

    static mut REFILL_SCRIPT: Vec<(i32, u8)> = Vec::new();
    static mut REFILL_LENS: Vec<i32> = Vec::new();

    /// Each script entry: (count, fill byte). count < 0 is returned
    /// untouched (error/EOF injection); otherwise `count` copies of the
    /// fill byte are written to dest and `count` returned.
    unsafe extern "C" fn scripted_refill(dest: *mut u8, len: i32, _s: *mut AdsStream) -> i32 {
        REFILL_LENS.push(len);
        if REFILL_SCRIPT.is_empty() {
            return -1;
        }
        let (count, fill) = REFILL_SCRIPT.remove(0);
        if count < 0 {
            return count;
        }
        assert!(count <= len, "test refill overruns the offered length");
        for i in 0..count as isize {
            *dest.offset(i) = fill;
        }
        count
    }

    // --- fread ----------------------------------------------------------

    #[test]
    fn fread_size_zero_returns_zero_and_touches_nothing() {
        let mut buf = *b"abcdefgh";
        let mut s = stream_for(&mut buf, 8);
        let mut dest = [0u8; 8];
        unsafe {
            assert_eq!(fread(dest.as_mut_ptr(), 0, 5, &mut s), 0);
            assert_eq!(s.count, 8);
            assert_eq!(s.ptr, buf.as_mut_ptr());
            assert_eq!(dest, [0u8; 8]);
        }
    }

    #[test]
    fn fread_nitems_zero_returns_zero() {
        let mut buf = *b"abcdefgh";
        let mut s = stream_for(&mut buf, 8);
        let mut dest = [0u8; 8];
        unsafe {
            assert_eq!(fread(dest.as_mut_ptr(), 4, 0, &mut s), 0);
            // count is stored back (unchanged) on the completion exit.
            assert_eq!(s.count, 8);
        }
    }

    #[test]
    fn fread_served_entirely_from_buffer() {
        let _guard = hook_lock();
        reset_hooks();
        let mut buf = *b"abcdefgh";
        let mut s = stream_for(&mut buf, 8);
        let mut dest = [0u8; 8];
        unsafe {
            assert_eq!(fread(dest.as_mut_ptr(), 1, 5, &mut s), 5);
            assert_eq!(&dest[..5], b"abcde");
            assert_eq!(s.count, 3, "leftover stored back on completion");
            assert_eq!(s.ptr, buf.as_mut_ptr().add(5));
        }
    }

    #[test]
    fn fread_items_rounding_on_early_eof() {
        let _guard = hook_lock();
        reset_hooks();
        unsafe {
            STREAM_GETC = chunk_refill_getc;
            GETC_CHUNKS = std::vec![b"defg".to_vec(), b"hijk".to_vec()];
            GETC_FLAGS = Vec::new();
        }
        let mut buf = *b"abc_____";
        let mut s = stream_for(&mut buf, 3);
        s.bulk_threshold = 100; // stay on the per-char path
        let mut dest = [0u8; 16];
        unsafe {
            // total = 4*3 = 12; buffer gives "abc", then two refilled
            // chunks give "defghijk" (11 bytes), then EOF.
            assert_eq!(fread(dest.as_mut_ptr(), 4, 3, &mut s), 2, "11 bytes = 2 whole items");
            assert_eq!(&dest[..11], b"abcdefghijk");
            assert_eq!(s.count, 0);
            // bulk_threshold (100) >= total (12): FLAG_BULK_WANTED never set.
            assert!(GETC_FLAGS.iter().all(|f| f & FLAG_BULK_WANTED == 0));
        }
        reset_hooks();
    }

    #[test]
    fn fread_marks_bulk_wanted_around_getc() {
        let _guard = hook_lock();
        reset_hooks();
        unsafe {
            STREAM_GETC = scripted_getc;
            GETC_SCRIPT = std::vec![b'x' as i32, -1];
            GETC_FLAGS = Vec::new();
        }
        let mut buf = *b"________";
        let mut s = stream_for(&mut buf, 0);
        s.bulk_threshold = 0; // below total: mark set around getc
        let mut dest = [0u8; 8];
        unsafe {
            assert_eq!(fread(dest.as_mut_ptr(), 1, 4, &mut s), 1);
            assert_eq!(dest[0], b'x');
            assert_eq!(GETC_FLAGS.len(), 2);
            assert!(
                GETC_FLAGS.iter().all(|f| f & FLAG_BULK_WANTED != 0),
                "FLAG_BULK_WANTED set around every getc call"
            );
            assert_eq!(s.flags & FLAG_BULK_WANTED, 0, "cleared afterwards");
        }
        reset_hooks();
    }

    #[test]
    fn fread_bulk_refill_path() {
        let _guard = hook_lock();
        reset_hooks();
        unsafe {
            STREAM_GETC = scripted_getc;
            STREAM_REFILL = scripted_refill;
            // getc sees FLAG_BULK_WANTED and asks for a refill (-2).
            GETC_SCRIPT = std::vec![-2];
            GETC_FLAGS = Vec::new();
            REFILL_SCRIPT = std::vec![(6, b'Z'), (0, 0)];
            REFILL_LENS = Vec::new();
        }
        let mut backing = *b"________";
        let mut s = stream_for(&mut backing, 0);
        s.bulk_threshold = 0; // < total: refill allowed once requested
        s.offset_end = 5;
        let mut dest = [0u8; 16];
        unsafe {
            // total = 10: getc -> -2, refill delivers 6, next refill EOFs.
            assert_eq!(fread(dest.as_mut_ptr(), 2, 5, &mut s), 3, "6 bytes = 3 items");
            assert_eq!(&dest[..6], b"ZZZZZZ");
            assert_eq!(REFILL_LENS, std::vec![10, 4]);
            // Offset bookkeeping: base_off = (ptr + offset_end) - base = 5,
            // then offset_end = 5 + 6 - 1.
            assert_eq!(s.offset_end, 10);
            // Last delivered byte parked at base[0]; ptr/lim -> base + 1.
            assert_eq!(backing[0], b'Z');
            assert_eq!(s.ptr, backing.as_mut_ptr().add(1));
            assert_eq!(s.lim, backing.as_mut_ptr().add(1));
            assert!(s.flags & FLAG_GOT_REFILL != 0);
        }
        reset_hooks();
    }

    #[test]
    fn fread_refill_uses_alt_offset_when_flag_set() {
        let _guard = hook_lock();
        reset_hooks();
        unsafe {
            STREAM_GETC = scripted_getc;
            STREAM_REFILL = scripted_refill;
            GETC_SCRIPT = std::vec![-2];
            GETC_FLAGS = Vec::new();
            REFILL_SCRIPT = std::vec![(3, b'q'), (0, 0)];
            REFILL_LENS = Vec::new();
        }
        let mut backing = *b"________";
        let mut s = stream_for(&mut backing, 0);
        s.flags = FLAG_ALT_OFFSET;
        s.alt_offset = 42;
        s.offset_end = 7; // must be ignored: alt_offset wins
        s.bulk_threshold = 0;
        let mut dest = [0u8; 8];
        unsafe {
            assert_eq!(fread(dest.as_mut_ptr(), 1, 4, &mut s), 3);
            assert_eq!(&dest[..3], b"qqq");
            assert_eq!(s.offset_end, 42 + 3 - 1);
        }
        reset_hooks();
    }

    #[test]
    fn fread_error_flag_after_refill_forces_eof() {
        let _guard = hook_lock();
        reset_hooks();
        unsafe {
            STREAM_GETC = scripted_getc;
            STREAM_REFILL = scripted_refill;
            GETC_SCRIPT = std::vec![-2];
            GETC_FLAGS = Vec::new();
            REFILL_SCRIPT = std::vec![(2, b'e')];
            REFILL_LENS = Vec::new();
        }
        let mut backing = *b"________";
        let mut s = stream_for(&mut backing, 0);
        s.flags = FLAG_ERROR;
        s.bulk_threshold = 0;
        let mut dest = [0u8; 8];
        unsafe {
            // Refill delivered 2 bytes but FLAG_ERROR stops the loop.
            assert_eq!(fread(dest.as_mut_ptr(), 1, 9, &mut s), 2);
            assert_eq!(&dest[..2], b"ee");
        }
        reset_hooks();
    }

    #[test]
    fn fread_refill_error_result_is_eof() {
        let _guard = hook_lock();
        reset_hooks();
        unsafe {
            STREAM_GETC = scripted_getc;
            STREAM_REFILL = scripted_refill;
            GETC_SCRIPT = std::vec![-2];
            GETC_FLAGS = Vec::new();
            REFILL_SCRIPT = std::vec![(-1, 0)];
            REFILL_LENS = Vec::new();
        }
        let mut backing = *b"________";
        let mut s = stream_for(&mut backing, 0);
        s.bulk_threshold = 0;
        let mut dest = [0u8; 8];
        unsafe {
            assert_eq!(fread(dest.as_mut_ptr(), 1, 9, &mut s), 0);
            assert_eq!(s.count, 0, "count stored back on the EOF exit");
        }
        reset_hooks();
    }

    #[test]
    fn fread_string_mode_uses_getc_and_never_touches_count() {
        let _guard = hook_lock();
        reset_hooks();
        unsafe {
            STREAM_GETC = scripted_getc;
            GETC_SCRIPT = std::vec![b'h' as i32, b'i' as i32, -1];
            GETC_FLAGS = Vec::new();
        }
        let mut backing = *b"........";
        let mut s = stream_for(&mut backing, 99);
        // String mode, readable state: lim > ptr -> remaining negative.
        s.flags = FLAG_STRING_MODE | STRING_MODE_VALUE;
        s.ptr = unsafe { backing.as_mut_ptr().add(1) };
        s.lim = unsafe { backing.as_mut_ptr().add(4) };
        s.bulk_threshold = 100; // per-char path
        let mut dest = [0u8; 8];
        unsafe {
            assert!(s.flags & STRING_MODE_MASK == STRING_MODE_VALUE);
            assert_eq!(fread(dest.as_mut_ptr(), 1, 5, &mut s), 2);
            assert_eq!(&dest[..2], b"hi");
            assert_eq!(s.count, 99, "count word untouched in string mode");
        }
        reset_hooks();
    }

    #[test]
    fn fread_unrecognized_string_mode_state_reads_via_getc() {
        let _guard = hook_lock();
        reset_hooks();
        unsafe {
            STREAM_GETC = scripted_getc;
            GETC_SCRIPT = std::vec![b'k' as i32, -1];
            GETC_FLAGS = Vec::new();
        }
        let mut backing = *b"........";
        let mut s = stream_for(&mut backing, 77);
        // FLAG_STRING_MODE set but masked flags != STRING_MODE_VALUE.
        s.flags = FLAG_STRING_MODE;
        s.bulk_threshold = 100;
        let mut dest = [0u8; 8];
        unsafe {
            assert_eq!(fread(dest.as_mut_ptr(), 1, 3, &mut s), 1);
            assert_eq!(dest[0], b'k');
            assert_eq!(s.count, 77, "count never stored in string mode");
        }
        reset_hooks();
    }

    #[test]
    fn fread_default_hooks_hit_eof_immediately() {
        let _guard = hook_lock();
        reset_hooks();
        let mut backing = *b"________";
        let mut s = stream_for(&mut backing, 0);
        s.bulk_threshold = 0;
        let mut dest = [0u8; 8];
        unsafe {
            assert_eq!(fread(dest.as_mut_ptr(), 1, 4, &mut s), 0);
        }
    }

    // --- stream_read_chars ----------------------------------------------

    #[test]
    fn read_chars_fast_path_copies_from_buffer() {
        let mut buf = *b"abcdefgh";
        let mut s = stream_for(&mut buf, 8);
        let mut dest = [0u8; 8];
        unsafe {
            assert_eq!(stream_read_chars(dest.as_mut_ptr(), 5, &mut s), 5);
            assert_eq!(&dest[..5], b"abcde");
            assert_eq!(s.count, 3);
            assert_eq!(s.ptr, buf.as_mut_ptr().add(5));
        }
    }

    #[test]
    fn read_chars_capped_by_buffer_contents() {
        let mut buf = *b"abc";
        let mut s = stream_for(&mut buf, 3);
        let mut dest = [0u8; 8];
        unsafe {
            assert_eq!(stream_read_chars(dest.as_mut_ptr(), 10, &mut s), 3);
            assert_eq!(&dest[..3], b"abc");
            assert_eq!(s.count, 0);
        }
    }

    #[test]
    fn read_chars_eof_on_empty_buffer_returns_zero() {
        let _guard = hook_lock();
        reset_hooks(); // default getc stub answers -1
        let mut buf = *b"________";
        let mut s = stream_for(&mut buf, 0);
        let mut dest = [0u8; 8];
        unsafe {
            assert_eq!(stream_read_chars(dest.as_mut_ptr(), 5, &mut s), 0);
        }
    }

    #[test]
    fn read_chars_getc_then_bulk_copy() {
        let _guard = hook_lock();
        reset_hooks();
        // Buffer "empty" (count 0); the getc simulates a refill by
        // bumping count before returning the first char.
        unsafe extern "C" fn refilling_getc(stream: *mut AdsStream, _mode: i32) -> i32 {
            (*stream).count = 3;
            b'A' as i32
        }
        let mut buf = *b"BCD_____";
        let mut s = stream_for(&mut buf, 0);
        let mut dest = [0u8; 8];
        unsafe {
            STREAM_GETC = refilling_getc;
            assert_eq!(stream_read_chars(dest.as_mut_ptr(), 4, &mut s), 4);
            assert_eq!(&dest[..4], b"ABCD");
            assert_eq!(s.count, 0, "3 - 3 copied after the getc char");
            assert_eq!(s.ptr, buf.as_mut_ptr().add(3));
        }
        reset_hooks();
    }

    #[test]
    fn read_chars_single_byte_request() {
        let mut buf = *b"abcdefgh";
        let mut s = stream_for(&mut buf, 8);
        let mut dest = [0u8; 8];
        unsafe {
            assert_eq!(stream_read_chars(dest.as_mut_ptr(), 1, &mut s), 1);
            assert_eq!(dest[0], b'a');
            assert_eq!(s.count, 7);
        }
    }

    #[test]
    fn read_chars_getc_result_minus_two_is_stored_as_a_byte() {
        let _guard = hook_lock();
        reset_hooks();
        unsafe {
            STREAM_GETC = scripted_getc;
            GETC_SCRIPT = std::vec![-2];
            GETC_FLAGS = Vec::new();
        }
        let mut buf = *b"xyz_____";
        let mut s = stream_for(&mut buf, 0);
        let mut dest = [0u8; 8];
        unsafe {
            // -2 is not EOF here: stored as 0xfe, then min_u(n-1, count)
            // bulk-copies from the buffer (count still 0 -> nothing more).
            assert_eq!(stream_read_chars(dest.as_mut_ptr(), 3, &mut s), 1);
            assert_eq!(dest[0], 0xfe);
        }
        reset_hooks();
    }

    #[test]
    fn read_chars_string_mode_unsigned_min_copies_n_minus_one() {
        let _guard = hook_lock();
        reset_hooks();
        unsafe {
            STREAM_GETC = scripted_getc;
            GETC_SCRIPT = std::vec![b'S' as i32];
            GETC_FLAGS = Vec::new();
        }
        let mut backing = *b"abcdefgh";
        let mut s = stream_for(&mut backing, 1234);
        // String mode, readable state, lim > ptr: remaining is negative,
        // so the UNSIGNED minimum picks n - 1 and the port (like the
        // original) copies that many bytes from ptr regardless.
        s.flags = FLAG_STRING_MODE | STRING_MODE_VALUE;
        s.ptr = unsafe { backing.as_mut_ptr().add(1) };
        s.lim = unsafe { backing.as_mut_ptr().add(5) };
        let mut dest = [0u8; 8];
        unsafe {
            assert_eq!(stream_read_chars(dest.as_mut_ptr(), 4, &mut s), 4);
            assert_eq!(&dest[..4], b"Sbcd");
            assert_eq!(s.ptr, backing.as_mut_ptr().add(4));
            assert_eq!(s.count, 1234, "count untouched in string mode");
        }
        reset_hooks();
    }

    #[test]
    fn read_chars_whitespace_and_nul_bytes_are_plain_data() {
        // These are raw byte readers: no whitespace skipping, no NUL
        // special-casing, no NUL padding of short reads.
        let mut buf = *b" \t\n\0xy__";
        let mut s = stream_for(&mut buf, 6);
        let mut dest = [0xaa; 8];
        unsafe {
            assert_eq!(stream_read_chars(dest.as_mut_ptr(), 6, &mut s), 6);
            assert_eq!(&dest[..6], b" \t\n\0xy");
            assert_eq!(dest[6], 0xaa, "no NUL padding past the read");
            assert_eq!(dest[7], 0xaa);
        }
    }

    /// Raw offsets only hold on the 32-bit ARM target; on 64-bit hosts
    /// the pointer fields widen. Functional behavior is host-testable
    /// either way since all access goes through named fields.
    #[test]
    #[cfg(target_pointer_width = "32")]
    fn struct_layout_matches_original() {
        assert_eq!(core::mem::size_of::<AdsStream>(), 0x30);
        assert_eq!(core::mem::offset_of!(AdsStream, count), 0x00);
        assert_eq!(core::mem::offset_of!(AdsStream, ptr), 0x04);
        assert_eq!(core::mem::offset_of!(AdsStream, field_08), 0x08);
        assert_eq!(core::mem::offset_of!(AdsStream, flags), 0x0c);
        assert_eq!(core::mem::offset_of!(AdsStream, base), 0x10);
        assert_eq!(core::mem::offset_of!(AdsStream, handle), 0x14);
        assert_eq!(core::mem::offset_of!(AdsStream, offset_end), 0x18);
        assert_eq!(core::mem::offset_of!(AdsStream, bulk_threshold), 0x1c);
        assert_eq!(core::mem::offset_of!(AdsStream, field_20), 0x20);
        assert_eq!(core::mem::offset_of!(AdsStream, field_24), 0x24);
        assert_eq!(core::mem::offset_of!(AdsStream, alt_offset), 0x28);
        assert_eq!(core::mem::offset_of!(AdsStream, lim), 0x2c);
    }
}
