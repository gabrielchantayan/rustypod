//! Ports of the small ADS stdio stream-flag accessors that sit apart from
//! the buffered-read cluster (fread.rs) in the ADS library region:
//!
//! - `stream_clear_error` — original: `FUN_080333c8` @ 0x080333c8
//!   (48 bytes). The `clearerr` core: clears flag bits 0x4000 | 0xc0 in
//!   the +0x0c flag word (both stream indicators — EOF and error — plus
//!   the sticky 0x4000 state bit).
//! - `stream_test_error_flag` — original: `FUN_080333f8` @ 0x080333f8
//!   (44 bytes). The `ferror` core: returns `flags & 0x80`.
//!   CORRECTION of the names.yaml scouting name (`stream_test_eof_flag`):
//!   0x80 is the ERROR indicator — it is set by
//!   `stdio_stream_error_reset` @ 0x08030004 on the buffered-WRITE
//!   failure path, and the printf front-end @ 0x0802f694 turns its result
//!   into the EOF return of a failed printf. (The EOF indicator is the
//!   0x40 bit also cleared above.)
//! - `setvbuf_core` — original: `FUN_08033424` @ 0x08033424 (164 bytes).
//!   The `setvbuf` engine — see the function docs for the exact
//!   validation and stored fields.
//!
//! All three originals bracket their body with the ADS re-entrancy hooks
//! on the per-stream lock at FILE+0x3c (`mov r0, lock; mov r0, r0` — the
//! `bl _mutex_acquire/_mutex_release` pairs are linked out to nops in
//! retailOS). The only machine-visible residue is that
//! `stream_clear_error` returns the lock address in r0 (the release
//! argument); the port reproduces that artifact.
//!
//! The stream layout is [`AdsStream`] (stdio/fread.rs) — the 48-byte ADS
//! stream struct; the lock word at +0x3c lives past it, inside the
//! 0x88-byte FILE allocation (`stdio_stream_alloc` @ 0x08035924), so it
//! is addressed by raw byte offset (device layout; on the host the offset
//! is computed but never dereferenced).

use crate::stdio::fread::AdsStream;

/// Error indicator (`ferror`): set by `stdio_stream_error_reset`
/// @ 0x08030004 when a buffered write fails.
pub const FLAG_STREAM_ERROR: u32 = 0x80;

/// EOF indicator (`feof` family): cleared together with the error bit by
/// `clearerr`.
pub const FLAG_STREAM_EOF: u32 = 0x40;

/// Sticky stream-state bit also cleared by `clearerr` (exact producer not
/// yet identified; distinct from the 0x400000 "buffer touched" bit).
pub const FLAG_STREAM_STICKY: u32 = 0x4000;

/// Byte offset of the per-stream re-entrancy lock inside the 0x88-byte
/// FILE allocation (past the 48-byte AdsStream prefix).
const STREAM_LOCK_OFFSET: usize = 0x3c;

/// Buffer-mode field inside the flag word: 0x100 full / 0x200 line /
/// 0x400 none, replaced wholesale by `setvbuf_core` (`bic #0xf00`).
const FLAG_BUFFER_MODE_MASK: u32 = 0xf00;

/// "Stream has been used/buffer committed" bit: once set, `setvbuf` is
/// refused (ISO C: setvbuf only before the first I/O operation).
const FLAG_BUFFER_COMMITTED: u32 = 0x400000;

/// Open-mode bits (read 0x1 / write 0x2): at least one must be set for
/// the stream to accept a setvbuf.
const FLAG_OPEN_MASK: u32 = 0x3;

/// The per-stream lock address at FILE+0x3c (see module docs).
#[inline(always)]
fn stream_lock_addr(stream: *mut AdsStream) -> *mut u8 {
    (stream as *mut u8).wrapping_add(STREAM_LOCK_OFFSET)
}

/// stream_clear_error — original: `FUN_080333c8` @ 0x080333c8 (48 bytes).
///
/// `clearerr` core: clears the EOF (0x40) and error (0x80) indicators and
/// the sticky 0x4000 bit (`bic #0x4000; bic #0xc0`). Returns the lock
/// address FILE+0x3c — an artifact of the nop'd unlock hook whose
/// argument the original leaves in r0.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn stream_clear_error(stream: *mut AdsStream) -> *mut u8 {
    (*stream).flags &= !(FLAG_STREAM_STICKY | FLAG_STREAM_ERROR | FLAG_STREAM_EOF);
    stream_lock_addr(stream)
}

/// stream_test_error_flag — original: `FUN_080333f8` @ 0x080333f8
/// (44 bytes).
///
/// `ferror` core: returns `flags & 0x80` (0x80 when the error indicator
/// is set, 0 otherwise — the original returns the masked value, not a
/// normalized boolean).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn stream_test_error_flag(stream: *mut AdsStream) -> u32 {
    (*stream).flags & FLAG_STREAM_ERROR
}

/// setvbuf_core — original: `FUN_08033424` @ 0x08033424 (164 bytes).
///
/// The `setvbuf` engine. Fails (returns 1) unless the stream is open
/// (`flags & 3 != 0`) and its buffer is not yet committed
/// (`flags & 0x400000 == 0`). Then:
/// - mode 0x100 (_IOFBF) / 0x200 (_IOLBF): requires `size - 1 < 0xffffff`
///   unsigned (i.e. 1..=0xffffff) and installs the caller's buffer;
/// - mode 0x400 (_IONBF): installs the internal 1-byte buffer at
///   FILE+0x24 with size 1 (the caller's `buf`/`size` are ignored);
/// - any other mode: fail.
///
/// Install stores `buf` to the buffer base (+0x10) AND the read cursor
/// (+0x04), `size` to +0x1c, and replaces the flag word's buffer-mode
/// field (`flags = (flags & ~0xf00) | mode`). Returns 0 on success.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn setvbuf_core(
    stream: *mut AdsStream,
    mut buf: *mut u8,
    mode: u32,
    mut size: u32,
) -> u32 {
    let flags = (*stream).flags;
    if flags & FLAG_OPEN_MASK == 0 || flags & FLAG_BUFFER_COMMITTED != 0 {
        return 1;
    }
    if mode == 0x100 || mode == 0x200 {
        // sub r0, size, #1; mvn r1, #0xff000000; cmp r0, r1; bcc install
        if size.wrapping_sub(1) >= 0x00ff_ffff {
            return 1;
        }
    } else if mode == 0x400 {
        // _IONBF: the internal 1-byte buffer at FILE+0x24.
        buf = core::ptr::addr_of_mut!((*stream).field_24) as *mut u8;
        size = 1;
    } else {
        return 1;
    }
    (*stream).base = buf;
    (*stream).bulk_threshold = size as i32;
    (*stream).ptr = buf;
    (*stream).flags = (flags & !FLAG_BUFFER_MODE_MASK) | mode;
    0
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    /// A zeroed stream with the given flag word.
    fn stream_with_flags(flags: u32) -> AdsStream {
        let mut s: AdsStream = unsafe { core::mem::zeroed() };
        s.flags = flags;
        s
    }

    #[test]
    fn clear_error_clears_exactly_the_three_bits() {
        let mut s = stream_with_flags(0xffff_ffff);
        let ret = unsafe { stream_clear_error(&mut s) };
        assert_eq!(s.flags, 0xffff_ffff & !0x40c0);
        // The artifact return value is the lock address FILE+0x3c.
        assert_eq!(ret as usize, &mut s as *mut AdsStream as usize + 0x3c);
        // Idempotent, and leaves an already-clean word untouched.
        let mut clean = stream_with_flags(0x0000_0303);
        unsafe { stream_clear_error(&mut clean) };
        assert_eq!(clean.flags, 0x0000_0303);
    }

    #[test]
    fn test_error_flag_returns_masked_value() {
        for flags in [0u32, 0x80, 0x40, 0xc0, 0xffff_ffff, 0xffff_ff7f] {
            let mut s = stream_with_flags(flags);
            let got = unsafe { stream_test_error_flag(&mut s) };
            assert_eq!(got, flags & 0x80, "flags={flags:#x}");
            assert_eq!(s.flags, flags, "must not modify the stream");
        }
    }

    #[test]
    fn setvbuf_rejects_closed_or_committed_streams() {
        let mut buf = [0u8; 16];
        for flags in [0u32, 0x400000, 0x400003, 0x400001] {
            let mut s = stream_with_flags(flags);
            let ret = unsafe { setvbuf_core(&mut s, buf.as_mut_ptr(), 0x100, 16) };
            assert_eq!(ret, 1, "flags={flags:#x} must be rejected");
            assert_eq!(s.flags, flags, "no store on the failure path");
            assert!(s.base.is_null());
        }
    }

    #[test]
    fn setvbuf_full_and_line_modes_validate_size() {
        let mut buf = [0u8; 16];
        for mode in [0x100u32, 0x200] {
            // Valid sizes: 1..=0xffffff.
            for size in [1u32, 16, 0xffffff] {
                let mut s = stream_with_flags(0x3 | 0xf00);
                let ret = unsafe { setvbuf_core(&mut s, buf.as_mut_ptr(), mode, size) };
                assert_eq!(ret, 0, "mode={mode:#x} size={size:#x}");
                assert_eq!(s.base, buf.as_mut_ptr());
                assert_eq!(s.ptr, buf.as_mut_ptr());
                assert_eq!(s.bulk_threshold, size as i32);
                // Mode field replaced, open bits preserved.
                assert_eq!(s.flags, 0x3 | mode);
            }
            // Invalid sizes: 0 and 0x1000000 up.
            for size in [0u32, 0x1000000, u32::MAX] {
                let mut s = stream_with_flags(0x3);
                let ret = unsafe { setvbuf_core(&mut s, buf.as_mut_ptr(), mode, size) };
                assert_eq!(ret, 1, "mode={mode:#x} size={size:#x} must fail");
            }
        }
    }

    #[test]
    fn setvbuf_nobuf_mode_uses_internal_byte() {
        let mut s = stream_with_flags(0x1 | 0x200);
        // buf/size arguments are ignored in _IONBF mode.
        let ret = unsafe { setvbuf_core(&mut s, core::ptr::null_mut(), 0x400, 0) };
        assert_eq!(ret, 0);
        let internal = core::ptr::addr_of_mut!(s.field_24) as *mut u8;
        assert_eq!(s.base, internal, "buffer must be the internal FILE+0x24 byte");
        assert_eq!(s.ptr, internal);
        assert_eq!(s.bulk_threshold, 1);
        assert_eq!(s.flags, 0x1 | 0x400);
    }

    #[test]
    fn setvbuf_rejects_unknown_modes() {
        let mut buf = [0u8; 16];
        for mode in [0u32, 0x300, 0x800, 0x700, 1, 0x10000] {
            let mut s = stream_with_flags(0x3);
            let ret = unsafe { setvbuf_core(&mut s, buf.as_mut_ptr(), mode, 16) };
            assert_eq!(ret, 1, "mode={mode:#x} must be rejected");
        }
    }
}
