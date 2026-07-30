//! The retailOS line-buffer putc:
//!
//! - `linebuf_putc` @ 0x082cf2c8 (88 bytes) — the character sink behind
//!   [`super::fwrite::stream_write_block`] (its sole caller in the image,
//!   binary-verified `bl` scan: the `bl 0x082cf2c8` @ 0x0802ffd8). Not
//!   the ADS buffered-stream layer: a standalone debug-console line
//!   buffer. A null context (`ctx == 0`) answers -1 without touching
//!   any state. Otherwise the position counter is incremented FIRST,
//!   the low byte of `c` is stored at the OLD position, and the line is
//!   flushed — NUL-terminated in place, emitted via Angel semihosting
//!   `swi 0x123456` op 0x04 (SYS_WRITE0, r1 = buffer base, result
//!   ignored), position reset to 0 — when `c == '\n'` (full-word
//!   compare: `c == 0x0000010a` does NOT flush, though it stores 0x0a)
//!   or the new position reaches 0x50 (80 chars, signed `blt` skipped).
//!   Returns `c` verbatim (the full word, not the truncated byte).
//!
//! Globals (modeled as [`LINE_BUF`]/[`LINE_BUF_POS`]):
//! - literal pool @ 0x082cf320 = 0x08a0fc00 — line position counter.
//! - literal pool @ 0x082cf324 = 0x08b31720 — line buffer base; the
//!   deepest write is the NUL at index 0x50, so 0x51 bytes.
//!
//! Register usage: r0 = c, r1 = ctx, r4 = c, r6 = &position,
//! r1 = buffer base.
//!
//! Deviations: the flush goes through the [`super::semihost::SEMIHOST_SWI`]
//! dispatch hook (house pattern) instead of an inlined `swi 0x123456`;
//! on device the SWI is dead anyway (no debugger attached). The two
//! firmware globals are Rust statics rather than fixed addresses.

use super::semihost::{semihost_swi, SYS_WRITE0};

/// Line capacity: the original flushes when the position reaches 0x50.
pub const LINE_BUF_CAPACITY: usize = 0x50;

/// Line buffer (original: BSS @ 0x08b31720). 0x50 data bytes plus the
/// NUL the flush appends at the current position.
#[cfg_attr(target_os = "none", no_mangle)]
pub static mut LINE_BUF: [u8; LINE_BUF_CAPACITY + 1] = [0; LINE_BUF_CAPACITY + 1];

/// Append position within [`LINE_BUF`] (original: word @ 0x08a0fc00).
#[cfg_attr(target_os = "none", no_mangle)]
pub static mut LINE_BUF_POS: i32 = 0;

/// `linebuf_putc` — original: `FUN_082cf2c8` @ 0x082cf2c8 (88 bytes).
///
/// Appends the low byte of `c` to [`LINE_BUF`] at [`LINE_BUF_POS`]
/// (incremented before the store) and flushes the line — NUL-terminate,
/// SYS_WRITE0 semihost SWI, position reset — on `'\n'` or a full
/// 0x50-byte line. Returns `c`; -1 when `ctx` is 0 (no sink attached —
/// the context value is otherwise ignored by the original).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn linebuf_putc(c: i32, ctx: i32) -> i32 {
    if ctx == 0 {
        return -1;
    }
    let pos_ptr = core::ptr::addr_of_mut!(LINE_BUF_POS);
    let buf = core::ptr::addr_of_mut!(LINE_BUF) as *mut u8;
    let pos = *pos_ptr;
    let new_pos = pos.wrapping_add(1);
    *pos_ptr = new_pos;
    // strb: only the low byte lands, indexed by the OLD position.
    *buf.add(pos as usize) = c as u8;
    // `cmp r4,#0xa` / `cmpne r0,#0x50` / `blt`: flush on a newline
    // (full-word compare) or when the new position reaches 0x50.
    if c == 0x0a || new_pos >= LINE_BUF_CAPACITY as i32 {
        *buf.add(new_pos as usize) = 0;
        semihost_swi()(SYS_WRITE0, buf as *const usize);
        *pos_ptr = 0;
    }
    c
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::stdio::semihost::tests::SWI_LOCK;
    use std::string::String;
    use std::sync::MutexGuard;
    use std::vec::Vec;

    /// One recorded flush: (op, NUL-terminated string as issued).
    static mut FLUSH_LOG: Vec<(usize, Vec<u8>)> = Vec::new();

    /// Recording mock for the SWI boundary: captures the op and the
    /// NUL-terminated string r1 points at (SYS_WRITE0 shape).
    unsafe extern "C" fn recording_swi(op: usize, block: *const usize) -> i32 {
        let mut s = Vec::new();
        let mut p = block as *const u8;
        while *p != 0 {
            s.push(*p);
            p = p.add(1);
        }
        (*core::ptr::addr_of_mut!(FLUSH_LOG)).push((op, s));
        -1 // result must be ignored by linebuf_putc
    }

    /// Locks the SWI boundary (shared with the semihost/stream_file
    /// tests), installs the recording mock, and resets the buffer state.
    fn setup() -> MutexGuard<'static, ()> {
        let guard = SWI_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            super::super::semihost::SEMIHOST_SWI = recording_swi;
            (*core::ptr::addr_of_mut!(FLUSH_LOG)).clear();
            (*core::ptr::addr_of_mut!(LINE_BUF)).fill(0);
            *core::ptr::addr_of_mut!(LINE_BUF_POS) = 0;
        }
        guard
    }

    fn flushes() -> Vec<(usize, String)> {
        unsafe {
            (*core::ptr::addr_of!(FLUSH_LOG))
                .iter()
                .map(|(op, s)| (*op, String::from_utf8_lossy(s).into_owned()))
                .collect()
        }
    }

    fn pos() -> i32 {
        unsafe { *core::ptr::addr_of!(LINE_BUF_POS) }
    }

    fn buf_byte(i: usize) -> u8 {
        unsafe { (*core::ptr::addr_of!(LINE_BUF))[i] }
    }

    #[test]
    fn null_ctx_fails_without_touching_state() {
        let _guard = setup();
        unsafe {
            assert_eq!(linebuf_putc(b'a' as i32, 0), -1);
            assert_eq!(linebuf_putc(b'\n' as i32, 0), -1, "newline also gated");
        }
        assert_eq!(pos(), 0, "no append, no flush");
        assert_eq!(buf_byte(0), 0);
        assert!(flushes().is_empty(), "no SWI issued");
    }

    #[test]
    fn plain_bytes_accumulate_and_return_c() {
        let _guard = setup();
        unsafe {
            for &b in b"abc" {
                assert_eq!(linebuf_putc(b as i32, 7), b as i32, "returns c verbatim");
            }
        }
        assert_eq!(pos(), 3);
        assert_eq!(&unsafe { *core::ptr::addr_of!(LINE_BUF) }[..3], b"abc");
        assert!(flushes().is_empty(), "no newline, line not full");
    }

    #[test]
    fn newline_flushes_nul_terminates_and_resets() {
        let _guard = setup();
        unsafe {
            linebuf_putc(b'h' as i32, 1);
            linebuf_putc(b'i' as i32, 1);
            assert_eq!(linebuf_putc(b'\n' as i32, 1), 0x0a, "returns the newline");
        }
        assert_eq!(pos(), 0, "position reset after the flush");
        let f = flushes();
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].0, SYS_WRITE0, "Angel op 0x04");
        assert_eq!(f[0].1, "hi\n", "the newline is part of the flushed line");
        assert_eq!(buf_byte(3), 0, "NUL written at the post-increment position");
        unsafe {
            // The next line starts at the buffer base again.
            linebuf_putc(b'X' as i32, 1);
        }
        assert_eq!(buf_byte(0), b'X');
        assert_eq!(pos(), 1);
    }

    #[test]
    fn full_line_flushes_at_80_bytes_without_a_newline() {
        let _guard = setup();
        unsafe {
            for i in 0..80 {
                assert_eq!(linebuf_putc(b'x' as i32, 1), b'x' as i32, "byte {i}");
            }
        }
        let f = flushes();
        assert_eq!(f.len(), 1, "the 80th byte (new position 0x50) flushes");
        assert_eq!(f[0].0, SYS_WRITE0);
        assert_eq!(f[0].1, "x".repeat(80));
        assert_eq!(buf_byte(80), 0, "NUL at index 0x50");
        assert_eq!(pos(), 0);
        unsafe {
            linebuf_putc(b'y' as i32, 1);
        }
        assert_eq!(buf_byte(0), b'y', "next line restarts at index 0");
        assert_eq!(pos(), 1);
        assert_eq!(flushes().len(), 1, "79-byte lines do not flush");
    }

    #[test]
    fn nul_and_high_bytes_are_plain_data() {
        let _guard = setup();
        unsafe {
            assert_eq!(linebuf_putc(0x00, 1), 0, "NUL returns 0, no special case");
            assert_eq!(linebuf_putc(0xff, 1), 0xff);
            // Full-word newline compare: low byte 0x0a alone does not flush.
            assert_eq!(linebuf_putc(0x10a, 1), 0x10a, "returns the full word");
        }
        assert_eq!(pos(), 3, "0x10a stored as a byte, no flush");
        assert_eq!(buf_byte(0), 0x00);
        assert_eq!(buf_byte(1), 0xff);
        assert_eq!(buf_byte(2), 0x0a, "strb keeps only the low byte");
        assert!(flushes().is_empty());
    }

    #[test]
    fn swi_result_is_ignored() {
        let _guard = setup(); // recording_swi answers -1
        unsafe {
            assert_eq!(linebuf_putc(b'\n' as i32, 1), 0x0a, "still returns c");
        }
        assert_eq!(pos(), 0, "flush completed despite the failing SWI");
        assert_eq!(flushes().len(), 1);
    }
}
