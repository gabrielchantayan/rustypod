//! The ADS stdio-layer block writer from osos, writing through the
//! retailOS line-buffer putc:
//!
//! - `stream_write_block` @ 0x0802ffa8 (92 bytes) — writes `size *
//!   nitems` bytes from `buf` one character at a time through the putc
//!   @ 0x082cf2c8, returning `nitems` when every byte was accepted and
//!   0 on the first putc failure (-1). This is the write-side mirror of
//!   the `fread`/`stream_read_chars` pair in `fread.rs` — same
//!   `(buf, size, nitems, stream-ish)` calling shape — but its sink is
//!   NOT the ADS buffered stream layer: 0x082cf2c8 is the retailOS
//!   line-buffer putc (appends to the line buffer @ 0x08b31720, flushing
//!   via Angel `svc 0x123456` on `'\n'` or a full 0x50-byte line, and
//!   answers -1 when its second argument is 0). The only caller in the
//!   image (binary-verified `bl` scan) is 0x08266c04, inside
//!   `FUN_08266be8`, a retailOS log/formatter helper that reports
//!   `stream_write_block(...) == nitems` as a bool. Register usage:
//!   r0 = buf, r1 = size, r2 = nitems, r3 = putc context.
//!
//! The putc @ 0x082cf2c8 is ported as
//! [`super::linebuf_putc::linebuf_putc`] (it owns the line-buffer global
//! and the semihosting flush); the call still goes through the
//! [`STREAM_WRITE_PUTC`] hook slot, the same house pattern `fread.rs`
//! uses for `STREAM_REFILL`, with the real port as the shipped default.

/// putc sink used by [`stream_write_block`]: the original calls
/// `FUN_082cf2c8 @ 0x082cf2c8(c, ctx)`, which returns the character
/// written, or -1 when `ctx` is 0 (no sink attached).
pub type StreamPutcFn = unsafe extern "C" fn(c: i32, ctx: i32) -> i32;

/// putc entry used by [`stream_write_block`]; tests script it with
/// mocks. Defaults to the ported line-buffer putc @ 0x082cf2c8
/// ([`super::linebuf_putc::linebuf_putc`]), which answers -1 for a null
/// context and otherwise appends to the line buffer.
#[cfg_attr(target_os = "none", no_mangle)]
pub static mut STREAM_WRITE_PUTC: StreamPutcFn = super::linebuf_putc::linebuf_putc;

/// Volatile hook read (keeps runtime swapping alive; house pattern).
#[inline(always)]
unsafe fn hook<T: Copy>(slot: *const T) -> T {
    core::ptr::read_volatile(slot)
}

/// `stream_write_block` — original: `FUN_0802ffa8` @ 0x0802ffa8
/// (92 bytes).
///
/// Writes `size * nitems` bytes from `buf` through [`STREAM_WRITE_PUTC`]
/// (the line-buffer putc @ 0x082cf2c8 in the original), one `putc(byte,
/// ctx)` call per byte, and returns `nitems` once the whole block is
/// accepted. The first putc answering -1 abandons the block and returns
/// 0 — partial-item counts are NOT computed (unlike `fread`, which
/// divides its byte count down on early EOF; the write side is
/// all-or-nothing). A `size` of 0 short-circuits to `nitems` without
/// touching the sink; the product `size * nitems` is the ARM `mul`'s
/// mod-2^32 value and the loop bound compares SIGNED (`blt`), so a
/// nonpositive total writes nothing and still returns `nitems`.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn stream_write_block(
    mut buf: *const u8,
    size: i32,
    nitems: i32,
    ctx: i32,
) -> i32 {
    if size != 0 {
        let total = size.wrapping_mul(nitems);
        let putc = hook(core::ptr::addr_of!(STREAM_WRITE_PUTC));
        let mut written: i32 = 0;
        while written < total {
            let c = *buf;
            buf = buf.add(1);
            if putc(c as i32, ctx) == -1 {
                return 0;
            }
            written += 1;
        }
    }
    nitems
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::Mutex;
    use std::vec::Vec;

    /// Serializes tests that swap STREAM_WRITE_PUTC.
    static HOOK_LOCK: Mutex<()> = Mutex::new(());

    fn hook_lock() -> std::sync::MutexGuard<'static, ()> {
        HOOK_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn reset_hook() {
        unsafe {
            STREAM_WRITE_PUTC = super::super::linebuf_putc::linebuf_putc;
        }
    }

    /// Bytes observed by the scripted putc, in call order.
    static mut PUTC_BYTES: Vec<u8> = Vec::new();
    /// Contexts observed by the scripted putc, in call order.
    static mut PUTC_CTXS: Vec<i32> = Vec::new();
    /// How many calls succeed before the putc starts answering -1.
    static mut PUTC_FAIL_AFTER: i32 = 0;

    unsafe extern "C" fn scripted_putc(c: i32, ctx: i32) -> i32 {
        PUTC_BYTES.push(c as u8);
        PUTC_CTXS.push(ctx);
        if PUTC_BYTES.len() as i32 > PUTC_FAIL_AFTER {
            -1
        } else {
            c
        }
    }

    unsafe fn install_scripted_putc(fail_after: i32) {
        PUTC_BYTES = Vec::new();
        PUTC_CTXS = Vec::new();
        PUTC_FAIL_AFTER = fail_after;
        STREAM_WRITE_PUTC = scripted_putc;
    }

    #[test]
    fn default_hook_is_the_linebuf_putc() {
        let _guard = hook_lock();
        // Serializes against the linebuf_putc tests, which assert on the
        // shared line-buffer state this test writes through.
        let _swi_guard = super::super::semihost::tests::SWI_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        reset_hook();
        unsafe {
            *core::ptr::addr_of_mut!(super::super::linebuf_putc::LINE_BUF_POS) = 0;
        }
        let buf = *b"abc";
        unsafe {
            // Null putc context: the real line putc answers -1.
            assert_eq!(stream_write_block(buf.as_ptr(), 1, 3, 0), 0);
            // Non-null context: the real line putc accepts every byte.
            assert_eq!(stream_write_block(buf.as_ptr(), 1, 3, 1), 3);
            *core::ptr::addr_of_mut!(super::super::linebuf_putc::LINE_BUF_POS) = 0;
        }
        reset_hook();
    }

    #[test]
    fn full_block_writes_every_byte_and_returns_nitems() {
        let _guard = hook_lock();
        unsafe {
            install_scripted_putc(i32::MAX);
            let buf = *b"hello!";
            assert_eq!(stream_write_block(buf.as_ptr(), 2, 3, 42), 3);
            assert_eq!(PUTC_BYTES, b"hello!".to_vec());
            assert_eq!(PUTC_CTXS, std::vec![42; 6], "ctx forwarded verbatim");
        }
        reset_hook();
    }

    #[test]
    fn putc_failure_abandons_the_block_and_returns_zero() {
        let _guard = hook_lock();
        unsafe {
            install_scripted_putc(2); // two bytes accepted, third fails
            let buf = *b"abcdef";
            assert_eq!(stream_write_block(buf.as_ptr(), 1, 6, 0), 0);
            assert_eq!(PUTC_BYTES.len(), 3, "stops at the first failure");
            assert_eq!(PUTC_BYTES, b"abc".to_vec());
        }
        reset_hook();
    }

    #[test]
    fn size_zero_returns_nitems_without_touching_the_sink() {
        let _guard = hook_lock();
        unsafe {
            install_scripted_putc(0); // would fail on the first call
            let buf = *b"abc";
            assert_eq!(stream_write_block(buf.as_ptr(), 0, 9, 1), 9);
            assert!(PUTC_BYTES.is_empty());
        }
        reset_hook();
    }

    #[test]
    fn nitems_zero_writes_nothing_and_returns_zero() {
        let _guard = hook_lock();
        unsafe {
            install_scripted_putc(0);
            let buf = *b"abc";
            assert_eq!(stream_write_block(buf.as_ptr(), 4, 0, 1), 0);
            assert!(PUTC_BYTES.is_empty(), "total = size * 0 = 0 bytes");
        }
        reset_hook();
    }

    #[test]
    fn negative_total_writes_nothing_and_returns_nitems() {
        let _guard = hook_lock();
        unsafe {
            install_scripted_putc(0);
            let buf = *b"abc";
            // Signed `blt` bound: total = 3 * -2 < 0, loop never runs.
            assert_eq!(stream_write_block(buf.as_ptr(), 3, -2, 1), -2);
            assert!(PUTC_BYTES.is_empty());
        }
        reset_hook();
    }

    #[test]
    fn single_byte_blocks() {
        let _guard = hook_lock();
        unsafe {
            install_scripted_putc(i32::MAX);
            let buf = *b"\0\xff\n";
            assert_eq!(stream_write_block(buf.as_ptr(), 1, 3, 5), 3);
            assert_eq!(PUTC_BYTES, std::vec![0x00, 0xff, b'\n'],
                "NUL and high bytes are plain data");
        }
        reset_hook();
    }
}
