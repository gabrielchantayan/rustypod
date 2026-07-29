//! Indented key/value message emitter — formats one `<key>` + `<integer>`
//! plist fragment into a stream object's inline scratch buffer, then
//! hands the buffer to the stream's append path.
//!
//! - `formatted_message_emit` — original: `FUN_08123600` @ 0x08123600
//!   (80 bytes; 83 `bl` call sites, binary-scanned).
//!
//! Algorithm: prepare the stream's indentation for the requested nesting
//! `depth` (`indent_prepare` @ 0x08123a54 fills the scratch buffer at
//! +0x215 with `depth` copies of the stream's indent unit, looked up from
//! a table indexed by the style byte at +0x14), then format
//! `"%s<key>%s</key>\n%s<integer>%d</integer>\n"` — a literal @
//! 0x08123650, immediately after the body and reached with `adr` — into
//! the inline 512-byte buffer at +0x15 via `snprintf` @ 0x0802f768 with
//! the argument list `(indent, key, indent, value)`, and finally tail-
//! branch to the stream append @ 0x08123c58(stream, buffer), which
//! `strlen`s the buffer and either `strncat`s it onto the stream output
//! (+0x04 base, +0x08 end, +0x0c written) or bumps the overflow counter
//! at +0x10 when it no longer fits.
//!
//! Call sites confirm the shape, e.g. @ 0x081502b0:
//! `formatted_message_emit(ctx + 0xc, "Minimum", *(u8 *)(ctx + 0x264), 2)`
//! — a plist writer emitting one integer property per call.
//!
//! `MessageStream` fields used (pinned by this function's `add rX, r4,
//! #off` sequence):
//!
//! ```text
//! +0x15 buf     ([u8; 0x200])  inline format buffer, one message at a time
//! +0x215 indent ([u8; 0x40])   indent scratch, filled by the preparer
//! ```
//!
//! Deviations:
//! - `snprintf` @ 0x0802f768 *is* ported
//!   (`printf::printf_api::snprintf`) and is called directly, per the
//!   porting rules. The variadic `...` is passed as an explicit four-word
//!   [`VaList`] built on the stack — exactly the r3 + two stack-word
//!   argument area the original builds (house convention, see
//!   `printf/printf_api.rs`).
//! - `indent_prepare` @ 0x08123a54 and the stream append @ 0x08123c58
//!   are not ported; they are the [`INDENT_PREPARE`] / [`STREAM_APPEND`]
//!   dispatch boundaries (house pattern, see `sqlite/error_msg.rs`). The
//!   default indent slot writes a single NUL — the same end state the
//!   original reaches with `depth == 0` (buffer NULed, zero copies
//!   appended). The default append slot drops the message: the stream
//!   keeps its counters, the formatted text stays in the inline buffer
//!   (the original's overflow path would instead bump +0x10 by the
//!   message length — that counter belongs to the append batch).
//! - The original tail-branches to the append (`b 0x08123c58`); the Rust
//!   body calls and returns. Same argument registers, one extra stack
//!   frame in the match.py diff.

use super::printf_api::{snprintf, VaList};

/// The plist-fragment format literal @ 0x08123650 (addressed by the
/// original with `adr r2, 0x8123650`, right after the 80-byte body).
/// Consumes four argument words: indent, key, indent, value.
const PLIST_INTEGER_FORMAT: &[u8] = b"%s<key>%s</key>\n%s<integer>%d</integer>\n\0";

/// Capacity of the inline format buffer at +0x15 (original: `mov r1,
/// #0x200`).
const BUFFER_CAPACITY: usize = 0x200;

/// An indented-message output stream, only the fields this emitter
/// touches. See the module header for the original byte offsets; the
/// output base/end/written/overflow words at +0x04..+0x10 and the
/// indent-style byte at +0x14 belong to the append/indent batches and
/// are unmodeled here.
#[repr(C)]
pub struct MessageStream {
    /// +0x00..+0x15: unmodeled (stream output state and indent style).
    pub _gap_00: [u8; 0x15],
    /// +0x15: inline format buffer; the message is built here, then
    /// appended to the stream.
    pub buf: [u8; BUFFER_CAPACITY],
    /// +0x215: indent scratch buffer; the preparer fills it with `depth`
    /// copies of the stream's indent unit. Only its address is used here
    /// (as the first and third `%s` argument); its true extent is owned
    /// by the indent batch.
    pub indent: [u8; 0x40],
}

// The original's byte offsets. The struct is all bytes, so they hold on
// every host — asserted unconditionally.
const _BUF_OFFSET: [u8; 0x15] = [0; core::mem::offset_of!(MessageStream, buf)];
const _INDENT_OFFSET: [u8; 0x215] = [0; core::mem::offset_of!(MessageStream, indent)];

/// The indentation preparer: `indent_prepare(stream, depth)` @
/// 0x08123a54. Fills `stream.indent` with `depth` copies of the stream's
/// indent unit.
pub type IndentPrepareFn = unsafe extern "C" fn(stream: *mut MessageStream, depth: u32);

/// Default stub: no preparer wired, so the indent comes out empty — the
/// same end state the original reaches with `depth == 0` (it NULs the
/// scratch buffer, then appends zero copies).
pub(crate) unsafe extern "C" fn empty_indent_prepare(stream: *mut MessageStream, _depth: u32) {
    (*stream).indent[0] = 0;
}

/// The active indentation preparer. Host tests install recording mocks;
/// the real port replaces the default when 0x08123a54 lands.
pub static mut INDENT_PREPARE: IndentPrepareFn = empty_indent_prepare;

/// Reads the preparer slot (volatile — the slot is meant to be swapped
/// at runtime, and a plain read lets LLVM const-fold the default away).
#[inline(always)]
pub(crate) fn indent_prepare_op() -> IndentPrepareFn {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(INDENT_PREPARE)) }
}

/// The stream append: `stream_append(stream, text)` @ 0x08123c58.
/// Appends the NUL-terminated `text` to the stream output, or accounts
/// it as overflow when it no longer fits.
pub type StreamAppendFn = unsafe extern "C" fn(stream: *mut MessageStream, text: *const u8);

/// Default stub: no append wired, so the message is dropped — the
/// formatted text stays in the inline buffer and the stream's counters
/// are untouched (see the module header for how this differs from the
/// original's overflow path).
pub(crate) unsafe extern "C" fn dropping_stream_append(
    _stream: *mut MessageStream,
    _text: *const u8,
) {
}

/// The active stream append. Host tests install recording mocks; the
/// real port replaces the default when 0x08123c58 lands.
pub static mut STREAM_APPEND: StreamAppendFn = dropping_stream_append;

/// Reads the append slot (volatile — see [`indent_prepare_op`]).
#[inline(always)]
pub(crate) fn stream_append_op() -> StreamAppendFn {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(STREAM_APPEND)) }
}

/// formatted_message_emit — original: `FUN_08123600` @ 0x08123600 (80
/// bytes; 83 `bl` call sites).
///
/// Emit one indented `<key>key</key>` + `<integer>value</integer>` plist
/// fragment to `stream`: prepare the indentation for nesting `depth`,
/// format the fragment into the stream's inline buffer with
/// [`PLIST_INTEGER_FORMAT`], and append the buffer to the stream output.
///
/// Register usage: r0 = stream, r1 = key, r2 = value, r3 = depth
/// (original forwards r3 as the preparer's depth argument).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn formatted_message_emit(
    stream: *mut MessageStream,
    key: *const u8,
    value: i32,
    depth: u32,
) {
    let stream = &mut *stream;
    (indent_prepare_op())(stream, depth);
    let indent = stream.indent.as_ptr();
    // The original's argument area: r3 = indent, stack = {key, indent,
    // value} — here built as one explicit four-word va_list. (`as u32`
    // truncates on 64-bit hosts; the words are only dereferenced by the
    // engine on the 32-bit target.)
    let args: [u32; 4] = [indent as u32, key as u32, indent as u32, value as u32];
    snprintf(
        stream.buf.as_mut_ptr(),
        stream.buf.len(),
        PLIST_INTEGER_FORMAT.as_ptr(),
        args.as_ptr(),
    );
    let text = stream.buf.as_ptr();
    (stream_append_op())(stream, text);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::super::printf_api::{PrintfEngineFn, PRINTF_ENGINE};
    use super::*;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// Serializes tests that swap the three dispatch slots (and the
    /// default-slot test, which must not observe a swapped slot).
    static SLOT_LOCK: Mutex<()> = Mutex::new(());

    fn slot_lock() -> MutexGuard<'static, ()> {
        SLOT_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A backing allocation for a stream, padded so the (unmodeled)
    /// fields around the two used ones stay in bounds.
    fn backing() -> Vec<u8> {
        std::vec![0xAAu8; 0x15 + BUFFER_CAPACITY + 0x40 + 0x40]
    }

    fn stream_of(backing: &mut [u8]) -> *mut MessageStream {
        backing.as_mut_ptr() as *mut MessageStream
    }

    /// Contract-faithful fake engine: emits the format bytes verbatim
    /// (no `%` handling) through the bound sink, returning the count —
    /// same fake as `printf_api`'s tests. Lets the formatted message be
    /// observed end to end without the printf_core batch.
    unsafe extern "C" fn echo_engine(
        fmt: *const u8,
        putc: crate::printf_helpers::PutcFn,
        ctx: *mut core::ffi::c_void,
        _ap: VaList,
    ) -> i32 {
        let mut p = fmt;
        let mut n = 0;
        while *p != 0 {
            putc(*p, ctx);
            p = p.add(1);
            n += 1;
        }
        n
    }

    /// Snapshot of everything the formatter leg is contract-bound to
    /// pass: the format literal, the bounded-sink window, and the four
    /// argument words (copied while the call is live — the va_list is a
    /// stack array inside `formatted_message_emit`).
    static mut FORMAT_LEG: Option<(*const u8, usize, usize, [u32; 4])> = None;

    unsafe extern "C" fn snapshot_engine(
        fmt: *const u8,
        _putc: crate::printf_helpers::PutcFn,
        ctx: *mut core::ffi::c_void,
        ap: VaList,
    ) -> i32 {
        let w = ctx as *const usize; // BoundedCursor { cursor, end }
        let mut words = [0u32; 4];
        for (i, slot) in words.iter_mut().enumerate() {
            *slot = *ap.add(i);
        }
        FORMAT_LEG = Some((fmt, *w, *w.add(1), words));
        0
    }

    /// (stream, depth) of the last indent-prepare invocation, and a
    /// scratch indent the mock installs (two tabs) so the buffer content
    /// the emitter formats is observably the preparer's product.
    static mut PREPARE_LEG: Option<(*mut MessageStream, u32)> = None;

    unsafe extern "C" fn recording_indent_prepare(stream: *mut MessageStream, depth: u32) {
        PREPARE_LEG = Some((stream, depth));
        (&mut (*stream).indent)[..3].copy_from_slice(b"\t\t\0");
    }

    /// (stream, text) of the last append invocation, plus the text
    /// copied out while it is valid (the next emit overwrites it).
    static mut APPEND_LEG: Option<(*mut MessageStream, *const u8, Vec<u8>)> = None;

    unsafe extern "C" fn recording_stream_append(stream: *mut MessageStream, text: *const u8) {
        let mut copied = std::vec::Vec::new();
        let mut p = text;
        while *p != 0 {
            copied.push(*p);
            p = p.add(1);
        }
        APPEND_LEG = Some((stream, text, copied));
    }

    /// Swaps in the three recording mocks for `body`, then restores the
    /// previous slots so a failed assertion cannot leak the mocks into
    /// the next test.
    unsafe fn with_mocks(engine: PrintfEngineFn, body: impl FnOnce()) {
        let saved_prepare = indent_prepare_op();
        let saved_append = stream_append_op();
        let saved_engine = core::ptr::read_volatile(core::ptr::addr_of!(PRINTF_ENGINE));
        core::ptr::write_volatile(core::ptr::addr_of_mut!(INDENT_PREPARE), recording_indent_prepare);
        core::ptr::write_volatile(core::ptr::addr_of_mut!(STREAM_APPEND), recording_stream_append);
        core::ptr::write_volatile(core::ptr::addr_of_mut!(PRINTF_ENGINE), engine);
        body();
        core::ptr::write_volatile(core::ptr::addr_of_mut!(INDENT_PREPARE), saved_prepare);
        core::ptr::write_volatile(core::ptr::addr_of_mut!(STREAM_APPEND), saved_append);
        core::ptr::write_volatile(core::ptr::addr_of_mut!(PRINTF_ENGINE), saved_engine);
    }

    #[test]
    fn prepares_indents_formats_and_appends_in_order() {
        let _guard = slot_lock();
        let mut mem = backing();
        let stream = stream_of(&mut mem);
        let key = b"Minimum\0";
        unsafe {
            with_mocks(snapshot_engine, || {
                formatted_message_emit(stream, key.as_ptr(), 44100, 2);
            });
            let (prep_stream, prep_depth) = PREPARE_LEG.expect("indent prepared");
            assert_eq!(prep_stream, stream, "preparer saw the stream");
            assert_eq!(prep_depth, 2, "preparer saw the depth (original r3)");

            let (fmt, cursor, end, words) = FORMAT_LEG.expect("formatter ran");
            let mut fmt_bytes = std::vec::Vec::new();
            let mut p = fmt;
            while *p != 0 {
                fmt_bytes.push(*p);
                p = p.add(1);
            }
            assert_eq!(fmt_bytes, &PLIST_INTEGER_FORMAT[..PLIST_INTEGER_FORMAT.len() - 1]);
            let buf = (*stream).buf.as_mut_ptr();
            assert_eq!(cursor, buf as usize, "snprintf target is the inline buffer at +0x15");
            assert_eq!(end, buf.add(BUFFER_CAPACITY - 1) as usize, "bounded at +0x15 + 0x200");
            let indent = (*stream).indent.as_ptr();
            assert_eq!(
                words,
                [indent as u32, key.as_ptr() as u32, indent as u32, 44100],
                "argument area: (indent, key, indent, value)"
            );

            let (app_stream, app_text, _) =
                (*core::ptr::addr_of_mut!(APPEND_LEG)).take().expect("appended");
            assert_eq!(app_stream, stream);
            assert_eq!(app_text, buf, "append got the inline buffer");
        }
    }

    #[test]
    fn formats_the_prepared_indent_and_key_into_the_fragment() {
        let _guard = slot_lock();
        let mut mem = backing();
        let stream = stream_of(&mut mem);
        unsafe {
            with_mocks(echo_engine, || {
                formatted_message_emit(stream, b"Format\0".as_ptr(), 2, 1);
            });
            // The echo engine emits the literal without expanding the
            // conversions; the observable contract here is that the
            // append receives exactly the formatter's product (the
            // preparer's two tabs sit in the scratch the %s slots name).
            let (_, _, text) = (*core::ptr::addr_of_mut!(APPEND_LEG)).take().expect("appended");
            assert_eq!(text, &PLIST_INTEGER_FORMAT[..PLIST_INTEGER_FORMAT.len() - 1]);
            let stream = &*stream;
            assert_eq!(&stream.indent[..3], b"\t\t\0".as_slice(), "preparer's product in place");
        }
    }

    #[test]
    fn default_slots_give_empty_indent_and_drop_the_message() {
        let _guard = slot_lock();
        let mut mem = backing();
        let stream = stream_of(&mut mem);
        unsafe {
            // No mocks installed: documented defaults + the engine stub.
            formatted_message_emit(stream, b"k\0".as_ptr(), -1, 7);
            assert_eq!((*stream).indent[0], 0, "default preparer: empty indent");
            assert_eq!((*stream).buf[0], 0, "stub engine still NUL-terminates the buffer");
            // The default append dropped the message: bytes past the NUL
            // are the untouched backing fill.
            assert_eq!((*stream).buf[1], 0xAA);
        }
    }
}
