//! Indented key/value message emitter — formats one `<key>` + `<integer>`
//! plist fragment into a stream object's inline scratch buffer, then
//! hands the buffer to the stream's append path.
//!
//! - `formatted_message_emit` — original: `FUN_08123600` @ 0x08123600
//!   (80 bytes; 83 `bl` call sites, binary-scanned).
//! - `formatted_message_emit_boolean` — original: `FUN_0812395c` @
//!   0x0812395c (88 bytes; 58 `bl` call sites, binary-scanned).
//! - `indent_prepare` — original: `FUN_08123a54` @ 0x08123a54 (76
//!   bytes; 14 `bl` call sites, binary-scanned).
//!
//! Algorithm: prepare the stream's indentation for the requested nesting
//! `depth` ([`indent_prepare`] fills the scratch buffer at +0x215 with
//! `depth` copies of the stream's indent unit, looked up from a table
//! indexed by the style byte at +0x14), then format
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
//! The boolean sibling @ 0x0812395c is the same emitter with the value
//! replaced by an empty-element tag looked up from a table: the literal-
//! pool word @ 0x081239b4 (right after the 88-byte body) holds the table
//! base 0x089cb210, the tag is `table[index]` (`ldr r3, [r0, r5, lsl
//! #2]`), and the format literal @ 0x081239b8 (reached with `adr`) is
//! `"%s<key>%s</key>\n%s<%s/>\n"` with the argument list `(indent, key,
//! indent, tag)`. Every call site passes `index` 0/1 with plist boolean
//! semantics — @ 0x081502b0 emits `"Stereo"` with 1 but
//! `"Multichannel"` with 0 — so the table is the `{"false", "true"}`
//! tag pair of a plist boolean property. (The osos.dec bytes at VA
//! 0x089cb210 are an unreferenced resource-string blob, so the runtime
//! table contents are not statically readable from the image; the
//! pair above is pinned by the call sites and plist syntax, and the
//! [`BOOLEAN_TAG_TABLE`] slot keeps the indirection faithful.)
//!
//! `MessageStream` fields used (pinned by this function's `add rX, r4,
//! #off` sequence):
//!
//! ```text
//! +0x14 style   (u8)          indent-style byte, indexes the unit table
//! +0x15 buf     ([u8; 0x200])  inline format buffer, one message at a time
//! +0x215 indent ([u8; 0x40])   indent scratch, filled by the preparer
//! ```
//!
//! `indent_prepare` @ 0x08123a54 (ported below): NUL the scratch at
//! +0x215, then `strncat` @ 0x08031200 the indent unit `depth` times —
//! `unit = INDENT_UNIT_TABLE[style]`, table base from the literal-pool
//! word @ 0x08123aa0 (0x089cb218, 8 bytes past the boolean-tag table
//! base; the style byte is re-read each iteration), each copy bounded
//! at 0x40 source bytes with no destination bound. The osos.dec bytes
//! at VA 0x089cb218 are the same unreferenced resource-string blob as
//! the boolean sibling's table, so the runtime unit strings are not
//! statically readable from the image; the [`INDENT_UNIT_TABLE`] slot
//! keeps the indirection faithful, defaulting to the single-entry
//! `{"\t"}` table pinned by plist convention.
//!
//! Deviations:
//! - `snprintf` @ 0x0802f768 *is* ported
//!   (`printf::printf_api::snprintf`) and is called directly, per the
//!   porting rules. The variadic `...` is passed as an explicit four-word
//!   [`VaList`] built on the stack — exactly the r3 + two stack-word
//!   argument area the original builds (house convention, see
//!   `printf/printf_api.rs`).
//! - `indent_prepare` @ 0x08123a54 *is* ported (below) and is the
//!   shipped default of the [`INDENT_PREPARE`] dispatch slot; the slot
//!   stays swappable so host tests can install recording mocks (house
//!   pattern, see `sqlite/error_msg.rs`). Its indent-unit table base —
//!   the original's literal-pool word @ 0x08123aa0 — is the swappable
//!   [`INDENT_UNIT_TABLE`] static, mirroring the boolean sibling's
//!   [`BOOLEAN_TAG_TABLE`]. The stream append @ 0x08123c58 is not
//!   ported; it is the [`STREAM_APPEND`] dispatch boundary. The default
//!   append slot drops the message: the stream keeps its counters, the
//!   formatted text stays in the inline buffer (the original's overflow
//!   path would instead bump +0x10 by the message length — that counter
//!   belongs to the append batch).
//! - The original tail-branches to the append (`b 0x08123c58`); the Rust
//!   body calls and returns. Same argument registers, one extra stack
//!   frame in the match.py diff.

use super::printf_api::{snprintf, VaList};
use crate::libc::strcat::strncat;

/// The plist-fragment format literal @ 0x08123650 (addressed by the
/// original with `adr r2, 0x8123650`, right after the 80-byte body).
/// Consumes four argument words: indent, key, indent, value.
const PLIST_INTEGER_FORMAT: &[u8] = b"%s<key>%s</key>\n%s<integer>%d</integer>\n\0";

/// The boolean-sibling format literal @ 0x081239b8 (addressed by the
/// original with `adr r2, 0x81239b8`, right after the 88-byte body and
/// its literal-pool word). Consumes four argument words: indent, key,
/// indent, tag — the tag is emitted as an empty element (`<true/>`).
const PLIST_BOOLEAN_FORMAT: &[u8] = b"%s<key>%s</key>\n%s<%s/>\n\0";

/// Capacity of the inline format buffer at +0x15 (original: `mov r1,
/// #0x200`).
const BUFFER_CAPACITY: usize = 0x200;

/// Capacity of the indent scratch buffer at +0x215, and the per-copy
/// `strncat` limit the original passes (`mov r2, #0x40`). Note the
/// original bounds each *source* copy at 0x40 bytes but never the
/// destination — `depth` copies of a long unit would overrun the
/// scratch; the port keeps the call pattern faithful.
const INDENT_SCRATCH_CAPACITY: usize = 0x40;

/// An indented-message output stream, only the fields this emitter
/// touches. See the module header for the original byte offsets; the
/// output base/end/written/overflow words at +0x04..+0x10 belong to the
/// append batch and are unmodeled here.
#[repr(C)]
pub struct MessageStream {
    /// +0x00..+0x14: unmodeled (stream output state).
    pub _gap_00: [u8; 0x14],
    /// +0x14: indent-style byte; indexes [`INDENT_UNIT_TABLE`] with no
    /// bounds check (the original's `ldrb r0, [r5, #0x14]` + `ldr r1,
    /// [r7, r0, lsl #2]`).
    pub style: u8,
    /// +0x15: inline format buffer; the message is built here, then
    /// appended to the stream.
    pub buf: [u8; BUFFER_CAPACITY],
    /// +0x215: indent scratch buffer; [`indent_prepare`] fills it with
    /// `depth` copies of the stream's indent unit.
    pub indent: [u8; INDENT_SCRATCH_CAPACITY],
}

// The original's byte offsets. The struct is all bytes, so they hold on
// every host — asserted unconditionally.
const _STYLE_OFFSET: [u8; 0x14] = [0; core::mem::offset_of!(MessageStream, style)];
const _BUF_OFFSET: [u8; 0x15] = [0; core::mem::offset_of!(MessageStream, buf)];
const _INDENT_OFFSET: [u8; 0x215] = [0; core::mem::offset_of!(MessageStream, indent)];

/// A static table of C-string pointers; the strings are immutable
/// literals, so sharing the table across (test) threads is sound.
struct IndentUnits([*const u8; 1]);
unsafe impl Sync for IndentUnits {}

/// The default indent-unit table: a single style whose unit is one
/// horizontal tab — the conventional plist indent. The original's table
/// base lives in the literal-pool word @ 0x08123aa0 (value 0x089cb218);
/// its runtime contents are not statically readable from osos.dec (the
/// VA is an unreferenced resource-string blob — see the module header),
/// so the default is pinned by plist convention, exactly the situation
/// of the boolean sibling's tag table.
static DEFAULT_INDENT_UNITS: IndentUnits = IndentUnits([b"\t\0".as_ptr()]);

/// The active indent-unit table base — the value of the original's
/// literal-pool word @ 0x08123aa0, dereferenced as `table[style]` with
/// no bounds check (the original's `ldr r1, [r7, r0, lsl #2]`). Host
/// tests install recording tables; the firmware table replaces the
/// default if 0x089cb218's runtime contents are ever mapped.
pub static mut INDENT_UNIT_TABLE: *const *const u8 = DEFAULT_INDENT_UNITS.0.as_ptr();

/// Reads the table-base slot (volatile — the slot is meant to be swapped
/// at runtime, and a plain read lets LLVM const-fold the default away).
#[inline(always)]
pub(crate) fn indent_unit_table() -> *const *const u8 {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(INDENT_UNIT_TABLE)) }
}

/// indent_prepare — original: `FUN_08123a54` @ 0x08123a54 (76 bytes; 14
/// `bl` call sites).
///
/// Fill `stream.indent` (the scratch at +0x215) with `depth` copies of
/// the stream's indent unit: NUL the scratch, then `strncat(indent,
/// INDENT_UNIT_TABLE[style], 0x40)` per copy — the unit string is looked
/// up from the table base in the literal-pool word @ 0x08123aa0,
/// indexed by the style byte at +0x14 (re-read each iteration, no
/// bounds check). Each copy appends at most 0x40 source bytes; the
/// destination is never bounded (faithful to the original).
///
/// Register usage: r0 = stream, r1 = depth.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn indent_prepare(stream: *mut MessageStream, depth: u32) {
    let stream = &mut *stream;
    stream.indent[0] = 0;
    let table = indent_unit_table();
    for _ in 0..depth {
        let unit = *table.offset(stream.style as isize);
        strncat(
            stream.indent.as_mut_ptr(),
            unit,
            INDENT_SCRATCH_CAPACITY,
        );
    }
}

/// The indentation preparer: `indent_prepare(stream, depth)` @
/// 0x08123a54. Fills `stream.indent` with `depth` copies of the stream's
/// indent unit.
pub type IndentPrepareFn = unsafe extern "C" fn(stream: *mut MessageStream, depth: u32);

/// The active indentation preparer. The shipped default is the ported
/// [`indent_prepare`]; host tests install recording mocks.
pub static mut INDENT_PREPARE: IndentPrepareFn = indent_prepare;

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

/// A static table of C-string pointers; the strings are immutable
/// literals, so sharing the table across (test) threads is sound.
struct BooleanTags([*const u8; 2]);
unsafe impl Sync for BooleanTags {}

/// The default boolean-tag table: the plist empty-element tags indexed
/// 0/1, as pinned by the call sites (index 0 for `"Multichannel"`, 1
/// for `"Stereo"`). The original's table base lives in the literal-pool
/// word @ 0x081239b4; its runtime contents are not statically readable
/// from osos.dec (see the module header).
static DEFAULT_BOOLEAN_TAGS: BooleanTags =
    BooleanTags([b"false\0".as_ptr(), b"true\0".as_ptr()]);

/// The active boolean-tag table base — the value of the original's
/// literal-pool word @ 0x081239b4, dereferenced as `table[index]` with
/// no bounds check (the original's `ldr r3, [r0, r5, lsl #2]`). Host
/// tests install recording tables; the firmware table replaces the
/// default if 0x089cb210's runtime contents are ever mapped.
pub static mut BOOLEAN_TAG_TABLE: *const *const u8 = DEFAULT_BOOLEAN_TAGS.0.as_ptr();

/// Reads the table-base slot (volatile — see [`indent_prepare_op`]).
#[inline(always)]
pub(crate) fn boolean_tag_table() -> *const *const u8 {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(BOOLEAN_TAG_TABLE)) }
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

/// formatted_message_emit_boolean — original: `FUN_0812395c` @
/// 0x0812395c (88 bytes; 58 `bl` call sites).
///
/// Emit one indented `<key>key</key>` + `<tag/>` plist boolean property
/// to `stream`: prepare the indentation for nesting `depth`, look the
/// empty-element `tag` up as `BOOLEAN_TAG_TABLE[index]` (the original's
/// literal-pool table base @ 0x081239b4, `ldr r3, [r0, r5, lsl #2]`),
/// format the fragment into the stream's inline buffer with
/// [`PLIST_BOOLEAN_FORMAT`], and append the buffer to the stream
/// output. Same body as [`formatted_message_emit`] apart from the table
/// lookup and the format literal.
///
/// Register usage: r0 = stream, r1 = key, r2 = index, r3 = depth
/// (original forwards r3 as the preparer's depth argument and indexes
/// the tag table with r2).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn formatted_message_emit_boolean(
    stream: *mut MessageStream,
    key: *const u8,
    index: u32,
    depth: u32,
) {
    let stream = &mut *stream;
    (indent_prepare_op())(stream, depth);
    // The original's table lookup: base from the pool word @ 0x081239b4,
    // entry at base + index*4, no bounds check.
    let tag = *boolean_tag_table().offset(index as isize);
    let indent = stream.indent.as_ptr();
    // Same four-word argument area as the integer sibling: r3 = indent,
    // stack = {key, indent, tag}.
    let args: [u32; 4] = [indent as u32, key as u32, indent as u32, tag as u32];
    snprintf(
        stream.buf.as_mut_ptr(),
        stream.buf.len(),
        PLIST_BOOLEAN_FORMAT.as_ptr(),
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
    fn default_slots_prepare_the_default_indent_and_drop_the_message() {
        let _guard = slot_lock();
        let mut mem = backing();
        let stream = stream_of(&mut mem);
        unsafe {
            (*stream).style = 0; // index the default table's "\t" unit
            // No mocks installed: ported default preparer, default table,
            // default append, and the engine stub.
            formatted_message_emit(stream, b"k\0".as_ptr(), -1, 3);
            assert_eq!(
                &(&(*stream).indent)[..4],
                b"\t\t\t\0".as_slice(),
                "default preparer: depth copies of the default unit"
            );
            assert_eq!((*stream).buf[0], 0, "stub engine still NUL-terminates the buffer");
            // The default append dropped the message: bytes past the NUL
            // are the untouched backing fill.
            assert_eq!((*stream).buf[1], 0xAA);
        }
    }

    /// A recording unit table distinct from the default, so the lookup
    /// is observably the slot's product: style 0 -> "--", style 1 -> "..".
    static RECORDING_UNITS: IndentUnits2 = IndentUnits2([b"--\0".as_ptr(), b"..\0".as_ptr()]);

    /// Two-entry variant of the unit-table wrapper for the recording
    /// table (the default needs only one style).
    struct IndentUnits2([*const u8; 2]);
    unsafe impl Sync for IndentUnits2 {}

    /// Swaps in the recording unit table for `body`, then restores the
    /// previous base (same discipline as [`with_mocks`]).
    unsafe fn with_units(body: impl FnOnce()) {
        let saved = indent_unit_table();
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(INDENT_UNIT_TABLE),
            RECORDING_UNITS.0.as_ptr(),
        );
        body();
        core::ptr::write_volatile(core::ptr::addr_of_mut!(INDENT_UNIT_TABLE), saved);
    }

    #[test]
    fn prepare_depth_zero_only_nuls_the_scratch() {
        let _guard = slot_lock();
        let mut mem = backing();
        let stream = stream_of(&mut mem);
        unsafe {
            (*stream).style = 1;
            with_units(|| {
                indent_prepare(stream, 0);
            });
            assert_eq!((*stream).indent[0], 0, "scratch NULed");
            assert_eq!((*stream).indent[1], 0xAA, "zero copies appended");
        }
    }

    #[test]
    fn prepare_appends_depth_copies_of_the_styled_unit() {
        let _guard = slot_lock();
        let mut mem = backing();
        let stream = stream_of(&mut mem);
        unsafe {
            (*stream).style = 1;
            with_units(|| {
                indent_prepare(stream, 3);
            });
            assert_eq!(
                &(&(*stream).indent)[..7],
                b"......\0".as_slice(),
                "depth 3 x style 1 (\"..\")"
            );
            (*stream).style = 0;
            with_units(|| {
                indent_prepare(stream, 2);
            });
            assert_eq!(
                &(&(*stream).indent)[..5],
                b"----\0".as_slice(),
                "depth 2 x style 0 (\"--\"), scratch reset first"
            );
        }
    }

    #[test]
    fn prepare_bounds_each_copy_at_0x40_source_bytes() {
        let _guard = slot_lock();
        let mut mem = backing();
        let stream = stream_of(&mut mem);
        // A unit longer than the per-copy limit: only the first 0x40
        // bytes land per strncat(dst, src, 0x40).
        static LONG_UNIT: [u8; 0x49] = {
            let mut a = [b'x'; 0x49];
            a[0x48] = 0;
            a
        };
        struct LongUnit([*const u8; 1]);
        unsafe impl Sync for LongUnit {}
        static LONG_TABLE: LongUnit = LongUnit([LONG_UNIT.as_ptr()]);
        unsafe {
            (*stream).style = 0;
            let saved = indent_unit_table();
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(INDENT_UNIT_TABLE),
                LONG_TABLE.0.as_ptr(),
            );
            indent_prepare(stream, 1);
            core::ptr::write_volatile(core::ptr::addr_of_mut!(INDENT_UNIT_TABLE), saved);
            assert!(
                (*stream).indent.iter().all(|&b| b == b'x'),
                "0x40 source bytes copied"
            );
            // strncat's terminator lands one past the 0x40-byte scratch
            // (the original never bounds the destination; the backing's
            // pad absorbs it here).
            assert_eq!((*stream).indent.as_ptr().add(INDENT_SCRATCH_CAPACITY).read(), 0);
        }
    }

    /// A recording table distinct from the default, so the lookup is
    /// observably the slot's product: index 0 -> "no", index 1 -> "yes".
    static RECORDING_TAGS: BooleanTags = BooleanTags([b"no\0".as_ptr(), b"yes\0".as_ptr()]);

    /// Swaps in the recording tag table for `body`, then restores the
    /// previous base (same discipline as [`with_mocks`]).
    unsafe fn with_table(body: impl FnOnce()) {
        let saved = boolean_tag_table();
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(BOOLEAN_TAG_TABLE),
            RECORDING_TAGS.0.as_ptr(),
        );
        body();
        core::ptr::write_volatile(core::ptr::addr_of_mut!(BOOLEAN_TAG_TABLE), saved);
    }

    #[test]
    fn boolean_looks_up_the_tag_and_emits_in_order() {
        let _guard = slot_lock();
        let mut mem = backing();
        let stream = stream_of(&mut mem);
        let key = b"Stereo\0";
        unsafe {
            with_mocks(snapshot_engine, || {
                with_table(|| {
                    formatted_message_emit_boolean(stream, key.as_ptr(), 1, 3);
                });
            });
            let (prep_stream, prep_depth) = PREPARE_LEG.expect("indent prepared");
            assert_eq!(prep_stream, stream, "preparer saw the stream");
            assert_eq!(prep_depth, 3, "preparer saw the depth (original r3)");

            let (fmt, cursor, end, words) = FORMAT_LEG.expect("formatter ran");
            let mut fmt_bytes = std::vec::Vec::new();
            let mut p = fmt;
            while *p != 0 {
                fmt_bytes.push(*p);
                p = p.add(1);
            }
            assert_eq!(fmt_bytes, &PLIST_BOOLEAN_FORMAT[..PLIST_BOOLEAN_FORMAT.len() - 1]);
            let buf = (*stream).buf.as_mut_ptr();
            assert_eq!(cursor, buf as usize, "snprintf target is the inline buffer at +0x15");
            assert_eq!(end, buf.add(BUFFER_CAPACITY - 1) as usize, "bounded at +0x15 + 0x200");
            let indent = (*stream).indent.as_ptr();
            assert_eq!(
                words,
                [
                    indent as u32,
                    key.as_ptr() as u32,
                    indent as u32,
                    RECORDING_TAGS.0[1] as u32
                ],
                "argument area: (indent, key, indent, table[index])"
            );

            let (app_stream, app_text, _) =
                (*core::ptr::addr_of_mut!(APPEND_LEG)).take().expect("appended");
            assert_eq!(app_stream, stream);
            assert_eq!(app_text, buf, "append got the inline buffer");
        }
    }

    #[test]
    fn boolean_index_zero_picks_the_first_tag() {
        let _guard = slot_lock();
        let mut mem = backing();
        let stream = stream_of(&mut mem);
        unsafe {
            with_mocks(snapshot_engine, || {
                with_table(|| {
                    formatted_message_emit_boolean(stream, b"Multichannel\0".as_ptr(), 0, 3);
                });
            });
            let (_, _, _, words) = FORMAT_LEG.expect("formatter ran");
            assert_eq!(words[3], RECORDING_TAGS.0[0] as u32, "index 0 -> first tag");
        }
    }

    #[test]
    fn boolean_default_table_is_the_plist_false_true_pair() {
        let _guard = slot_lock();
        let mut mem = backing();
        let stream = stream_of(&mut mem);
        unsafe {
            // Only the engine is mocked, so the lookup observes the
            // documented default table.
            with_mocks(snapshot_engine, || {
                formatted_message_emit_boolean(stream, b"PodcastsSupported\0".as_ptr(), 1, 1);
            });
            let (_, _, _, words) = FORMAT_LEG.expect("formatter ran");
            assert_eq!(words[3], b"true\0".as_ptr() as u32, "index 1 -> \"true\"");
            with_mocks(snapshot_engine, || {
                formatted_message_emit_boolean(stream, b"Multichannel\0".as_ptr(), 0, 1);
            });
            let (_, _, _, words) = FORMAT_LEG.expect("formatter ran");
            assert_eq!(words[3], b"false\0".as_ptr() as u32, "index 0 -> \"false\"");
        }
    }
}
