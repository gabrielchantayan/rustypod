//! FreeType `ftstream` — the byte-order-aware stream cursor
//! (`FT_Stream_Seek`, `FT_Stream_Skip` and the `FT_Stream_ReadChar` /
//! `ReadShort` / `ReadOffset` / `ReadLong` / `ReadLongLE` readers) as
//! compiled into retailOS. The `FT_ASSERT` calls of this debug build are
//! live, and their `__FILE__` pointers resolve to
//! `...\freetype\src\base\ftstream.c`, which is how these are pinned to
//! that translation unit. Call counts are binary-scanned b/bl words.
//!
//! The `__LINE__` literals the asserts carry order these functions
//! exactly as upstream `ftstream.c` lays them out — `EnterFrame` 235,
//! `ExitFrame` 304,
//! `GetChar` 328, `GetShort` 345, `GetShortLE` 364, `GetLong` 401,
//! `ReadChar` 437, `ReadShort` 475, `ReadOffset` 569, `ReadLong` 616,
//! `ReadLongLE` 662 — which is the second, independent confirmation of
//! each name (the first being the `"FT_Stream_ReadXxx:"` trace tag or
//! the byte pattern itself). Three siblings upstream puts inside those
//! gaps are missing from the image entirely, dead-stripped: `GetOffset`
//! (~383), `GetLongLE` (~419) and `ReadShortLE` (~520) have no assert
//! line and no trace string anywhere in 0x0804c000..0x08051000.
//!
//! With `FT_Stream_ReadFields` the module is complete: the linker sorted
//! this translation unit alphabetically, and the 25 functions from
//! `FT_Stream_Close` @ 0x0804ed9c to `FT_Stream_TryRead` @ 0x0804fd94
//! are contiguous with no gaps left — the only names missing from that
//! run are the three dead-stripped ones above.
//!
//! Three functions here are `ftobjs.c`'s rather than `ftstream.c`'s —
//! [`ft_stream_new`], [`ft_stream_free`] and [`ft_stream_open`], the
//! create/destroy/attach trio the face loader calls. They are kept in
//! this module because they exist only to drive the stream object, and
//! `ft_stream_new`'s `mov r1, #40` is what pins `sizeof( FT_StreamRec )`
//! and therefore the `FtStream` layout below.
//!
//! Two independent cursors live in an `FtStream`, and the two reader
//! families use one each:
//!
//! - `pos`/`size` — the whole-file position. The `FT_Stream_Read*`
//!   family and the seek/skip/bulk-transfer functions use it, and they
//!   report failures through an `FT_Error` and the trace log.
//! - `cursor`/`limit` — a *frame*, the window `FT_Stream_EnterFrame`
//!   maps. The `FT_Stream_Get*` family reads out of that, bounds-tests
//!   by comparing pointers, and on overrun silently returns 0 without
//!   moving the cursor.
//!
//! A stream is either a *memory* stream — `read` is null and the whole
//! file is mapped at `base` — or a *disk* stream, whose `read` callback
//! is asked for every byte. Both flavors keep `pos` in the struct;
//! seeking a disk stream is a zero-length read at the target offset.
//!
//! # Deviations
//!
//! The trace/assert strings are re-created here as `static` byte
//! strings rather than pointing at the original `.rodata` copies
//! (0x0804fd50, 0x0804fc74, 0x0804fc8c, 0x0804f8c4, 0x0804f594,
//! 0x0804fb44/0x0804fb5c, 0x0804fa04/0x0804fa1c and the per-function
//! copies of `"assertion failed on line %d of file %s\n"`). The original
//! gives every reader its own copy of `" invalid i/o; pos = 0x%lx,
//! size = 0x%lx\n"`; the port shares one — the text is identical, only
//! the pointer identity differs. The `__FILE__` argument is the
//! ftstream.c path string the original passes by pointer (runtime
//! 0x089012e8); the port passes its own copy of the same text.

use crate::ft::error::{
    FT_ERR_INVALID_ARGUMENT, FT_ERR_INVALID_LIBRARY_HANDLE, FT_ERR_OK,
};
use crate::ft::memory::{ft_mem_alloc, ft_mem_free, ft_mem_qalloc, FtMemory};
use crate::ft::trace::{ft_error_trace, ft_panic};

pub use crate::ft::error::FT_ERR_INVALID_STREAM_OPERATION;

/// `FT_Stream_IoFunc` — `read(stream, offset, buffer, count)` returning
/// the number of bytes transferred. A seek is a call with a null buffer
/// and `count == 0`, whose non-zero return means "cannot seek there".
pub type FtStreamIoFunc = unsafe extern "C" fn(
    stream: *mut FtStream,
    offset: u32,
    buffer: *mut u8,
    count: u32,
) -> u32;

/// `FT_Stream_CloseFunc`.
pub type FtStreamCloseFunc = unsafe extern "C" fn(stream: *mut FtStream);

/// `FT_StreamRec` as this build lays it out: `base` @ +0, `size` @ +4,
/// `pos` @ +8, `descriptor` @ +12, `pathname` @ +16, `read` @ +20,
/// `close` @ +24, `memory` @ +28, `cursor` @ +32, `limit` @ +36 — every
/// one of the ten confirmed by the machine code, and the whole record
/// pinned to 40 bytes by [`ft_stream_new`]'s allocation.
#[repr(C)]
pub struct FtStream {
    pub base: *mut u8,
    pub size: u32,
    pub pos: u32,
    pub descriptor: *mut core::ffi::c_void,
    pub pathname: *mut core::ffi::c_void,
    pub read: Option<FtStreamIoFunc>,
    pub close: Option<FtStreamCloseFunc>,
    pub memory: *mut FtMemory,
    pub cursor: *mut u8,
    pub limit: *mut u8,
}

/// `sizeof( FT_StreamRec )` — the `mov r1, #40` [`ft_stream_new`] hands
/// the allocator. Checked on 32-bit targets, where the port's layout
/// must be the original's byte for byte.
#[cfg(target_pointer_width = "32")]
const _: () = assert!(core::mem::size_of::<FtStream>() == 40);

/// `FT_LibraryRec`'s first word. [`ft_stream_new`] reads `[library, #0]`
/// and nothing else, so only that field is modelled here.
#[repr(C)]
pub struct FtLibrary {
    pub memory: *mut FtMemory,
}

/// `FT_Open_Args` — how a caller describes the font to open. 32 bytes on
/// ARM; [`ft_stream_new`] reads `flags` @ +0, `memory_base` @ +4,
/// `memory_size` @ +8, `pathname` @ +12 and `stream` @ +16, which is the
/// whole dispatch.
#[repr(C)]
pub struct FtOpenArgs {
    pub flags: u32,
    pub memory_base: *const u8,
    pub memory_size: i32,
    pub pathname: *mut core::ffi::c_void,
    pub stream: *mut FtStream,
    pub driver: *mut core::ffi::c_void,
    pub num_params: i32,
    pub params: *mut core::ffi::c_void,
}

/// `FT_OPEN_MEMORY` — `tst r0, #1` @ 0x0804f2a8.
pub const FT_OPEN_MEMORY: u32 = 0x1;
/// `FT_OPEN_STREAM` — `tst r0, #2` @ 0x0804f2e4.
pub const FT_OPEN_STREAM: u32 = 0x2;
/// `FT_OPEN_PATHNAME` — `tst r0, #4` @ 0x0804f2c0.
pub const FT_OPEN_PATHNAME: u32 = 0x4;

/// Trace strings, byte-for-byte as they sit in the original image.
static SEEK_INVALID_IO: &[u8] = b"FT_Stream_Seek: invalid i/o; pos = 0x%lx, size = 0x%lx\n\0";
static READ_SHORT_TAG: &[u8] = b"FT_Stream_ReadShort:\0";
static INVALID_IO: &[u8] = b" invalid i/o; pos = 0x%lx, size = 0x%lx\n\0";
static READ_LONG_INVALID_IO: &[u8] =
    b"FT_Stream_ReadLong: invalid i/o; pos = 0x%lx, size = 0x%lx\n\0";
static READ_CHAR_INVALID_IO: &[u8] =
    b"FT_Stream_ReadChar: invalid i/o; pos = 0x%lx, size = 0x%lx\n\0";
static READ_OFFSET_TAG: &[u8] = b"FT_Stream_ReadOffset:\0";
static READ_LONG_LE_TAG: &[u8] = b"FT_Stream_ReadLongLE:\0";
static READ_AT_INVALID_IO: &[u8] =
    b"FT_Stream_ReadAt: invalid i/o; pos = 0x%lx, size = 0x%lx\n\0";
static READ_AT_TAG: &[u8] = b"FT_Stream_ReadAt:\0";
static INVALID_READ: &[u8] = b" invalid read; expected %lu bytes, got %lu\n\0";
static ENTER_FRAME_TAG: &[u8] = b"FT_Stream_EnterFrame:\0";
static ENTER_FRAME_INVALID_IO: &[u8] =
    b" invalid i/o; pos = 0x%lx, count = %lu, size = 0x%lx\n\0";

/// `FT_ASSERT`'s message and the `__FILE__` these two readers pass.
static ASSERTION_FAILED: &[u8] = b"assertion failed on line %d of file %s\n\0";
static FTSTREAM_C: &[u8] =
    b"c:\\BWA\\N25CFirmwareWin-75\\srcroot\\Firmware\\Silver\\3rdParty\\freetype\\src\\base\\ftstream.c\0";

/// `FT_ASSERT` `__LINE__` literals baked into each function, read out of
/// its literal pool or `moveq r1, #imm`.
const ASSERT_LINE_ENTER_FRAME: u32 = 235;
const ASSERT_LINE_EXIT_FRAME: u32 = 304;
const ASSERT_LINE_GET_CHAR: u32 = 328;
const ASSERT_LINE_GET_SHORT: u32 = 345;
const ASSERT_LINE_GET_SHORT_LE: u32 = 364;
const ASSERT_LINE_GET_LONG: u32 = 401;
const ASSERT_LINE_READ_CHAR: u32 = 437;
const ASSERT_LINE_READ_SHORT: u32 = 475;
const ASSERT_LINE_READ_OFFSET: u32 = 569;
const ASSERT_LINE_READ_LONG: u32 = 616;
const ASSERT_LINE_READ_LONG_LE: u32 = 662;

/// A failed `FT_ASSERT` in this file: every one of them passes the same
/// message and `__FILE__`, differing only in `__LINE__`. Diverges
/// through [`ft_panic`], exactly like the original, whose code after the
/// call is unreachable.
///
/// # Safety
/// Never returns.
#[inline]
unsafe fn assert_failed(line: u32) -> ! {
    ft_panic(
        ASSERTION_FAILED.as_ptr(),
        line,
        FTSTREAM_C.as_ptr() as usize as u32,
        0,
    )
}

/// The `FT_Stream_Get*` family's bounds test, `p + span < limit` — a
/// *pointer* comparison against `limit`, not the arithmetic `pos + n <
/// size` the `FT_Stream_Read*` family uses.
///
/// # Safety
/// `stream` must be valid with a non-null `cursor`.
#[inline]
unsafe fn frame_has(stream: *const FtStream, span: usize) -> bool {
    (*stream).cursor.add(span) < (*stream).limit
}

/// ft_stream_enter_frame (FreeType `FT_Stream_EnterFrame`) — original:
/// `FUN_0804edb0` @ 0x0804edb0 (308 bytes; 35 `bl` call sites).
///
/// Maps a `count`-byte window as the frame the whole `FT_Stream_Get*`
/// family then reads out of, and leaves `pos` just past it. The two
/// stream flavors get there differently:
///
/// - a **memory** stream points `cursor` straight into `base + pos`,
///   after checking `pos < size && pos + count <= size` (an unsigned,
///   *wrapping* add, so a `count` near 2^32 wraps and sails through —
///   quirk preserved and pinned by a test).
/// - a **disk** stream [`ft_mem_qalloc`]s a `count`-byte buffer into
///   `base` and reads the whole frame into it. Note `count` is an
///   `FT_ULong` handed to a signed `FT_Long` parameter, so a request of
///   2^31 or more is rejected as `FT_Err_Invalid_Argument` rather than
///   attempted.
///
/// A short read is reported (two trace calls) and the buffer is freed —
/// but `cursor`, `limit` and `pos` are still assigned afterwards, from
/// the *freed* `base`, which by then is null. That is upstream's own
/// fall-through, kept bug for bug: a failed `EnterFrame` leaves a null
/// `cursor` and a `limit` of `count`.
///
/// A null `stream`, or one whose `cursor` is already non-null (upstream's
/// "check for nested frame access"), hits the live `FT_ASSERT` and never
/// returns.
///
/// # Safety
/// `stream` must be null or valid, and its `memory` must be a usable
/// [`FtMemory`] whenever `read` is set.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ft_stream_enter_frame(stream: *mut FtStream, count: u32) -> i32 {
    if stream.is_null() || !(*stream).cursor.is_null() {
        assert_failed(ASSERT_LINE_ENTER_FRAME);
    }

    let mut error = FT_ERR_OK;

    if let Some(read) = (*stream).read {
        let memory = (*stream).memory;
        (*stream).base = ft_mem_qalloc(memory, count as i32, &mut error);
        if error != FT_ERR_OK {
            return error;
        }

        let read_bytes = read(stream, (*stream).pos, (*stream).base, count);
        if read_bytes < count {
            ft_error_trace(ENTER_FRAME_TAG.as_ptr(), 0, 0, 0);
            ft_error_trace(INVALID_READ.as_ptr(), count, read_bytes, 0);
            ft_mem_free(memory, (*stream).base);
            (*stream).base = core::ptr::null_mut();
            error = FT_ERR_INVALID_STREAM_OPERATION;
        }

        (*stream).cursor = (*stream).base;
        (*stream).limit = (*stream).cursor.wrapping_add(count as usize);
        (*stream).pos = (*stream).pos.wrapping_add(read_bytes);
    } else {
        let (pos, size) = ((*stream).pos, (*stream).size);
        if pos >= size || pos.wrapping_add(count) > size {
            ft_error_trace(ENTER_FRAME_TAG.as_ptr(), 0, 0, 0);
            ft_error_trace(ENTER_FRAME_INVALID_IO.as_ptr(), pos, count, size);
            return FT_ERR_INVALID_STREAM_OPERATION;
        }

        (*stream).cursor = (*stream).base.wrapping_add(pos as usize);
        (*stream).limit = (*stream).cursor.wrapping_add(count as usize);
        (*stream).pos = pos.wrapping_add(count);
    }

    error
}

/// ft_stream_exit_frame (FreeType `FT_Stream_ExitFrame`) — original:
/// `FUN_0804ef8c` @ 0x0804ef8c (68 bytes; 33 `bl` + 1 `b` call sites).
///
/// Releases what [`ft_stream_enter_frame`] mapped: a disk stream's frame
/// was heap-allocated, so `base` is freed and nulled (upstream's
/// `FT_FREE`); a memory stream's frame pointed into the file image and
/// is simply forgotten. `cursor` and `limit` are cleared either way,
/// which is what re-arms the nested-frame assert in `EnterFrame`.
///
/// A null `stream` hits the live `FT_ASSERT` and never returns.
///
/// # Safety
/// `stream` must be null or valid; a disk stream's `memory` must be the
/// allocator its `base` came from.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ft_stream_exit_frame(stream: *mut FtStream) {
    if stream.is_null() {
        assert_failed(ASSERT_LINE_EXIT_FRAME);
    }

    if (*stream).read.is_some() {
        ft_mem_free((*stream).memory, (*stream).base);
        (*stream).base = core::ptr::null_mut();
    }

    (*stream).cursor = core::ptr::null_mut();
    (*stream).limit = core::ptr::null_mut();
}

/// ft_stream_extract_frame (FreeType `FT_Stream_ExtractFrame`) —
/// original: `FUN_0804effc` @ 0x0804effc (44 bytes; 12 `bl` + 1 `b` call
/// sites).
///
/// [`ft_stream_enter_frame`] followed by handing the frame to the caller:
/// `*pbytes` takes the cursor and the stream forgets it. That is an
/// `ExitFrame` with the free left out — ownership of a disk stream's
/// buffer moves to the caller, who must give it back through
/// [`ft_stream_release_frame`]. `pbytes` is untouched when the enter
/// fails.
///
/// # Safety
/// As [`ft_stream_enter_frame`]; `pbytes` must be a valid pointer slot.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ft_stream_extract_frame(
    stream: *mut FtStream,
    count: u32,
    pbytes: *mut *mut u8,
) -> i32 {
    let error = ft_stream_enter_frame(stream, count);
    if error == FT_ERR_OK {
        *pbytes = (*stream).cursor;
        (*stream).cursor = core::ptr::null_mut();
        (*stream).limit = core::ptr::null_mut();
    }
    error
}

/// ft_stream_release_frame (FreeType `FT_Stream_ReleaseFrame`) —
/// original: `FUN_0804fcb8` @ 0x0804fcb8 (48 bytes; 19 `bl` + 1 `b` call
/// sites).
///
/// Gives back what [`ft_stream_extract_frame`] handed out: a disk
/// stream's block goes to the allocator, a memory stream's "block" was
/// never allocated and is only forgotten. `*pbytes` is nulled either
/// way — twice in the original (`str r5, [r4]` at 0x0804fcdc and again
/// at 0x0804fce0), because upstream writes `FT_FREE( *pbytes )`, whose
/// macro already nulls it, and then `*pbytes = NULL` again.
///
/// Unlike its siblings this one has no `FT_ASSERT` on `stream` — the
/// pre-2.4 body.
///
/// # Safety
/// `stream` must be valid; `pbytes` must be a valid pointer slot whose
/// block, for a disk stream, came from `stream->memory`.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ft_stream_release_frame(stream: *mut FtStream, pbytes: *mut *mut u8) {
    if (*stream).read.is_some() {
        ft_mem_free((*stream).memory, *pbytes);
    }
    *pbytes = core::ptr::null_mut();
}

/// `FT_Frame_Field` — one row of a frame-description table. 4 bytes on
/// ARM (`add r4, r4, #4` walks it): `value` @ +0, `size` @ +1,
/// `offset` @ +2.
#[repr(C)]
pub struct FtFrameField {
    /// One of the `FT_FRAME_*` opcodes below.
    pub value: u8,
    /// Width of the destination field in bytes (1, 2 or 4), or the byte
    /// count for [`FT_FRAME_BYTES`]/[`FT_FRAME_SKIP`].
    pub size: u8,
    /// Byte offset of the destination field inside `structure` — or, for
    /// [`FT_FRAME_START`], the frame length to enter.
    pub offset: u16,
}

/// `FT_FRAME_OP_SIGNED` — bit 0 of an opcode, tested by `tst r0, #1`
/// @ 0x0804f794. Upstream builds every opcode as
/// `command << 2 | little << 1 | signed`.
pub const FT_FRAME_OP_SIGNED: u8 = 1;

/// `ft_frame_end` — and, with it, every opcode the original's jump table
/// does not list (1..3, 5..7, 10, 11 and anything above 25): they all
/// land on the `default:` arm, which writes the cursor back and returns
/// the error so far.
pub const FT_FRAME_END: u8 = 0;
/// `ft_frame_start` — enter a frame of `offset` bytes.
pub const FT_FRAME_START: u8 = 4;
/// `ft_frame_byte` / `ft_frame_schar`.
pub const FT_FRAME_BYTE: u8 = 8;
pub const FT_FRAME_SCHAR: u8 = 9;
/// `ft_frame_ushort_be` / `short_be` / `ushort_le` / `short_le`.
pub const FT_FRAME_USHORT_BE: u8 = 12;
pub const FT_FRAME_SHORT_BE: u8 = 13;
pub const FT_FRAME_USHORT_LE: u8 = 14;
pub const FT_FRAME_SHORT_LE: u8 = 15;
/// `ft_frame_ulong_be` / `long_be` / `ulong_le` / `long_le`.
pub const FT_FRAME_ULONG_BE: u8 = 16;
pub const FT_FRAME_LONG_BE: u8 = 17;
pub const FT_FRAME_ULONG_LE: u8 = 18;
pub const FT_FRAME_LONG_LE: u8 = 19;
/// `ft_frame_uoff3_be` / `off3_be` / `uoff3_le` / `off3_le`.
pub const FT_FRAME_UOFF3_BE: u8 = 20;
pub const FT_FRAME_OFF3_BE: u8 = 21;
pub const FT_FRAME_UOFF3_LE: u8 = 22;
pub const FT_FRAME_OFF3_LE: u8 = 23;
/// `ft_frame_bytes` — copy `size` bytes into the structure.
pub const FT_FRAME_BYTES: u8 = 24;
/// `ft_frame_skip` — advance the cursor by `size` bytes.
pub const FT_FRAME_SKIP: u8 = 25;

/// ft_stream_read_fields (FreeType `FT_Stream_ReadFields`) — original:
/// `FUN_0804f5d0` @ 0x0804f5d0 (508 bytes; 21 `bl` + 1 `b` call sites).
///
/// The table-driven struct loader the sfnt/truetype/type1 drivers use
/// instead of hand-rolling reads: it walks `fields`, decoding one value
/// per row out of the frame cursor and storing it at
/// `structure + offset`. Rows may also open a frame
/// ([`FT_FRAME_START`], which makes the function responsible for the
/// matching [`ft_stream_exit_frame`]), copy a run of raw bytes
/// ([`FT_FRAME_BYTES`]) or skip one ([`FT_FRAME_SKIP`]).
///
/// The opcode encoding is upstream's `command << 2 | little << 1 |
/// signed`, and the original's jump table over 4..=25 is the
/// independent confirmation of that: `ft_frame_start` is 4,
/// `ft_frame_byte`/`schar` 8/9, the shorts 12..15, the longs 16..19, the
/// 3-byte offsets 20..23 and bytes/skip 24/25 — with 5..7 and 10..11
/// deliberately absent, since those bit patterns name no opcode. Every
/// value is read unsigned and then sign-extended by shifting left and
/// arithmetic-shifting back by 24/16/8/0, so the signed and unsigned
/// variants share one decoder.
///
/// Two exits, and they differ: the `default:` arm (which is where
/// `ft_frame_end` lands) writes the cursor back into the stream before
/// leaving, while both *error* exits — a failed `FT_FRAME_START` and a
/// [`FT_FRAME_BYTES`] run that would pass `limit` — leave `cursor`
/// exactly as the last successful `EnterFrame` left it. Either way a
/// frame this call opened is closed on the way out.
///
/// # Deviations
///
/// The original loads `stream->cursor` *before* testing its arguments
/// (`ldr r1, [r0, #32]` @ 0x0804f5e0 sits above the `bne`), so a null
/// `stream` reads address 0x20 and throws the result away; the port
/// checks first. `FT_MEM_COPY` is the misalignment-capable ADS forward
/// copy at 0x08000020 (through the iRAM veneer at 0x08037db0); the port
/// uses [`memmove`](crate::libc::memmove::memmove), which reproduces it
/// and additionally tolerates overlap the original does not need. The
/// stores are `strb`/`strh`/`str` in the original and unaligned writes
/// here, which agree whenever the original does not fault.
///
/// # Safety
/// `stream` and `fields` must be null or valid; `fields` must end in a
/// row whose opcode is not one of the listed ones (`FT_FRAME_END`);
/// `structure` must have room for every row's `offset`/`size`; and the
/// frame must cover every value the table reads — only the
/// `FT_FRAME_BYTES`/`FT_FRAME_SKIP` rows are bounds-checked.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ft_stream_read_fields(
    stream: *mut FtStream,
    fields: *const FtFrameField,
    structure: *mut u8,
) -> i32 {
    if fields.is_null() || stream.is_null() {
        return FT_ERR_INVALID_ARGUMENT;
    }

    let mut fields = fields;
    let mut cursor = (*stream).cursor;
    let mut error = FT_ERR_OK;
    let mut frame_accessed = false;

    loop {
        let op = (*fields).value;

        // `value` is always accumulated unsigned; `sign_shift` says how
        // far to shift it left and arithmetically back for the signed
        // variants.
        let (value, sign_shift): (u32, u32) = match op {
            FT_FRAME_START => {
                error = ft_stream_enter_frame(stream, (*fields).offset as u32);
                if error != FT_ERR_OK {
                    break;
                }
                frame_accessed = true;
                cursor = (*stream).cursor;
                fields = fields.add(1);
                continue;
            }

            FT_FRAME_BYTES | FT_FRAME_SKIP => {
                let len = (*fields).size as usize;
                if cursor.wrapping_add(len) > (*stream).limit {
                    error = FT_ERR_INVALID_STREAM_OPERATION;
                    break;
                }
                if op == FT_FRAME_BYTES {
                    crate::libc::memmove::memmove(
                        structure.wrapping_add((*fields).offset as usize),
                        cursor,
                        len,
                    );
                }
                cursor = cursor.wrapping_add(len);
                fields = fields.add(1);
                continue;
            }

            FT_FRAME_BYTE | FT_FRAME_SCHAR => {
                let value = *cursor as u32;
                cursor = cursor.wrapping_add(1);
                (value, 24)
            }

            FT_FRAME_USHORT_BE | FT_FRAME_SHORT_BE => {
                let value = ((*cursor as u32) << 8) | *cursor.add(1) as u32;
                cursor = cursor.wrapping_add(2);
                (value, 16)
            }
            FT_FRAME_USHORT_LE | FT_FRAME_SHORT_LE => {
                let value = (*cursor as u32) | ((*cursor.add(1) as u32) << 8);
                cursor = cursor.wrapping_add(2);
                (value, 16)
            }

            FT_FRAME_ULONG_BE | FT_FRAME_LONG_BE => {
                let value = ((*cursor as u32) << 24)
                    | ((*cursor.add(1) as u32) << 16)
                    | ((*cursor.add(2) as u32) << 8)
                    | *cursor.add(3) as u32;
                cursor = cursor.wrapping_add(4);
                (value, 0)
            }
            FT_FRAME_ULONG_LE | FT_FRAME_LONG_LE => {
                let value = (*cursor as u32)
                    | ((*cursor.add(1) as u32) << 8)
                    | ((*cursor.add(2) as u32) << 16)
                    | ((*cursor.add(3) as u32) << 24);
                cursor = cursor.wrapping_add(4);
                (value, 0)
            }

            FT_FRAME_UOFF3_BE | FT_FRAME_OFF3_BE => {
                let value = ((*cursor as u32) << 16)
                    | ((*cursor.add(1) as u32) << 8)
                    | *cursor.add(2) as u32;
                cursor = cursor.wrapping_add(3);
                (value, 8)
            }
            FT_FRAME_UOFF3_LE | FT_FRAME_OFF3_LE => {
                let value = (*cursor as u32)
                    | ((*cursor.add(1) as u32) << 8)
                    | ((*cursor.add(2) as u32) << 16);
                cursor = cursor.wrapping_add(3);
                (value, 8)
            }

            _ => {
                (*stream).cursor = cursor;
                break;
            }
        };

        let value = if op & FT_FRAME_OP_SIGNED != 0 {
            (((value << sign_shift) as i32) >> sign_shift) as u32
        } else {
            value
        };

        let field = structure.wrapping_add((*fields).offset as usize);
        match (*fields).size {
            1 => field.write_unaligned(value as u8),
            2 => field.cast::<u16>().write_unaligned(value as u16),
            // Upstream's `default:` — a full `FT_ULong`, one word here.
            _ => field.cast::<u32>().write_unaligned(value),
        }

        fields = fields.add(1);
    }

    if frame_accessed {
        ft_stream_exit_frame(stream);
    }

    error
}

/// ft_stream_get_char (FreeType `FT_Stream_GetChar`) — original:
/// `FUN_0804f05c` @ 0x0804f05c (64 bytes; 13 call sites).
///
/// The `FT_Stream_Get*` family reads out of the *frame* a preceding
/// `FT_Stream_EnterFrame` mapped — `cursor`/`limit`, not `pos`/`size` —
/// and reports nothing when it runs off the end: the result is simply 0
/// and the cursor does not move. Every one of them asserts
/// `stream && stream->cursor`.
///
/// This one takes a byte and sign-extends it (`ldrsbcc`), like
/// [`ft_stream_read_char`].
///
/// # Safety
/// `stream` must be null or valid; `cursor`/`limit` must delimit a
/// readable frame.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ft_stream_get_char(stream: *mut FtStream) -> i32 {
    if stream.is_null() || (*stream).cursor.is_null() {
        assert_failed(ASSERT_LINE_GET_CHAR);
    }
    if !frame_has(stream, 0) {
        return 0;
    }
    let p = (*stream).cursor;
    (*stream).cursor = p.add(1);
    *p as i8 as i32
}

/// ft_stream_get_short (FreeType `FT_Stream_GetShort`) — original:
/// `FUN_0804f15c` @ 0x0804f15c (76 bytes; 50 call sites, the busiest
/// function in ftstream.c).
///
/// `FT_NEXT_SHORT`: signed big-endian 16-bit, `(i8)p[0] << 8 | p[1]`,
/// with the frame test `p + 1 < limit`. See [`ft_stream_get_char`] for
/// the family's shape.
///
/// # Safety
/// As [`ft_stream_get_char`].
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ft_stream_get_short(stream: *mut FtStream) -> i32 {
    if stream.is_null() || (*stream).cursor.is_null() {
        assert_failed(ASSERT_LINE_GET_SHORT);
    }
    if !frame_has(stream, 1) {
        return 0;
    }
    let p = (*stream).cursor;
    (*stream).cursor = p.add(2);
    ((*p as i8 as i32) << 8) | (*p.add(1) as i32)
}

/// ft_stream_get_short_le (FreeType `FT_Stream_GetShortLE`) — original:
/// `FUN_0804f1d8` @ 0x0804f1d8 (76 bytes; 5 call sites).
///
/// `FT_NEXT_SHORT_LE`: signed *little*-endian 16-bit,
/// `(i8)p[1] << 8 | p[0]` — the `ldrsb` moves to the second byte, which
/// is the only difference from [`ft_stream_get_short`].
///
/// # Safety
/// As [`ft_stream_get_char`].
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ft_stream_get_short_le(stream: *mut FtStream) -> i32 {
    if stream.is_null() || (*stream).cursor.is_null() {
        assert_failed(ASSERT_LINE_GET_SHORT_LE);
    }
    if !frame_has(stream, 1) {
        return 0;
    }
    let p = (*stream).cursor;
    (*stream).cursor = p.add(2);
    ((*p.add(1) as i8 as i32) << 8) | (*p as i32)
}

/// ft_stream_get_long (FreeType `FT_Stream_GetLong`) — original:
/// `FUN_0804f0c8` @ 0x0804f0c8 (100 bytes; 10 call sites).
///
/// `FT_NEXT_LONG`: big-endian 32-bit (all `ldrb`, so identical to
/// `FT_NEXT_ULONG` at this width), frame test `p + 3 < limit`.
///
/// # Safety
/// As [`ft_stream_get_char`].
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ft_stream_get_long(stream: *mut FtStream) -> i32 {
    if stream.is_null() || (*stream).cursor.is_null() {
        assert_failed(ASSERT_LINE_GET_LONG);
    }
    if !frame_has(stream, 3) {
        return 0;
    }
    let p = (*stream).cursor;
    (*stream).cursor = p.add(4);
    (((*p as u32) << 24)
        | ((*p.add(1) as u32) << 16)
        | ((*p.add(2) as u32) << 8)
        | (*p.add(3) as u32)) as i32
}

/// ft_stream_open_memory (FreeType `FT_Stream_OpenMemory`) — original:
/// `FUN_0804f354` @ 0x0804f354 (28 bytes; 3 call sites).
///
/// Points a stream at an in-memory image: `base`/`size` (stored together
/// by one `stm r0, {r1, r2}`), then zeroes `pos`, `cursor`, `read` and
/// `close` — that field set, in that order, is upstream's function body
/// verbatim and is the independent confirmation of the `FtStream`
/// layout the readers were reverse-engineered against. `limit` is
/// deliberately left alone, as upstream leaves it.
///
/// # Safety
/// `stream` must be a valid `FtStream` pointer (the original does not
/// null-check it); `base` must be valid for `size` bytes.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ft_stream_open_memory(
    stream: *mut FtStream,
    base: *const u8,
    size: u32,
) {
    (*stream).base = base as *mut u8;
    (*stream).size = size;
    (*stream).pos = 0;
    (*stream).cursor = core::ptr::null_mut();
    (*stream).read = None;
    (*stream).close = None;
}

/// ft_stream_close (FreeType `FT_Stream_Close`) — original:
/// `FUN_0804ed9c` @ 0x0804ed9c (20 bytes; 4 call sites).
///
/// `if ( stream && stream->close ) stream->close( stream )` — a tail
/// `bxne r1` with `stream` still in `r0`. The pre-2.4 body: it does not
/// clear `close`, `base` or `size` afterwards, so calling it twice calls
/// the callback twice.
///
/// # Safety
/// `stream` must be null or valid, and its `close` callback must be
/// safe to invoke.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ft_stream_close(stream: *mut FtStream) {
    if stream.is_null() {
        return;
    }
    if let Some(close) = (*stream).close {
        close(stream);
    }
}

/// ft_stream_new (FreeType `FT_Stream_New`, ftobjs.c) — original:
/// `FUN_0804f250` @ 0x0804f250 (232 bytes; 3 `bl` call sites).
///
/// Allocates an `FT_StreamRec` from the library's allocator and points
/// it at whatever `args` describes, dispatching on `args->flags`:
///
/// - [`FT_OPEN_MEMORY`] — [`ft_stream_open_memory`] over
///   `memory_base`/`memory_size`.
/// - [`FT_OPEN_PATHNAME`] — [`ft_stream_open`], then `pathname` is
///   recorded in the stream *whether or not the open succeeded*.
/// - [`FT_OPEN_STREAM`] with a non-null `args->stream` — the fresh
///   allocation is thrown away again and the caller's stream adopted.
/// - anything else — `FT_Err_Invalid_Argument`.
///
/// On any failure the stream is freed and `*astream` set to null; on
/// success `memory` is re-stamped into the stream (upstream's "just to
/// be certain", which matters for the adopted-stream case) and the
/// stream handed back.
///
/// Note the two argument checks run *before* `*astream` is cleared, so a
/// null `library` or `args` leaves the caller's handle untouched — the
/// one place this build's source differs from the upstream text, which
/// clears it first.
///
/// The `mov r1, #40` here is `sizeof( FT_StreamRec )`; the port asks for
/// `size_of::<FtStream>()`, which is that same 40 on the target.
///
/// # Safety
/// `library`, `args` and `astream` must be null or valid; the library's
/// `memory` must be a usable [`FtMemory`].
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ft_stream_new(
    library: *mut FtLibrary,
    args: *const FtOpenArgs,
    astream: *mut *mut FtStream,
) -> i32 {
    if library.is_null() {
        return FT_ERR_INVALID_LIBRARY_HANDLE;
    }
    if args.is_null() {
        return FT_ERR_INVALID_ARGUMENT;
    }

    *astream = core::ptr::null_mut();

    let memory = (*library).memory;
    let mut error = FT_ERR_OK;
    let mut stream =
        ft_mem_alloc(memory, core::mem::size_of::<FtStream>() as i32, &mut error) as *mut FtStream;
    if error != FT_ERR_OK {
        return error;
    }

    (*stream).memory = memory;

    let flags = (*args).flags;
    if flags & FT_OPEN_MEMORY != 0 {
        ft_stream_open_memory(stream, (*args).memory_base, (*args).memory_size as u32);
    } else if flags & FT_OPEN_PATHNAME != 0 {
        error = ft_stream_open(stream, (*args).pathname as *const u8);
        (*stream).pathname = (*args).pathname;
    } else if flags & FT_OPEN_STREAM != 0 && !(*args).stream.is_null() {
        ft_mem_free(memory, stream as *mut u8);
        stream = (*args).stream;
    } else {
        error = FT_ERR_INVALID_ARGUMENT;
    }

    if error == FT_ERR_OK {
        (*stream).memory = memory;
    } else {
        ft_mem_free(memory, stream as *mut u8);
        stream = core::ptr::null_mut();
    }

    *astream = stream;
    error
}

/// ft_stream_free (FreeType `FT_Stream_Free`, ftobjs.c) — original:
/// `FUN_0804f028` @ 0x0804f028 (52 bytes; 3 `bl` call sites).
///
/// Closes the stream and, unless the caller owns it (`external`),
/// returns the record itself to the allocator — a tail branch into
/// [`ft_mem_free`] with `memory` snapshotted *before* the close, since
/// the close callback may scrub the record.
///
/// # Safety
/// `stream` must be null or valid; its `memory` must be the allocator it
/// came from when `external` is 0.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ft_stream_free(stream: *mut FtStream, external: i32) {
    if stream.is_null() {
        return;
    }

    let memory = (*stream).memory;
    ft_stream_close(stream);

    if external == 0 {
        ft_mem_free(memory, stream as *mut u8);
    }
}

/// ft_stream_pos (FreeType `FT_Stream_Pos`) — original: `FUN_0804f370`
/// @ 0x0804f370 (8 bytes: `ldr r0, [r0, #8]`, `bx lr`; 17 call sites).
///
/// `return stream->pos`.
///
/// # Safety
/// `stream` must be a valid `FtStream` pointer.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ft_stream_pos(stream: *const FtStream) -> u32 {
    (*stream).pos
}

/// ft_stream_open (FreeType `FT_Stream_Open`, the ftsystem.c hook) —
/// original: `FUN_0804f338` @ 0x0804f338 (28 bytes; 1 `bl` call site,
/// [`ft_stream_new`]).
///
/// Hands `(stream, pathname)` to the firmware's file layer
/// ([`ft_platform_stream_open`](crate::ft::system::ft_platform_stream_open)
/// @ 0x082d3ddc) and flattens its answer to FreeType's vocabulary: any
/// non-zero status becomes `FT_Err_Cannot_Open_Resource`, so the several
/// distinct firmware failures all reach FreeType as the same "no".
///
/// # Safety
/// `stream` must be a valid `FtStream`; `pathname` must be a
/// NUL-terminated path the platform layer accepts.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ft_stream_open(stream: *mut FtStream, pathname: *const u8) -> i32 {
    if crate::ft::system::ft_platform_stream_open(stream, pathname) != 0 {
        crate::ft::error::FT_ERR_CANNOT_OPEN_RESOURCE
    } else {
        FT_ERR_OK
    }
}

/// ft_stream_read_at (FreeType `FT_Stream_ReadAt`) — original:
/// `FUN_0804f38c` @ 0x0804f38c (176 bytes; 1 `bl` + 1 `b` call site,
/// plus the fall-through from [`ft_stream_read`]).
///
/// Copies `count` bytes from `pos` into `buffer` and leaves `pos +
/// transferred` in the stream. Two distinct failures, and only the first
/// is fatal:
///
/// - `pos >= size` returns [`FT_ERR_INVALID_STREAM_OPERATION`]
///   immediately, before anything is read or `pos` is touched. Note this
///   test runs even for a disk stream, unlike the seek's.
/// - a **short** transfer still updates `pos` and still returns the
///   bytes it got; it merely also reports the shortfall and returns the
///   error. A memory stream clamps `count` to `size - pos` and so short-
///   reads by construction near the end of the file.
///
/// The first failure traces once (this build merged upstream's two
/// `FT_ERROR`s, as it did for `FT_Stream_Seek`); the short-read failure
/// kept both.
///
/// # Safety
/// `stream` must be valid; `buffer` must have room for `count` bytes; a
/// memory stream's `base` must cover `pos + count`.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ft_stream_read_at(
    stream: *mut FtStream,
    pos: u32,
    buffer: *mut u8,
    count: u32,
) -> i32 {
    let size = (*stream).size;
    if pos >= size {
        ft_error_trace(READ_AT_INVALID_IO.as_ptr(), pos, size, 0);
        return FT_ERR_INVALID_STREAM_OPERATION;
    }
    let transferred = match (*stream).read {
        Some(read) => read(stream, pos, buffer, count),
        None => {
            let available = (size - pos).min(count);
            crate::libc::memcpy::memcpy_forward_words(buffer,
            (*stream).base.add(pos as usize),
            available as usize,);
            available
        }
    };
    (*stream).pos = pos.wrapping_add(transferred);
    if transferred < count {
        ft_error_trace(READ_AT_TAG.as_ptr(), 0, 0, 0);
        ft_error_trace(INVALID_READ.as_ptr(), count, transferred, 0);
        return FT_ERR_INVALID_STREAM_OPERATION;
    }
    0
}

/// ft_stream_read (FreeType `FT_Stream_Read`) — original: `FUN_0804f378`
/// @ 0x0804f378 (20 bytes; 15 call sites).
///
/// `ft_stream_read_at(stream, stream->pos, buffer, count)` — a register
/// shuffle and a `nop` that falls straight through into
/// [`ft_stream_read_at`], which the linker placed immediately after.
///
/// # Safety
/// As [`ft_stream_read_at`].
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ft_stream_read(
    stream: *mut FtStream,
    buffer: *mut u8,
    count: u32,
) -> i32 {
    ft_stream_read_at(stream, (*stream).pos, buffer, count)
}

/// ft_stream_try_read (FreeType `FT_Stream_TryRead`) — original:
/// `FUN_0804fd94` @ 0x0804fd94 (116 bytes; 1 call site).
///
/// [`ft_stream_read_at`]'s forgiving twin: reads at the *current* `pos`,
/// returns however many bytes it actually got and never traces or
/// reports an error. `pos >= size` yields 0 with `pos` untouched;
/// otherwise a memory stream clamps to `size - pos` and `pos` advances
/// by the transferred count. Note the original re-loads `pos` from the
/// struct for that final add (`ldr`/`add`/`str` @ 0x0804fdf4), so a
/// `read` callback that moved `pos` itself compounds with the advance —
/// where [`ft_stream_read_at`] instead adds to the `pos` it was handed.
///
/// # Safety
/// As [`ft_stream_read_at`].
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ft_stream_try_read(
    stream: *mut FtStream,
    buffer: *mut u8,
    count: u32,
) -> u32 {
    let (pos, size) = ((*stream).pos, (*stream).size);
    if pos >= size {
        return 0;
    }
    let transferred = match (*stream).read {
        Some(read) => read(stream, pos, buffer, count),
        None => {
            let available = (size - pos).min(count);
            crate::libc::memcpy::memcpy_forward_words(buffer,
            (*stream).base.add(pos as usize),
            available as usize,);
            available
        }
    };
    (*stream).pos = (*stream).pos.wrapping_add(transferred);
    transferred
}

/// ft_stream_seek (FreeType `FT_Stream_Seek`) — original:
/// `FUN_0804fce8` @ 0x0804fce8 (104 bytes; 65 `bl` + 2 `b` call sites,
/// one of the `b`s being [`ft_stream_skip`]).
///
/// Stores `pos` unconditionally, then validates it: a disk stream asks
/// its `read` callback for a zero-length read at `pos` and fails when
/// that returns non-zero; a memory stream simply requires
/// `pos <= size` — seeking to the first position *past* the last byte is
/// deliberately legal. Failure traces
/// `"FT_Stream_Seek: invalid i/o; ..."` (a single call in this build,
/// where upstream emits two) and returns
/// [`FT_ERR_INVALID_STREAM_OPERATION`]; success returns 0. Note `pos`
/// keeps the out-of-range value either way.
///
/// # Safety
/// `stream` must be a valid `FtStream` pointer (the original does not
/// null-check it).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ft_stream_seek(stream: *mut FtStream, pos: u32) -> i32 {
    (*stream).pos = pos;
    let failed = match (*stream).read {
        Some(read) => read(stream, pos, core::ptr::null_mut(), 0) != 0,
        None => pos > (*stream).size,
    };
    if failed {
        ft_error_trace(SEEK_INVALID_IO.as_ptr(), pos, (*stream).size, 0);
        return FT_ERR_INVALID_STREAM_OPERATION;
    }
    0
}

/// ft_stream_skip (FreeType `FT_Stream_Skip`) — original: `FUN_0804fd88`
/// @ 0x0804fd88 (12 bytes: `ldr`, `add`, `b`; 12 call sites).
///
/// `ft_stream_seek(stream, pos + distance)` with a wrapping add — this
/// pre-2.4 version has no `distance < 0` rejection, so a negative
/// distance seeks backwards (and underflows past 0 into a huge `u32`,
/// which the seek then rejects).
///
/// # Safety
/// As [`ft_stream_seek`].
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ft_stream_skip(stream: *mut FtStream, distance: i32) -> i32 {
    ft_stream_seek(stream, (*stream).pos.wrapping_add(distance as u32))
}

/// Fetches `count` bytes at `pos` for the two readers: memory streams
/// hand back `base + pos` directly, disk streams read into `buffer` and
/// must transfer exactly `count`. `None` means the read callback came up
/// short — the readers' `Fail` label.
///
/// # Safety
/// `stream` must be valid and `buffer` must have room for `count` bytes.
#[inline]
unsafe fn stream_frame(
    stream: *mut FtStream,
    pos: u32,
    buffer: *mut u8,
    count: u32,
) -> Option<*const u8> {
    match (*stream).read {
        None => Some((*stream).base.wrapping_add(pos as usize) as *const u8),
        Some(read) => {
            if read(stream, pos, buffer, count) != count {
                None
            } else {
                Some(buffer as *const u8)
            }
        }
    }
}

/// ft_stream_read_char (FreeType `FT_Stream_ReadChar`) — original:
/// `FUN_0804f4b8` @ 0x0804f4b8 (172 bytes; 11 call sites).
///
/// Reads one byte at `pos`, advances `pos` by 1 and returns it
/// **sign-extended** (`lsl #24` / `asr #24` on the way out — upstream's
/// `return (FT_Char)result`).
///
/// Unlike its wider siblings this one has no shared bounds test: the
/// memory path checks `pos < size` itself, and the disk path checks
/// *nothing* — a `read` callback that hands back its one byte is
/// believed even past `size`. That asymmetry is upstream's, and it is
/// what distinguishes `FT_Stream_ReadChar` from every other reader in
/// the file.
///
/// On failure `*error` becomes [`FT_ERR_INVALID_STREAM_OPERATION`], a
/// single trace call fires (this build merged upstream's two `FT_ERROR`s
/// into one string, as it did for `FT_Stream_Seek`) and the result is 0
/// with `pos` unchanged.
///
/// A null `stream` hits the live `FT_ASSERT` and never returns.
///
/// # Safety
/// `stream` must be null or valid; `error` must be a valid `i32`
/// pointer; a memory stream's `base` must cover `pos`.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ft_stream_read_char(stream: *mut FtStream, error: *mut i32) -> i32 {
    if stream.is_null() {
        assert_failed(ASSERT_LINE_READ_CHAR);
    }
    *error = 0;
    let mut result = 0u8;
    let pos = (*stream).pos;
    let ok = match (*stream).read {
        Some(read) => read(stream, pos, &mut result, 1) == 1,
        None => {
            if pos < (*stream).size {
                result = *(*stream).base.add(pos as usize);
                true
            } else {
                false
            }
        }
    };
    if ok {
        (*stream).pos = (*stream).pos.wrapping_add(1);
        return result as i8 as i32;
    }
    *error = FT_ERR_INVALID_STREAM_OPERATION;
    ft_error_trace(
        READ_CHAR_INVALID_IO.as_ptr(),
        (*stream).pos,
        (*stream).size,
        0,
    );
    0
}

/// ft_stream_read_short (FreeType `FT_Stream_ReadShort`) — original:
/// `FUN_0804fb88` @ 0x0804fb88 (188 bytes; 17 call sites).
///
/// Reads a big-endian 16-bit value at `pos` and advances `pos` by 2,
/// clearing `*error` first. The result is **sign-extended**: the
/// original's `ldrsb` on the high byte (`p[1] | (p[0] as i8) << 8`) is
/// what identifies this as `FT_Stream_ReadShort` rather than the
/// `ReadUShort` sibling — its trace tag says `"FT_Stream_ReadShort:"`
/// too. Upstream returns `FT_Short`; the port returns the sign-extended
/// word the original leaves in r0.
///
/// The bounds test is upstream's `pos + 1 < size` — unsigned, and with
/// a *wrapping* add, so a `pos` of `0xffffffff` wraps to 0 and sails
/// through it (quirk preserved and pinned by a test). On failure
/// `*error` becomes
/// [`FT_ERR_INVALID_STREAM_OPERATION`], two trace calls fire (tag, then
/// the `pos`/`size` detail — this reader kept both `FT_ERROR`s) and the
/// result is 0 with `pos` unchanged.
///
/// A null `stream` hits the live `FT_ASSERT` and never returns.
///
/// # Safety
/// `stream` must be null or valid; `error` must be a valid `i32`
/// pointer; a memory stream's `base` must cover `pos + 2`.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ft_stream_read_short(stream: *mut FtStream, error: *mut i32) -> i32 {
    if stream.is_null() {
        assert_failed(ASSERT_LINE_READ_SHORT);
    }
    *error = 0;
    let pos = (*stream).pos;
    let mut reads = [0u8; 2];
    if pos.wrapping_add(1) < (*stream).size {
        if let Some(p) = stream_frame(stream, pos, reads.as_mut_ptr(), 2) {
            // The original still advances `pos` when `p` is null.
            let result = if p.is_null() {
                0
            } else {
                (*p.add(1) as i32) | ((*p as i8 as i32) << 8)
            };
            (*stream).pos = (*stream).pos.wrapping_add(2);
            return result;
        }
    }
    *error = FT_ERR_INVALID_STREAM_OPERATION;
    ft_error_trace(READ_SHORT_TAG.as_ptr(), 0, 0, 0);
    ft_error_trace(INVALID_IO.as_ptr(), (*stream).pos, (*stream).size, 0);
    0
}

/// ft_stream_read_offset (FreeType `FT_Stream_ReadOffset`) — original:
/// `FUN_0804fa48` @ 0x0804fa48 (204 bytes; 1 call site, 0x080a32c4 in
/// the CFF/Type1 index parser cluster).
///
/// The 3-byte sibling of [`ft_stream_read_short`], reading upstream's
/// `FT_NEXT_OFF3`: a **signed** big-endian 24-bit offset,
/// `((i8)p[0] << 16) | (p[1] << 8) | p[2]` — the `ldrsb` on the top byte
/// @ 0x0804fac0 is what makes it `OFF3` rather than `UOFF3`. Bounds test
/// `pos + 2 < size` with the same wrapping add as its siblings, `pos`
/// advanced by 3.
///
/// Failure sets `*error` first, then emits two trace calls (tag, then
/// the `pos`/`size` detail), like [`ft_stream_read_short`].
///
/// A null `stream` hits the live `FT_ASSERT` and never returns.
///
/// # Safety
/// As [`ft_stream_read_short`], with `base` covering `pos + 3`.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ft_stream_read_offset(stream: *mut FtStream, error: *mut i32) -> i32 {
    if stream.is_null() {
        assert_failed(ASSERT_LINE_READ_OFFSET);
    }
    *error = 0;
    let pos = (*stream).pos;
    let mut reads = [0u8; 3];
    if pos.wrapping_add(2) < (*stream).size {
        if let Some(p) = stream_frame(stream, pos, reads.as_mut_ptr(), 3) {
            let result = if p.is_null() {
                0
            } else {
                ((*p as i8 as i32) << 16) | ((*p.add(1) as i32) << 8) | (*p.add(2) as i32)
            };
            (*stream).pos = (*stream).pos.wrapping_add(3);
            return result;
        }
    }
    *error = FT_ERR_INVALID_STREAM_OPERATION;
    ft_error_trace(READ_OFFSET_TAG.as_ptr(), 0, 0, 0);
    ft_error_trace(INVALID_IO.as_ptr(), (*stream).pos, (*stream).size, 0);
    0
}

/// ft_stream_read_long (FreeType `FT_Stream_ReadLong`) — original:
/// `FUN_0804f7cc` @ 0x0804f7cc (204 bytes; 13 call sites).
///
/// The 32-bit sibling of [`ft_stream_read_short`]: big-endian
/// `p[0]<<24 | p[1]<<16 | p[2]<<8 | p[3]` (all `ldrb`, so the byte
/// assembly is identical to `FT_Stream_ReadULong` — the trace tag
/// `"FT_Stream_ReadLong:"` is what names it), bounds test
/// `pos + 3 < size` with the same wrapping add, `pos` advanced by 4.
/// Failure emits a *single*
/// trace call (this reader's two `FT_ERROR`s were merged into one
/// string) and then sets `*error`, the reverse of `ReadShort`'s order.
///
/// A null `stream` hits the live `FT_ASSERT` and never returns.
///
/// # Safety
/// As [`ft_stream_read_short`], with `base` covering `pos + 4`.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ft_stream_read_long(stream: *mut FtStream, error: *mut i32) -> i32 {
    if stream.is_null() {
        assert_failed(ASSERT_LINE_READ_LONG);
    }
    *error = 0;
    let pos = (*stream).pos;
    let mut reads = [0u8; 4];
    if pos.wrapping_add(3) < (*stream).size {
        if let Some(p) = stream_frame(stream, pos, reads.as_mut_ptr(), 4) {
            let result = if p.is_null() {
                0
            } else {
                ((*p as u32) << 24)
                    | ((*p.add(1) as u32) << 16)
                    | ((*p.add(2) as u32) << 8)
                    | (*p.add(3) as u32)
            };
            (*stream).pos = (*stream).pos.wrapping_add(4);
            return result as i32;
        }
    }
    ft_error_trace(
        READ_LONG_INVALID_IO.as_ptr(),
        (*stream).pos,
        (*stream).size,
        0,
    );
    *error = FT_ERR_INVALID_STREAM_OPERATION;
    0
}

/// ft_stream_read_long_le (FreeType `FT_Stream_ReadLongLE`) — original:
/// `FUN_0804f900` @ 0x0804f900 (212 bytes; 1 call site, 0x0807d52c).
///
/// [`ft_stream_read_long`] with the bytes the other way round:
/// `FT_NEXT_ULONG_LE`, `p[0] | p[1]<<8 | p[2]<<16 | p[3]<<24`, all
/// `ldrb`. Same `pos + 3 < size` wrapping bounds test, same `pos += 4`,
/// and — like `ReadLong` — the failure path traces *before* it sets
/// `*error`. Unlike `ReadLong` this build kept both `FT_ERROR`s, so two
/// trace calls fire.
///
/// A null `stream` hits the live `FT_ASSERT` and never returns.
///
/// # Safety
/// As [`ft_stream_read_long`].
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ft_stream_read_long_le(stream: *mut FtStream, error: *mut i32) -> i32 {
    if stream.is_null() {
        assert_failed(ASSERT_LINE_READ_LONG_LE);
    }
    *error = 0;
    let pos = (*stream).pos;
    let mut reads = [0u8; 4];
    if pos.wrapping_add(3) < (*stream).size {
        if let Some(p) = stream_frame(stream, pos, reads.as_mut_ptr(), 4) {
            let result = if p.is_null() {
                0
            } else {
                (*p as u32)
                    | ((*p.add(1) as u32) << 8)
                    | ((*p.add(2) as u32) << 16)
                    | ((*p.add(3) as u32) << 24)
            };
            (*stream).pos = (*stream).pos.wrapping_add(4);
            return result as i32;
        }
    }
    ft_error_trace(READ_LONG_LE_TAG.as_ptr(), 0, 0, 0);
    ft_error_trace(INVALID_IO.as_ptr(), (*stream).pos, (*stream).size, 0);
    *error = FT_ERR_INVALID_STREAM_OPERATION;
    0
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ft::trace::{capture, TEST_TRACE_LOCK};
    use std::{vec, vec::Vec};

    /// A memory stream over `bytes` (no read callback).
    fn memory_stream(bytes: &mut [u8]) -> FtStream {
        FtStream {
            base: bytes.as_mut_ptr(),
            size: bytes.len() as u32,
            pos: 0,
            descriptor: core::ptr::null_mut(),
            pathname: core::ptr::null_mut(),
            read: None,
            close: None,
            memory: core::ptr::null_mut(),
            cursor: core::ptr::null_mut(),
            limit: core::ptr::null_mut(),
        }
    }

    /// What the disk-stream callback below was asked for.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct IoCall {
        offset: u32,
        buffer_is_null: bool,
        count: u32,
    }

    static mut IO_CALLS: [IoCall; 8] = [IoCall { offset: 0, buffer_is_null: false, count: 0 }; 8];
    static mut IO_CALL_COUNT: usize = 0;
    /// Bytes the callback serves, and the short-read/seek-failure knobs.
    static mut IO_DATA: [u8; 16] = [0; 16];
    static mut IO_SHORT_BY: u32 = 0;
    static mut IO_SEEK_FAILS: bool = false;

    unsafe extern "C" fn disk_read(
        _stream: *mut FtStream,
        offset: u32,
        buffer: *mut u8,
        count: u32,
    ) -> u32 {
        let n = *core::ptr::addr_of!(IO_CALL_COUNT);
        if n < 8 {
            (*core::ptr::addr_of_mut!(IO_CALLS))[n] =
                IoCall { offset, buffer_is_null: buffer.is_null(), count };
            *core::ptr::addr_of_mut!(IO_CALL_COUNT) = n + 1;
        }
        if count == 0 {
            // Seek probe: non-zero means "cannot seek there".
            return if *core::ptr::addr_of!(IO_SEEK_FAILS) { 1 } else { 0 };
        }
        let served = count - *core::ptr::addr_of!(IO_SHORT_BY);
        for i in 0..served {
            let index = offset.wrapping_add(i) as usize % 16;
            *buffer.add(i as usize) = (*core::ptr::addr_of!(IO_DATA))[index];
        }
        served
    }

    unsafe fn reset_io(data: &[u8]) {
        *core::ptr::addr_of_mut!(IO_CALL_COUNT) = 0;
        *core::ptr::addr_of_mut!(IO_SHORT_BY) = 0;
        *core::ptr::addr_of_mut!(IO_SEEK_FAILS) = false;
        let dst = core::ptr::addr_of_mut!(IO_DATA).cast::<u8>();
        for i in 0..16 {
            *dst.add(i) = data.get(i).copied().unwrap_or(0);
        }
    }

    unsafe fn io_calls() -> Vec<IoCall> {
        core::slice::from_raw_parts(
            core::ptr::addr_of!(IO_CALLS).cast::<IoCall>(),
            *core::ptr::addr_of!(IO_CALL_COUNT),
        )
        .to_vec()
    }

    fn disk_stream(size: u32) -> FtStream {
        FtStream {
            base: core::ptr::null_mut(),
            size,
            pos: 0,
            descriptor: core::ptr::null_mut(),
            pathname: core::ptr::null_mut(),
            read: Some(disk_read),
            close: None,
            memory: core::ptr::null_mut(),
            cursor: core::ptr::null_mut(),
            limit: core::ptr::null_mut(),
        }
    }

    /// Reference `FT_Stream_Seek` straight from the upstream source.
    fn seek_ref(pos: u32, size: u32, read_fails: Option<bool>) -> i32 {
        match read_fails {
            Some(true) => FT_ERR_INVALID_STREAM_OPERATION,
            Some(false) => 0,
            None => {
                if pos > size {
                    FT_ERR_INVALID_STREAM_OPERATION
                } else {
                    0
                }
            }
        }
    }

    /// Reference `FT_Stream_ReadShort` over a memory stream: big-endian,
    /// sign-extended, `pos + 1 < size` bounds test.
    fn read_short_ref(bytes: &[u8], pos: u32) -> (i32, i32, u32) {
        if pos.wrapping_add(1) < bytes.len() as u32 {
            let hi = bytes[pos as usize] as i8 as i32;
            let lo = bytes[pos as usize + 1] as i32;
            (lo | (hi << 8), 0, pos + 2)
        } else {
            (0, FT_ERR_INVALID_STREAM_OPERATION, pos)
        }
    }

    /// Reference `FT_Stream_ReadChar` over a memory stream: one byte,
    /// `pos < size`, returned as a signed `FT_Char`.
    fn read_char_ref(bytes: &[u8], pos: u32) -> (i32, i32, u32) {
        if pos < bytes.len() as u32 {
            (bytes[pos as usize] as i8 as i32, 0, pos + 1)
        } else {
            (0, FT_ERR_INVALID_STREAM_OPERATION, pos)
        }
    }

    /// Reference `FT_Stream_ReadOffset` over a memory stream:
    /// `FT_NEXT_OFF3`, signed big-endian 24-bit, `pos + 2 < size`.
    fn read_offset_ref(bytes: &[u8], pos: u32) -> (i32, i32, u32) {
        if pos.wrapping_add(2) < bytes.len() as u32 {
            let p = pos as usize;
            let value = ((bytes[p] as i8 as i32) << 16)
                | ((bytes[p + 1] as i32) << 8)
                | bytes[p + 2] as i32;
            (value, 0, pos + 3)
        } else {
            (0, FT_ERR_INVALID_STREAM_OPERATION, pos)
        }
    }

    /// Reference `FT_Stream_ReadLongLE` over a memory stream:
    /// `FT_NEXT_ULONG_LE`, `pos + 3 < size`.
    fn read_long_le_ref(bytes: &[u8], pos: u32) -> (i32, i32, u32) {
        if pos.wrapping_add(3) < bytes.len() as u32 {
            let p = pos as usize;
            let value = bytes[p] as u32
                | ((bytes[p + 1] as u32) << 8)
                | ((bytes[p + 2] as u32) << 16)
                | ((bytes[p + 3] as u32) << 24);
            (value as i32, 0, pos + 4)
        } else {
            (0, FT_ERR_INVALID_STREAM_OPERATION, pos)
        }
    }

    /// Reference `FT_Stream_ReadLong` over a memory stream.
    fn read_long_ref(bytes: &[u8], pos: u32) -> (i32, i32, u32) {
        if pos.wrapping_add(3) < bytes.len() as u32 {
            let p = pos as usize;
            let value = ((bytes[p] as u32) << 24)
                | ((bytes[p + 1] as u32) << 16)
                | ((bytes[p + 2] as u32) << 8)
                | bytes[p + 3] as u32;
            (value as i32, 0, pos + 4)
        } else {
            (0, FT_ERR_INVALID_STREAM_OPERATION, pos)
        }
    }

    #[test]
    fn seek_memory_stream_accepts_up_to_and_including_size() {
        let mut bytes = [0u8; 10];
        let mut stream = memory_stream(&mut bytes);
        for pos in [0u32, 1, 9, 10] {
            assert_eq!(unsafe { ft_stream_seek(&mut stream, pos) }, 0, "pos {pos}");
            assert_eq!(stream.pos, pos);
            assert_eq!(seek_ref(pos, 10, None), 0);
        }
    }

    #[test]
    fn seek_memory_stream_past_size_fails_but_still_stores_pos() {
        let _guard = TEST_TRACE_LOCK.lock().unwrap();
        let mut bytes = [0u8; 10];
        let mut stream = memory_stream(&mut bytes);
        let calls = unsafe {
            capture::start();
            assert_eq!(
                ft_stream_seek(&mut stream, 11),
                FT_ERR_INVALID_STREAM_OPERATION
            );
            capture::finish()
        };
        assert_eq!(stream.pos, 11);
        assert_eq!(seek_ref(11, 10, None), FT_ERR_INVALID_STREAM_OPERATION);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].args, [11, 10, 0]);
        assert!(unsafe { capture::formats(&calls) }[0].starts_with("FT_Stream_Seek:"));
    }

    #[test]
    fn seek_disk_stream_probes_the_callback_with_a_null_buffer() {
        let mut stream = disk_stream(10);
        unsafe { reset_io(&[]) };
        assert_eq!(unsafe { ft_stream_seek(&mut stream, 7) }, 0);
        assert_eq!(
            unsafe { io_calls() },
            vec![IoCall { offset: 7, buffer_is_null: true, count: 0 }]
        );
        // A disk stream is not bounds-checked against `size` at all.
        assert_eq!(unsafe { ft_stream_seek(&mut stream, 1_000_000) }, 0);
        assert_eq!(stream.pos, 1_000_000);
    }

    #[test]
    fn seek_disk_stream_reports_the_callbacks_refusal() {
        let _guard = TEST_TRACE_LOCK.lock().unwrap();
        let mut stream = disk_stream(10);
        let calls = unsafe {
            reset_io(&[]);
            *core::ptr::addr_of_mut!(IO_SEEK_FAILS) = true;
            capture::start();
            let error = ft_stream_seek(&mut stream, 3);
            assert_eq!(error, FT_ERR_INVALID_STREAM_OPERATION);
            capture::finish()
        };
        assert_eq!(seek_ref(3, 10, Some(true)), FT_ERR_INVALID_STREAM_OPERATION);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].args, [3, 10, 0]);
    }

    #[test]
    fn skip_advances_from_the_current_position() {
        let mut bytes = [0u8; 10];
        let mut stream = memory_stream(&mut bytes);
        stream.pos = 4;
        assert_eq!(unsafe { ft_stream_skip(&mut stream, 3) }, 0);
        assert_eq!(stream.pos, 7);
        assert_eq!(unsafe { ft_stream_skip(&mut stream, 0) }, 0);
        assert_eq!(stream.pos, 7);
    }

    #[test]
    fn skip_backwards_is_allowed_and_underflow_is_rejected_by_the_seek() {
        let _guard = TEST_TRACE_LOCK.lock().unwrap();
        let mut bytes = [0u8; 10];
        let mut stream = memory_stream(&mut bytes);
        stream.pos = 6;
        assert_eq!(unsafe { ft_stream_skip(&mut stream, -4) }, 0);
        assert_eq!(stream.pos, 2);
        // No `distance < 0` guard in this version: the wrapped position
        // is huge, so the seek's bounds check rejects it.
        unsafe { capture::start() };
        assert_eq!(
            unsafe { ft_stream_skip(&mut stream, -3) },
            FT_ERR_INVALID_STREAM_OPERATION
        );
        let calls = unsafe { capture::finish() };
        assert_eq!(stream.pos, 0xffff_ffff);
        assert_eq!(calls.len(), 1);
    }

    #[test]
    fn read_short_memory_stream_matches_reference_over_every_position() {
        let mut bytes = [0x00, 0x01, 0x7f, 0xff, 0x80, 0x00, 0xff, 0xfe];
        let snapshot = bytes;
        for pos in 0..12u32 {
            let _guard = TEST_TRACE_LOCK.lock().unwrap();
            let mut stream = memory_stream(&mut bytes);
            stream.pos = pos;
            let mut error = 0x1234;
            let value = unsafe {
                capture::start();
                let v = ft_stream_read_short(&mut stream, &mut error);
                capture::finish();
                v
            };
            let (want, want_error, want_pos) = read_short_ref(&snapshot, pos);
            assert_eq!((value, error, stream.pos), (want, want_error, want_pos), "pos {pos}");
        }
    }

    #[test]
    fn read_short_sign_extends_the_high_byte() {
        // 0xfffe -> -2, 0x8000 -> -32768, 0x7fff -> 32767.
        let mut bytes = [0xff, 0xfe, 0x80, 0x00, 0x7f, 0xff, 0, 0];
        let mut stream = memory_stream(&mut bytes);
        let mut error = 0;
        assert_eq!(unsafe { ft_stream_read_short(&mut stream, &mut error) }, -2);
        assert_eq!(unsafe { ft_stream_read_short(&mut stream, &mut error) }, -32768);
        assert_eq!(unsafe { ft_stream_read_short(&mut stream, &mut error) }, 32767);
        assert_eq!(error, 0);
        assert_eq!(stream.pos, 6);
    }

    #[test]
    fn read_short_past_the_end_fails_and_traces_twice() {
        // pos + 1 < size: the last two bytes are readable (pos 2), one
        // byte short of the end (pos 3) is not.
        let _guard = TEST_TRACE_LOCK.lock().unwrap();
        let mut bytes = [1u8, 2, 3, 4];
        let mut stream = memory_stream(&mut bytes);
        stream.pos = 2;
        let mut error = 0;
        assert_eq!(unsafe { ft_stream_read_short(&mut stream, &mut error) }, 0x0304);
        stream.pos = 3;
        let calls = unsafe {
            capture::start();
            assert_eq!(ft_stream_read_short(&mut stream, &mut error), 0);
            capture::finish()
        };
        assert_eq!(error, FT_ERR_INVALID_STREAM_OPERATION);
        assert_eq!(stream.pos, 3);
        let formats = unsafe { capture::formats(&calls) };
        assert_eq!(formats.len(), 2);
        assert_eq!(formats[0], "FT_Stream_ReadShort:");
        assert!(formats[1].starts_with(" invalid i/o;"));
        assert_eq!(calls[1].args, [3, 4, 0]);
    }

    #[test]
    fn bounds_check_wraps_at_the_top_of_the_address_space() {
        // `pos + 1` / `pos + 3` are 32-bit adds: a position near
        // 0xffffffff wraps to a small number and passes the test. Shown
        // on a disk stream, where the callback keeps the read harmless.
        let mut stream = disk_stream(16);
        unsafe { reset_io(&[0xaa; 16]) };
        stream.pos = 0xffff_ffff;
        let mut error = 0x1234;
        assert_eq!(
            unsafe { ft_stream_read_short(&mut stream, &mut error) },
            0xffff_aaaa_u32 as i32
        );
        assert_eq!((error, stream.pos), (0, 1));
        stream.pos = 0xffff_fffd;
        assert_eq!(
            unsafe { ft_stream_read_long(&mut stream, &mut error) },
            0xaaaa_aaaa_u32 as i32
        );
        assert_eq!((error, stream.pos), (0, 1));
    }

    #[test]
    fn read_short_disk_stream_uses_the_callback_buffer() {
        let mut stream = disk_stream(16);
        unsafe { reset_io(&[0xde, 0xad, 0xbe, 0xef]) };
        let mut error = 0x1234;
        let value = unsafe { ft_stream_read_short(&mut stream, &mut error) };
        assert_eq!(value, 0xffff_dead_u32 as i32); // sign-extended
        assert_eq!((error, stream.pos), (0, 2));
        assert_eq!(
            unsafe { io_calls() },
            vec![IoCall { offset: 0, buffer_is_null: false, count: 2 }]
        );
    }

    #[test]
    fn read_short_short_callback_read_fails() {
        let _guard = TEST_TRACE_LOCK.lock().unwrap();
        let mut stream = disk_stream(16);
        let mut error = 0;
        let calls = unsafe {
            reset_io(&[1, 2, 3, 4]);
            *core::ptr::addr_of_mut!(IO_SHORT_BY) = 1;
            capture::start();
            assert_eq!(ft_stream_read_short(&mut stream, &mut error), 0);
            capture::finish()
        };
        assert_eq!((error, stream.pos), (FT_ERR_INVALID_STREAM_OPERATION, 0));
        assert_eq!(calls.len(), 2);
    }

    #[test]
    fn read_long_memory_stream_matches_reference_over_every_position() {
        let mut bytes = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x00, 0xff];
        let snapshot = bytes;
        for pos in 0..14u32 {
            let _guard = TEST_TRACE_LOCK.lock().unwrap();
            let mut stream = memory_stream(&mut bytes);
            stream.pos = pos;
            let mut error = 0x1234;
            let value = unsafe {
                capture::start();
                let v = ft_stream_read_long(&mut stream, &mut error);
                capture::finish();
                v
            };
            let (want, want_error, want_pos) = read_long_ref(&snapshot, pos);
            assert_eq!((value, error, stream.pos), (want, want_error, want_pos), "pos {pos}");
        }
    }

    #[test]
    fn read_long_is_big_endian_and_keeps_the_top_bit() {
        let mut bytes = [0x80, 0x00, 0x00, 0x01, 0x12, 0x34, 0x56, 0x78, 0, 0];
        let mut stream = memory_stream(&mut bytes);
        let mut error = 0;
        assert_eq!(
            unsafe { ft_stream_read_long(&mut stream, &mut error) },
            0x8000_0001_u32 as i32
        );
        assert_eq!(unsafe { ft_stream_read_long(&mut stream, &mut error) }, 0x1234_5678);
        assert_eq!((error, stream.pos), (0, 8));
    }

    #[test]
    fn read_long_past_the_end_fails_and_traces_once() {
        // pos + 3 < size: pos 4 still fits in an 8-byte stream, pos 5
        // does not.
        let _guard = TEST_TRACE_LOCK.lock().unwrap();
        let mut bytes = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let mut stream = memory_stream(&mut bytes);
        stream.pos = 4;
        let mut error = 0;
        assert_eq!(
            unsafe { ft_stream_read_long(&mut stream, &mut error) },
            0x0506_0708
        );
        stream.pos = 5;
        let calls = unsafe {
            capture::start();
            assert_eq!(ft_stream_read_long(&mut stream, &mut error), 0);
            capture::finish()
        };
        assert_eq!((error, stream.pos), (FT_ERR_INVALID_STREAM_OPERATION, 5));
        let formats = unsafe { capture::formats(&calls) };
        assert_eq!(formats.len(), 1);
        assert!(formats[0].starts_with("FT_Stream_ReadLong: invalid i/o;"));
        assert_eq!(calls[0].args, [5, 8, 0]);
    }

    #[test]
    fn read_long_disk_stream_reads_four_bytes_through_the_callback() {
        let mut stream = disk_stream(16);
        unsafe { reset_io(&[0xca, 0xfe, 0xba, 0xbe]) };
        stream.pos = 0;
        let mut error = 0x1234;
        let value = unsafe { ft_stream_read_long(&mut stream, &mut error) };
        assert_eq!(value, 0xcafe_babe_u32 as i32);
        assert_eq!((error, stream.pos), (0, 4));
        assert_eq!(
            unsafe { io_calls() },
            vec![IoCall { offset: 0, buffer_is_null: false, count: 4 }]
        );
    }

    #[test]
    fn readers_sequence_through_a_memory_stream() {
        // A miniature big-endian record, read the way the sfnt/truetype
        // drivers do: tag, then two counts.
        let mut bytes = [0x74, 0x72, 0x75, 0x65, 0x00, 0x03, 0xff, 0xfd, 0, 0, 0, 0];
        let mut stream = memory_stream(&mut bytes);
        let mut error = 0;
        assert_eq!(
            unsafe { ft_stream_read_long(&mut stream, &mut error) },
            0x7472_7565
        );
        assert_eq!(unsafe { ft_stream_read_short(&mut stream, &mut error) }, 3);
        assert_eq!(unsafe { ft_stream_read_short(&mut stream, &mut error) }, -3);
        assert_eq!((error, stream.pos), (0, 8));
        assert_eq!(unsafe { ft_stream_skip(&mut stream, -8) }, 0);
        assert_eq!(stream.pos, 0);
    }

    #[test]
    fn read_char_memory_stream_matches_reference_over_every_position() {
        let mut bytes = [0x00, 0x01, 0x7f, 0x80, 0xff, 0xfe, 0x81, 0x42];
        let snapshot = bytes;
        for pos in 0..11u32 {
            let _guard = TEST_TRACE_LOCK.lock().unwrap();
            let mut stream = memory_stream(&mut bytes);
            stream.pos = pos;
            let mut error = 0x1234;
            let value = unsafe {
                capture::start();
                let v = ft_stream_read_char(&mut stream, &mut error);
                capture::finish();
                v
            };
            let want = read_char_ref(&snapshot, pos);
            assert_eq!((value, error, stream.pos), want, "pos {pos}");
        }
    }

    #[test]
    fn read_char_sign_extends_the_byte() {
        let mut bytes = [0x7f, 0x80, 0xff, 0x00];
        let mut stream = memory_stream(&mut bytes);
        let mut error = 0;
        assert_eq!(unsafe { ft_stream_read_char(&mut stream, &mut error) }, 127);
        assert_eq!(unsafe { ft_stream_read_char(&mut stream, &mut error) }, -128);
        assert_eq!(unsafe { ft_stream_read_char(&mut stream, &mut error) }, -1);
        assert_eq!(unsafe { ft_stream_read_char(&mut stream, &mut error) }, 0);
        assert_eq!((error, stream.pos), (0, 4));
    }

    #[test]
    fn read_char_past_the_end_fails_and_traces_once() {
        // `pos < size`, so the very last byte is readable.
        let _guard = TEST_TRACE_LOCK.lock().unwrap();
        let mut bytes = [1u8, 2, 3];
        let mut stream = memory_stream(&mut bytes);
        stream.pos = 2;
        let mut error = 0;
        assert_eq!(unsafe { ft_stream_read_char(&mut stream, &mut error) }, 3);
        assert_eq!(stream.pos, 3);
        let calls = unsafe {
            capture::start();
            assert_eq!(ft_stream_read_char(&mut stream, &mut error), 0);
            capture::finish()
        };
        assert_eq!((error, stream.pos), (FT_ERR_INVALID_STREAM_OPERATION, 3));
        let formats = unsafe { capture::formats(&calls) };
        assert_eq!(formats.len(), 1);
        assert!(formats[0].starts_with("FT_Stream_ReadChar: invalid i/o;"));
        assert_eq!(calls[0].args, [3, 3, 0]);
    }

    #[test]
    fn read_char_disk_stream_is_never_bounds_checked() {
        // The quirk that separates ReadChar from every other reader: on
        // a disk stream `size` is not consulted at all, so a callback
        // that serves its byte is believed arbitrarily far past the end.
        let mut stream = disk_stream(0);
        unsafe { reset_io(&[0x90]) };
        let mut error = 0x1234;
        stream.pos = 1_000_000;
        assert_eq!(
            unsafe { ft_stream_read_char(&mut stream, &mut error) },
            -112 // 0x90 sign-extended
        );
        assert_eq!((error, stream.pos), (0, 1_000_001));
        assert_eq!(
            unsafe { io_calls() },
            vec![IoCall { offset: 1_000_000, buffer_is_null: false, count: 1 }]
        );
    }

    #[test]
    fn read_char_short_callback_read_fails() {
        let _guard = TEST_TRACE_LOCK.lock().unwrap();
        let mut stream = disk_stream(16);
        let mut error = 0;
        let calls = unsafe {
            reset_io(&[1, 2, 3, 4]);
            *core::ptr::addr_of_mut!(IO_SHORT_BY) = 1;
            capture::start();
            assert_eq!(ft_stream_read_char(&mut stream, &mut error), 0);
            capture::finish()
        };
        assert_eq!((error, stream.pos), (FT_ERR_INVALID_STREAM_OPERATION, 0));
        assert_eq!(calls.len(), 1);
    }

    #[test]
    fn read_offset_memory_stream_matches_reference_over_every_position() {
        let mut bytes = [0x00, 0x80, 0x00, 0x7f, 0xff, 0xff, 0xff, 0x01, 0x02];
        let snapshot = bytes;
        for pos in 0..13u32 {
            let _guard = TEST_TRACE_LOCK.lock().unwrap();
            let mut stream = memory_stream(&mut bytes);
            stream.pos = pos;
            let mut error = 0x1234;
            let value = unsafe {
                capture::start();
                let v = ft_stream_read_offset(&mut stream, &mut error);
                capture::finish();
                v
            };
            let want = read_offset_ref(&snapshot, pos);
            assert_eq!((value, error, stream.pos), want, "pos {pos}");
        }
    }

    #[test]
    fn read_offset_is_a_signed_24_bit_big_endian_value() {
        // 0x7fffff is the largest, 0x800000 the smallest OFF3.
        let mut bytes = [0x7f, 0xff, 0xff, 0x80, 0x00, 0x00, 0xff, 0xff, 0xff, 0x00, 0x01, 0x00, 0];
        let mut stream = memory_stream(&mut bytes);
        let mut error = 0;
        assert_eq!(unsafe { ft_stream_read_offset(&mut stream, &mut error) }, 8_388_607);
        assert_eq!(unsafe { ft_stream_read_offset(&mut stream, &mut error) }, -8_388_608);
        assert_eq!(unsafe { ft_stream_read_offset(&mut stream, &mut error) }, -1);
        assert_eq!(unsafe { ft_stream_read_offset(&mut stream, &mut error) }, 256);
        assert_eq!((error, stream.pos), (0, 12));
    }

    #[test]
    fn read_offset_past_the_end_fails_and_traces_twice() {
        // pos + 2 < size: pos 4 fits in a 7-byte stream, pos 5 does not.
        let _guard = TEST_TRACE_LOCK.lock().unwrap();
        let mut bytes = [1u8, 2, 3, 4, 5, 6, 7];
        let mut stream = memory_stream(&mut bytes);
        stream.pos = 4;
        let mut error = 0;
        assert_eq!(
            unsafe { ft_stream_read_offset(&mut stream, &mut error) },
            0x0005_0607
        );
        stream.pos = 5;
        let calls = unsafe {
            capture::start();
            assert_eq!(ft_stream_read_offset(&mut stream, &mut error), 0);
            capture::finish()
        };
        assert_eq!((error, stream.pos), (FT_ERR_INVALID_STREAM_OPERATION, 5));
        let formats = unsafe { capture::formats(&calls) };
        assert_eq!(formats.len(), 2);
        assert_eq!(formats[0], "FT_Stream_ReadOffset:");
        assert!(formats[1].starts_with(" invalid i/o;"));
        assert_eq!(calls[1].args, [5, 7, 0]);
    }

    #[test]
    fn read_offset_disk_stream_asks_for_three_bytes() {
        let mut stream = disk_stream(16);
        unsafe { reset_io(&[0xab, 0xcd, 0xef]) };
        let mut error = 0x1234;
        let value = unsafe { ft_stream_read_offset(&mut stream, &mut error) };
        assert_eq!(value, 0xffab_cdef_u32 as i32); // top byte sign-extended
        assert_eq!((error, stream.pos), (0, 3));
        assert_eq!(
            unsafe { io_calls() },
            vec![IoCall { offset: 0, buffer_is_null: false, count: 3 }]
        );
    }

    #[test]
    fn read_long_le_memory_stream_matches_reference_over_every_position() {
        let mut bytes = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x00, 0xff];
        let snapshot = bytes;
        for pos in 0..14u32 {
            let _guard = TEST_TRACE_LOCK.lock().unwrap();
            let mut stream = memory_stream(&mut bytes);
            stream.pos = pos;
            let mut error = 0x1234;
            let value = unsafe {
                capture::start();
                let v = ft_stream_read_long_le(&mut stream, &mut error);
                capture::finish();
                v
            };
            let want = read_long_le_ref(&snapshot, pos);
            assert_eq!((value, error, stream.pos), want, "pos {pos}");
        }
    }

    #[test]
    fn read_long_le_is_the_byte_reverse_of_read_long() {
        let mut bytes = [0x01, 0x02, 0x03, 0x04, 0x80, 0x00, 0x00, 0x00];
        let mut stream = memory_stream(&mut bytes);
        let mut error = 0;
        assert_eq!(
            unsafe { ft_stream_read_long_le(&mut stream, &mut error) },
            0x0403_0201
        );
        assert_eq!(unsafe { ft_stream_read_long_le(&mut stream, &mut error) }, 0x80);
        assert_eq!((error, stream.pos), (0, 8));
        stream.pos = 0;
        assert_eq!(
            unsafe { ft_stream_read_long(&mut stream, &mut error) },
            0x0102_0304
        );
    }

    #[test]
    fn read_long_le_past_the_end_fails_and_traces_twice() {
        let _guard = TEST_TRACE_LOCK.lock().unwrap();
        let mut bytes = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let mut stream = memory_stream(&mut bytes);
        stream.pos = 5;
        let mut error = 0;
        let calls = unsafe {
            capture::start();
            assert_eq!(ft_stream_read_long_le(&mut stream, &mut error), 0);
            capture::finish()
        };
        assert_eq!((error, stream.pos), (FT_ERR_INVALID_STREAM_OPERATION, 5));
        let formats = unsafe { capture::formats(&calls) };
        assert_eq!(formats.len(), 2);
        assert_eq!(formats[0], "FT_Stream_ReadLongLE:");
        assert!(formats[1].starts_with(" invalid i/o;"));
        assert_eq!(calls[0].args, [0, 0, 0]);
        assert_eq!(calls[1].args, [5, 8, 0]);
    }

    #[test]
    fn read_long_le_disk_stream_reads_four_bytes_through_the_callback() {
        let mut stream = disk_stream(16);
        unsafe { reset_io(&[0xca, 0xfe, 0xba, 0xbe]) };
        let mut error = 0x1234;
        let value = unsafe { ft_stream_read_long_le(&mut stream, &mut error) };
        assert_eq!(value, 0xbeba_feca_u32 as i32);
        assert_eq!((error, stream.pos), (0, 4));
        assert_eq!(
            unsafe { io_calls() },
            vec![IoCall { offset: 0, buffer_is_null: false, count: 4 }]
        );
    }

    #[test]
    fn offset_and_long_le_bounds_checks_wrap_at_the_top_of_the_address_space() {
        // Same 32-bit wrapping add as ReadShort/ReadLong.
        let mut stream = disk_stream(16);
        unsafe { reset_io(&[0x5a; 16]) };
        let mut error = 0x1234;
        stream.pos = 0xffff_fffe;
        assert_eq!(
            unsafe { ft_stream_read_offset(&mut stream, &mut error) },
            0x005a_5a5a
        );
        assert_eq!((error, stream.pos), (0, 1));
        stream.pos = 0xffff_fffd;
        assert_eq!(
            unsafe { ft_stream_read_long_le(&mut stream, &mut error) },
            0x5a5a_5a5a
        );
        assert_eq!((error, stream.pos), (0, 1));
    }

    /// Deterministic xorshift32, so the randomized sweep is repeatable.
    fn next_random(state: &mut u32) -> u32 {
        *state ^= *state << 13;
        *state ^= *state >> 17;
        *state ^= *state << 5;
        *state
    }

    #[test]
    fn every_reader_matches_its_reference_over_random_buffers() {
        let mut state = 0x1357_9bdf_u32;
        for _ in 0..400 {
            let len = (next_random(&mut state) % 12) as usize;
            let mut bytes = vec![0u8; len];
            for byte in bytes.iter_mut() {
                *byte = next_random(&mut state) as u8;
            }
            let snapshot = bytes.clone();
            for pos in 0..(len as u32 + 3) {
                let _guard = TEST_TRACE_LOCK.lock().unwrap();
                unsafe { capture::start() };
                for (name, run, want) in [
                    (
                        "char",
                        ft_stream_read_char as unsafe extern "C" fn(*mut FtStream, *mut i32) -> i32,
                        read_char_ref(&snapshot, pos),
                    ),
                    ("short", ft_stream_read_short, read_short_ref(&snapshot, pos)),
                    ("offset", ft_stream_read_offset, read_offset_ref(&snapshot, pos)),
                    ("long", ft_stream_read_long, read_long_ref(&snapshot, pos)),
                    ("longle", ft_stream_read_long_le, read_long_le_ref(&snapshot, pos)),
                ] {
                    let mut stream = memory_stream(&mut bytes);
                    stream.pos = pos;
                    let mut error = 0x1234;
                    let value = unsafe { run(&mut stream, &mut error) };
                    assert_eq!(
                        (value, error, stream.pos),
                        want,
                        "{name} len {len} pos {pos} bytes {snapshot:?}"
                    );
                }
                unsafe { capture::finish() };
            }
        }
    }

    /// A stream with `bytes` mapped as an entered frame.
    fn framed_stream(bytes: &mut [u8]) -> FtStream {
        let mut stream = memory_stream(bytes);
        stream.cursor = bytes.as_mut_ptr();
        stream.limit = unsafe { bytes.as_mut_ptr().add(bytes.len()) };
        stream
    }

    /// Reference `FT_Stream_Get*` over a frame: `(value, cursor moved
    /// by)`. `span` is `n - 1`, the bound upstream tests.
    fn get_ref(bytes: &[u8], at: usize, width: usize, decode: fn(&[u8]) -> i32) -> (i32, usize) {
        // Upstream: `if ( p + width - 1 < limit )`.
        if at + width - 1 < bytes.len() {
            (decode(&bytes[at..at + width]), width)
        } else {
            (0, 0)
        }
    }

    fn decode_char(p: &[u8]) -> i32 {
        p[0] as i8 as i32
    }
    fn decode_short(p: &[u8]) -> i32 {
        ((p[0] as i8 as i32) << 8) | p[1] as i32
    }
    fn decode_short_le(p: &[u8]) -> i32 {
        ((p[1] as i8 as i32) << 8) | p[0] as i32
    }
    fn decode_long(p: &[u8]) -> i32 {
        (((p[0] as u32) << 24)
            | ((p[1] as u32) << 16)
            | ((p[2] as u32) << 8)
            | p[3] as u32) as i32
    }

    #[test]
    fn get_family_matches_reference_at_every_cursor_position() {
        let source = [0x80u8, 0x01, 0x7f, 0xff, 0x00, 0xfe, 0x42, 0x9a];
        for at in 0..=source.len() {
            let mut bytes = source;
            let base = bytes.as_mut_ptr();
            for (name, run, width, decode) in [
                (
                    "char",
                    ft_stream_get_char as unsafe extern "C" fn(*mut FtStream) -> i32,
                    1usize,
                    decode_char as fn(&[u8]) -> i32,
                ),
                ("short", ft_stream_get_short, 2, decode_short),
                ("short_le", ft_stream_get_short_le, 2, decode_short_le),
                ("long", ft_stream_get_long, 4, decode_long),
            ] {
                let mut stream = framed_stream(&mut bytes);
                stream.cursor = unsafe { base.add(at) };
                let value = unsafe { run(&mut stream) };
                let (want, moved) = get_ref(&source, at, width, decode);
                assert_eq!(value, want, "{name} at {at}");
                assert_eq!(
                    stream.cursor,
                    unsafe { base.add(at + moved) },
                    "{name} cursor at {at}"
                );
            }
        }
    }

    #[test]
    fn get_family_reads_the_last_bytes_of_a_frame_but_not_past_them() {
        // `p + n - 1 < limit` is exactly "n bytes remain": the family
        // consumes a frame to its final byte, and one byte short of a
        // full value silently yields 0 with the cursor parked.
        let mut bytes = [1u8, 2, 3, 4];
        let base = bytes.as_mut_ptr();
        let mut stream = framed_stream(&mut bytes);
        stream.cursor = unsafe { base.add(2) }; // exactly two left
        assert_eq!(unsafe { ft_stream_get_short(&mut stream) }, 0x0304);
        assert_eq!(stream.cursor, unsafe { base.add(4) });
        stream.cursor = unsafe { base.add(3) }; // one short
        assert_eq!(unsafe { ft_stream_get_short(&mut stream) }, 0);
        assert_eq!(stream.cursor, unsafe { base.add(3) });
        // Same boundary four bytes wide.
        stream.cursor = base;
        assert_eq!(unsafe { ft_stream_get_long(&mut stream) }, 0x0102_0304);
        stream.cursor = unsafe { base.add(1) };
        assert_eq!(unsafe { ft_stream_get_long(&mut stream) }, 0);
        assert_eq!(stream.cursor, unsafe { base.add(1) });
        // GetChar's own bound is `p < limit`.
        stream.cursor = unsafe { base.add(3) };
        assert_eq!(unsafe { ft_stream_get_char(&mut stream) }, 4);
        assert_eq!(unsafe { ft_stream_get_char(&mut stream) }, 0);
        assert_eq!(stream.cursor, unsafe { base.add(4) });
    }

    #[test]
    fn get_family_sign_extension_and_endianness() {
        let mut bytes = [0xffu8, 0xfe, 0x80, 0x00, 0x7f, 0xff, 0x00, 0x00, 0x00];
        let base = bytes.as_mut_ptr();
        let mut stream = framed_stream(&mut bytes);
        assert_eq!(unsafe { ft_stream_get_short(&mut stream) }, -2);
        assert_eq!(unsafe { ft_stream_get_short(&mut stream) }, -32768);
        assert_eq!(unsafe { ft_stream_get_short(&mut stream) }, 32767);
        // Little-endian sibling sees the same bytes the other way.
        stream.cursor = base;
        assert_eq!(unsafe { ft_stream_get_short_le(&mut stream) }, -257); // 0xfeff
        stream.cursor = base;
        assert_eq!(
            unsafe { ft_stream_get_long(&mut stream) },
            0xfffe_8000_u32 as i32
        );
        assert_eq!(unsafe { ft_stream_get_long(&mut stream) }, 0x7fff_0000);
    }

    #[test]
    fn get_family_walks_a_record_the_way_the_sfnt_driver_does() {
        let mut bytes = [0x00, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x2a, 0x00, 0x00];
        let mut stream = framed_stream(&mut bytes);
        assert_eq!(unsafe { ft_stream_get_long(&mut stream) }, 0x0001_0000);
        assert_eq!(unsafe { ft_stream_get_short(&mut stream) }, 12);
        assert_eq!(unsafe { ft_stream_get_char(&mut stream) }, 42);
        assert_eq!(stream.cursor, unsafe { bytes.as_mut_ptr().add(7) });
        // pos/size are a separate cursor and stayed put throughout.
        assert_eq!(stream.pos, 0);
    }

    #[test]
    fn open_memory_initializes_exactly_the_fields_upstream_does() {
        let mut bytes = [1u8, 2, 3, 4];
        let mut stream = disk_stream(99);
        // Pre-dirty everything so the zeroing is observable.
        stream.pos = 7;
        stream.cursor = 1 as *mut u8;
        stream.limit = 42 as *mut u8;
        stream.descriptor = 43 as *mut core::ffi::c_void;
        unsafe { ft_stream_open_memory(&mut stream, bytes.as_ptr(), 4) };
        assert_eq!(stream.base, bytes.as_mut_ptr());
        assert_eq!((stream.size, stream.pos), (4, 0));
        assert!(stream.cursor.is_null());
        assert!(stream.read.is_none() && stream.close.is_none());
        // Untouched by upstream's body.
        assert_eq!(stream.limit, 42 as *mut u8);
        assert_eq!(stream.descriptor, 43 as *mut core::ffi::c_void);
        // And the stream it produces reads as a memory stream.
        let mut error = 0;
        assert_eq!(unsafe { ft_stream_read_char(&mut stream, &mut error) }, 1);
    }

    static mut CLOSE_CALLS: u32 = 0;

    unsafe extern "C" fn record_close(_stream: *mut FtStream) {
        *core::ptr::addr_of_mut!(CLOSE_CALLS) += 1;
    }

    #[test]
    fn close_invokes_the_callback_and_tolerates_null() {
        let mut bytes = [0u8; 2];
        let mut stream = memory_stream(&mut bytes);
        unsafe {
            *core::ptr::addr_of_mut!(CLOSE_CALLS) = 0;
            // No callback installed: nothing happens.
            ft_stream_close(&mut stream);
            assert_eq!(*core::ptr::addr_of!(CLOSE_CALLS), 0);
            stream.close = Some(record_close);
            ft_stream_close(&mut stream);
            assert_eq!(*core::ptr::addr_of!(CLOSE_CALLS), 1);
            // The pre-2.4 body does not clear `close`, so a second
            // call fires the callback again.
            ft_stream_close(&mut stream);
            assert_eq!(*core::ptr::addr_of!(CLOSE_CALLS), 2);
            assert!(stream.close.is_some());
            // A null stream is explicitly allowed.
            ft_stream_close(core::ptr::null_mut());
            assert_eq!(*core::ptr::addr_of!(CLOSE_CALLS), 2);
        }
    }

    #[test]
    fn stream_pos_returns_the_cursor() {
        let mut bytes = [0u8; 4];
        let mut stream = memory_stream(&mut bytes);
        for pos in [0u32, 3, 0xffff_ffff] {
            stream.pos = pos;
            assert_eq!(unsafe { ft_stream_pos(&stream) }, pos);
        }
    }

    /// Reference `FT_Stream_ReadAt` over a memory stream, straight from
    /// upstream: returns (error, bytes copied, resulting pos).
    fn read_at_ref(size: u32, pos: u32, count: u32) -> (i32, u32, u32) {
        if pos >= size {
            return (FT_ERR_INVALID_STREAM_OPERATION, 0, u32::MAX);
        }
        let transferred = (size - pos).min(count);
        let error = if transferred < count {
            FT_ERR_INVALID_STREAM_OPERATION
        } else {
            0
        };
        (error, transferred, pos + transferred)
    }

    #[test]
    fn read_at_memory_stream_matches_reference_over_every_position_and_count() {
        let source = [0x10u8, 0x20, 0x30, 0x40, 0x50, 0x60];
        for pos in 0..8u32 {
            for count in 0..9u32 {
                let _guard = TEST_TRACE_LOCK.lock().unwrap();
                let mut bytes = source;
                let mut stream = memory_stream(&mut bytes);
                stream.pos = 0xdead;
                let mut buffer = [0xccu8; 12];
                let error = unsafe {
                    capture::start();
                    let e = ft_stream_read_at(&mut stream, pos, buffer.as_mut_ptr(), count);
                    capture::finish();
                    e
                };
                let (want_error, want_n, want_pos) = read_at_ref(6, pos, count);
                assert_eq!(error, want_error, "pos {pos} count {count}");
                if want_pos == u32::MAX {
                    // Rejected outright: nothing copied, pos untouched.
                    assert_eq!(stream.pos, 0xdead);
                    assert!(buffer.iter().all(|&b| b == 0xcc));
                } else {
                    assert_eq!(stream.pos, want_pos, "pos {pos} count {count}");
                    assert_eq!(
                        &buffer[..want_n as usize],
                        &source[pos as usize..(pos + want_n) as usize],
                        "pos {pos} count {count}"
                    );
                    assert!(buffer[want_n as usize..].iter().all(|&b| b == 0xcc));
                }
            }
        }
    }

    #[test]
    fn read_at_past_the_end_traces_once_and_reads_nothing() {
        let _guard = TEST_TRACE_LOCK.lock().unwrap();
        let mut bytes = [1u8, 2, 3];
        let mut stream = memory_stream(&mut bytes);
        stream.pos = 1;
        let mut buffer = [0u8; 4];
        let calls = unsafe {
            capture::start();
            assert_eq!(
                ft_stream_read_at(&mut stream, 3, buffer.as_mut_ptr(), 1),
                FT_ERR_INVALID_STREAM_OPERATION
            );
            capture::finish()
        };
        assert_eq!(stream.pos, 1); // untouched
        let formats = unsafe { capture::formats(&calls) };
        assert_eq!(formats.len(), 1);
        assert!(formats[0].starts_with("FT_Stream_ReadAt: invalid i/o;"));
        assert_eq!(calls[0].args, [3, 3, 0]);
    }

    #[test]
    fn read_at_short_read_still_advances_pos_but_reports_the_shortfall() {
        let _guard = TEST_TRACE_LOCK.lock().unwrap();
        let mut bytes = [1u8, 2, 3, 4];
        let mut stream = memory_stream(&mut bytes);
        let mut buffer = [0u8; 8];
        let calls = unsafe {
            capture::start();
            // 3 bytes left, 6 asked for.
            assert_eq!(
                ft_stream_read_at(&mut stream, 1, buffer.as_mut_ptr(), 6),
                FT_ERR_INVALID_STREAM_OPERATION
            );
            capture::finish()
        };
        assert_eq!(&buffer[..3], &[2, 3, 4]);
        assert_eq!(stream.pos, 4);
        let formats = unsafe { capture::formats(&calls) };
        assert_eq!(formats.len(), 2);
        assert_eq!(formats[0], "FT_Stream_ReadAt:");
        assert!(formats[1].starts_with(" invalid read; expected"));
        assert_eq!(calls[1].args, [6, 3, 0]); // expected, got
    }

    #[test]
    fn read_at_disk_stream_forwards_to_the_callback_verbatim() {
        let mut stream = disk_stream(16);
        unsafe { reset_io(&[9, 8, 7, 6, 5]) };
        let mut buffer = [0u8; 4];
        assert_eq!(
            unsafe { ft_stream_read_at(&mut stream, 1, buffer.as_mut_ptr(), 4) },
            0
        );
        assert_eq!(&buffer, &[8, 7, 6, 5]);
        assert_eq!(stream.pos, 5);
        assert_eq!(
            unsafe { io_calls() },
            vec![IoCall { offset: 1, buffer_is_null: false, count: 4 }]
        );
        // A disk stream is not clamped to `size` the way a memory
        // stream is — only the leading `pos >= size` test applies.
        assert_eq!(
            unsafe { ft_stream_read_at(&mut stream, 15, buffer.as_mut_ptr(), 4) },
            0
        );
        assert_eq!(stream.pos, 19);
    }

    #[test]
    fn read_reads_at_the_current_position() {
        let _guard = TEST_TRACE_LOCK.lock().unwrap();
        let mut bytes = [0xaau8, 0xbb, 0xcc, 0xdd];
        let mut stream = memory_stream(&mut bytes);
        stream.pos = 2;
        let mut buffer = [0u8; 2];
        unsafe { capture::start() };
        assert_eq!(
            unsafe { ft_stream_read(&mut stream, buffer.as_mut_ptr(), 2) },
            0
        );
        assert_eq!(&buffer, &[0xcc, 0xdd]);
        assert_eq!(stream.pos, 4);
        // Now at the end: `pos >= size` rejects outright.
        assert_eq!(
            unsafe { ft_stream_read(&mut stream, buffer.as_mut_ptr(), 1) },
            FT_ERR_INVALID_STREAM_OPERATION
        );
        assert_eq!(unsafe { capture::finish() }.len(), 1);
        assert_eq!(stream.pos, 4);
    }

    #[test]
    fn try_read_matches_read_at_but_never_errors_or_traces() {
        let source = [0x10u8, 0x20, 0x30, 0x40, 0x50, 0x60];
        for pos in 0..8u32 {
            for count in 0..9u32 {
                let _guard = TEST_TRACE_LOCK.lock().unwrap();
                let mut bytes = source;
                let mut stream = memory_stream(&mut bytes);
                stream.pos = pos;
                let mut buffer = [0xccu8; 12];
                let calls = unsafe {
                    capture::start();
                    let n = ft_stream_try_read(&mut stream, buffer.as_mut_ptr(), count);
                    let calls = capture::finish();
                    assert_eq!(n, if pos >= 6 { 0 } else { (6 - pos).min(count) });
                    calls
                };
                assert!(calls.is_empty(), "try_read must be silent");
                let want_pos = if pos >= 6 { pos } else { pos + (6 - pos).min(count) };
                assert_eq!(stream.pos, want_pos, "pos {pos} count {count}");
                let n = (want_pos - pos) as usize;
                if n > 0 {
                    assert_eq!(&buffer[..n], &source[pos as usize..pos as usize + n]);
                }
                assert!(buffer[n..].iter().all(|&b| b == 0xcc));
            }
        }
    }

    #[test]
    fn try_read_disk_stream_reports_whatever_the_callback_gave() {
        let mut stream = disk_stream(16);
        let mut buffer = [0u8; 4];
        unsafe {
            reset_io(&[1, 2, 3, 4]);
            *core::ptr::addr_of_mut!(IO_SHORT_BY) = 2;
            // A short read is not an error here, just a smaller count.
            assert_eq!(ft_stream_try_read(&mut stream, buffer.as_mut_ptr(), 4), 2);
        }
        assert_eq!(&buffer[..2], &[1, 2]);
        assert_eq!(stream.pos, 2);
    }

    // ------------------------------------------------------------------
    // The frame family and the ftobjs.c create/destroy trio.
    // ------------------------------------------------------------------

    use crate::ft::memory::test_memory::{self, TEST_MEMORY_LOCK};

    /// Both locks, taken in one binding so no sub-case can shadow them.
    fn frame_guards() -> (
        std::sync::MutexGuard<'static, ()>,
        std::sync::MutexGuard<'static, ()>,
    ) {
        (
            TEST_TRACE_LOCK.lock().unwrap(),
            TEST_MEMORY_LOCK.lock().unwrap(),
        )
    }

    /// Reference `FT_Stream_EnterFrame` over a memory stream, straight
    /// from upstream: `Some((cursor offset, limit offset, new pos))`, or
    /// `None` for the `FT_Err_Invalid_Stream_Operation` path.
    fn enter_frame_ref(size: u32, pos: u32, count: u32) -> Option<(u32, u32, u32)> {
        if pos >= size || pos.wrapping_add(count) > size {
            None
        } else {
            Some((pos, pos + count, pos + count))
        }
    }

    #[test]
    fn enter_frame_memory_stream_matches_reference_over_every_position_and_count() {
        let source = [0x10u8, 0x20, 0x30, 0x40, 0x50, 0x60];
        for pos in 0..8u32 {
            for count in 0..9u32 {
                let _guard = TEST_TRACE_LOCK.lock().unwrap();
                let mut bytes = source;
                let base = bytes.as_mut_ptr();
                let mut stream = memory_stream(&mut bytes);
                stream.pos = pos;
                let (error, calls) = unsafe {
                    capture::start();
                    let e = ft_stream_enter_frame(&mut stream, count);
                    (e, capture::finish())
                };
                match enter_frame_ref(6, pos, count) {
                    Some((cursor, limit, new_pos)) => {
                        assert_eq!(error, 0, "pos {pos} count {count}");
                        assert_eq!(stream.cursor, unsafe { base.add(cursor as usize) });
                        assert_eq!(stream.limit, unsafe { base.add(limit as usize) });
                        assert_eq!(stream.pos, new_pos);
                        assert!(calls.is_empty());
                    }
                    None => {
                        assert_eq!(
                            error, FT_ERR_INVALID_STREAM_OPERATION,
                            "pos {pos} count {count}"
                        );
                        // Nothing mapped, nothing moved.
                        assert!(stream.cursor.is_null());
                        assert_eq!(stream.pos, pos);
                        let formats = unsafe { capture::formats(&calls) };
                        assert_eq!(formats.len(), 2);
                        assert_eq!(formats[0], "FT_Stream_EnterFrame:");
                        assert!(formats[1].starts_with(" invalid i/o;"));
                        assert_eq!(calls[1].args, [pos, count, 6]);
                    }
                }
            }
        }
    }

    #[test]
    fn enter_frame_maps_a_window_the_get_family_then_reads() {
        let _guard = TEST_TRACE_LOCK.lock().unwrap();
        let mut bytes = [0x00u8, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x2a, 0xff];
        let mut stream = memory_stream(&mut bytes);
        unsafe {
            assert_eq!(ft_stream_enter_frame(&mut stream, 7), 0);
            assert_eq!(stream.pos, 7);
            assert_eq!(ft_stream_get_long(&mut stream), 0x0001_0000);
            assert_eq!(ft_stream_get_short(&mut stream), 12);
            assert_eq!(ft_stream_get_char(&mut stream), 42);
            // The frame ends before the last byte, so the next read
            // silently yields 0.
            assert_eq!(ft_stream_get_char(&mut stream), 0);
            ft_stream_exit_frame(&mut stream);
        }
        assert!(stream.cursor.is_null() && stream.limit.is_null());
        // A memory stream's frame was never allocated, so `base` stays.
        assert_eq!(stream.base, bytes.as_mut_ptr());
    }

    #[test]
    fn enter_frame_count_wraps_at_the_top_of_the_address_space() {
        // `pos + count` is a 32-bit add, so a huge count wraps below
        // `size` and the window is accepted — upstream's own quirk.
        let _guard = TEST_TRACE_LOCK.lock().unwrap();
        let mut bytes = [0u8; 8];
        let mut stream = memory_stream(&mut bytes);
        stream.pos = 4;
        unsafe {
            assert_eq!(ft_stream_enter_frame(&mut stream, 0xffff_fffc), 0);
        }
        assert_eq!(stream.pos, 0);
    }

    #[test]
    fn enter_frame_disk_stream_allocates_and_fills_the_frame() {
        let guards = frame_guards();
        unsafe {
            let mut memory = test_memory::reset(false);
            let mut stream = disk_stream(64);
            stream.memory = &mut memory;
            stream.pos = 3;
            reset_io(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);

            assert_eq!(ft_stream_enter_frame(&mut stream, 4), 0);
            assert_eq!(
                io_calls(),
                vec![IoCall { offset: 3, buffer_is_null: false, count: 4 }]
            );
            assert_eq!(test_memory::alloc_calls(), 1);
            assert!(!stream.base.is_null());
            assert_eq!(stream.cursor, stream.base);
            assert_eq!(stream.limit, stream.base.add(4));
            assert_eq!(stream.pos, 7);
            assert_eq!(
                core::slice::from_raw_parts(stream.base, 4),
                &[3u8, 4, 5, 6]
            );

            let block = stream.base;
            ft_stream_exit_frame(&mut stream);
            assert_eq!(test_memory::freed(), vec![block]);
            assert!(stream.base.is_null());
            assert!(stream.cursor.is_null() && stream.limit.is_null());
        }
        drop(guards);
    }

    #[test]
    fn enter_frame_disk_stream_short_read_frees_the_block_but_still_maps_it() {
        // Upstream's fall-through, kept bug for bug: the error path frees
        // and nulls `base`, then the shared tail assigns cursor = base
        // (null), limit = base + count (i.e. `count` as a pointer) and
        // advances pos by whatever was read.
        let guards = frame_guards();
        unsafe {
            let mut memory = test_memory::reset(false);
            let mut stream = disk_stream(64);
            stream.memory = &mut memory;
            reset_io(&[0xaa; 16]);
            *core::ptr::addr_of_mut!(IO_SHORT_BY) = 1;

            capture::start();
            let error = ft_stream_enter_frame(&mut stream, 8);
            let calls = capture::finish();

            assert_eq!(error, FT_ERR_INVALID_STREAM_OPERATION);
            assert_eq!(test_memory::free_calls(), 1);
            assert!(stream.base.is_null());
            assert!(stream.cursor.is_null());
            assert_eq!(stream.limit, 8usize as *mut u8);
            assert_eq!(stream.pos, 7);
            let formats = capture::formats(&calls);
            assert_eq!(formats.len(), 2);
            assert_eq!(formats[0], "FT_Stream_EnterFrame:");
            assert!(formats[1].starts_with(" invalid read; expected"));
            assert_eq!(calls[1].args, [8, 7, 0]);
        }
        drop(guards);
    }

    #[test]
    fn enter_frame_disk_stream_rejects_a_count_the_allocator_reads_as_negative() {
        // `count` is an FT_ULong handed to ft_mem_qalloc's signed
        // FT_Long, so 2^31 and up come out negative and are refused with
        // FT_Err_Invalid_Argument before any read happens.
        let guards = frame_guards();
        unsafe {
            let mut memory = test_memory::reset(false);
            let mut stream = disk_stream(64);
            stream.memory = &mut memory;
            reset_io(&[0; 16]);
            assert_eq!(
                ft_stream_enter_frame(&mut stream, 0x8000_0000),
                FT_ERR_INVALID_ARGUMENT
            );
            assert_eq!(test_memory::alloc_calls(), 0);
            assert!(io_calls().is_empty());
            assert_eq!(stream.pos, 0);
        }
        drop(guards);
    }

    #[test]
    fn enter_frame_disk_stream_reports_an_allocation_failure_untouched() {
        let guards = frame_guards();
        unsafe {
            let mut memory = test_memory::reset(true);
            let mut stream = disk_stream(64);
            stream.memory = &mut memory;
            reset_io(&[0; 16]);
            capture::start();
            let error = ft_stream_enter_frame(&mut stream, 8);
            let calls = capture::finish();
            assert_eq!(error, crate::ft::error::FT_ERR_OUT_OF_MEMORY);
            assert!(calls.is_empty());
            assert!(io_calls().is_empty());
            assert!(stream.cursor.is_null());
            assert_eq!(stream.pos, 0);
        }
        drop(guards);
    }

    #[test]
    fn exit_frame_only_frees_a_disk_streams_block() {
        let guards = frame_guards();
        unsafe {
            let mut memory = test_memory::reset(false);
            let mut bytes = [1u8, 2, 3, 4];
            let mut stream = memory_stream(&mut bytes);
            stream.memory = &mut memory;
            assert_eq!(ft_stream_enter_frame(&mut stream, 2), 0);
            ft_stream_exit_frame(&mut stream);
            assert_eq!(test_memory::free_calls(), 0);
            assert_eq!(stream.base, bytes.as_mut_ptr());
            assert!(stream.cursor.is_null() && stream.limit.is_null());
        }
        drop(guards);
    }

    #[test]
    fn extract_frame_hands_the_block_over_and_release_gives_it_back() {
        let guards = frame_guards();
        unsafe {
            let mut memory = test_memory::reset(false);
            let mut stream = disk_stream(64);
            stream.memory = &mut memory;
            reset_io(&[0x11, 0x22, 0x33, 0x44]);

            let mut bytes: *mut u8 = 1 as *mut u8;
            assert_eq!(ft_stream_extract_frame(&mut stream, 4, &mut bytes), 0);
            assert!(!bytes.is_null());
            assert_eq!(core::slice::from_raw_parts(bytes, 4), &[0x11, 0x22, 0x33, 0x44]);
            // The stream has forgotten the frame but has NOT freed it,
            // and `base` still points at it.
            assert!(stream.cursor.is_null() && stream.limit.is_null());
            assert_eq!(stream.base, bytes);
            assert_eq!(test_memory::free_calls(), 0);

            ft_stream_release_frame(&mut stream, &mut bytes);
            assert_eq!(test_memory::freed(), vec![stream.base]);
            assert!(bytes.is_null());
        }
        drop(guards);
    }

    #[test]
    fn extract_frame_leaves_pbytes_alone_when_the_enter_fails() {
        let _guard = TEST_TRACE_LOCK.lock().unwrap();
        let mut bytes = [1u8, 2];
        let mut stream = memory_stream(&mut bytes);
        let mut out = 0x55 as *mut u8;
        unsafe {
            capture::start();
            assert_eq!(
                ft_stream_extract_frame(&mut stream, 9, &mut out),
                FT_ERR_INVALID_STREAM_OPERATION
            );
            capture::finish();
        }
        assert_eq!(out, 0x55 as *mut u8);
    }

    #[test]
    fn release_frame_on_a_memory_stream_only_nulls_the_pointer() {
        let guards = frame_guards();
        unsafe {
            let mut memory = test_memory::reset(false);
            let mut bytes = [1u8, 2, 3, 4];
            let mut stream = memory_stream(&mut bytes);
            stream.memory = &mut memory;
            let mut out = bytes.as_mut_ptr();
            ft_stream_release_frame(&mut stream, &mut out);
            assert_eq!(test_memory::free_calls(), 0);
            assert!(out.is_null());
            // Even a null block is left null, and never reaches the
            // allocator.
            ft_stream_release_frame(&mut stream, &mut out);
            assert!(out.is_null());
        }
        drop(guards);
    }

    /// A library whose allocator is the test arena.
    fn library(memory: *mut FtMemory) -> FtLibrary {
        FtLibrary { memory }
    }

    fn open_args(flags: u32) -> FtOpenArgs {
        FtOpenArgs {
            flags,
            memory_base: core::ptr::null(),
            memory_size: 0,
            pathname: core::ptr::null_mut(),
            stream: core::ptr::null_mut(),
            driver: core::ptr::null_mut(),
            num_params: 0,
            params: core::ptr::null_mut(),
        }
    }

    #[test]
    fn stream_new_rejects_a_null_library_or_args_without_touching_astream() {
        let _guard = TEST_MEMORY_LOCK.lock().unwrap();
        unsafe {
            let mut memory = test_memory::reset(false);
            let mut library = library(&mut memory);
            let args = open_args(FT_OPEN_MEMORY);
            let mut out = 0x1234 as *mut FtStream;
            assert_eq!(
                ft_stream_new(core::ptr::null_mut(), &args, &mut out),
                FT_ERR_INVALID_LIBRARY_HANDLE
            );
            assert_eq!(out, 0x1234 as *mut FtStream);
            assert_eq!(
                ft_stream_new(&mut library, core::ptr::null(), &mut out),
                FT_ERR_INVALID_ARGUMENT
            );
            assert_eq!(out, 0x1234 as *mut FtStream);
            assert_eq!(test_memory::alloc_calls(), 0);
        }
    }

    #[test]
    fn stream_new_open_memory_produces_a_readable_memory_stream() {
        let _guard = TEST_MEMORY_LOCK.lock().unwrap();
        let bytes = [0xdeu8, 0xad, 0xbe, 0xef];
        unsafe {
            let mut memory = test_memory::reset(false);
            let mut library = library(&mut memory);
            let mut args = open_args(FT_OPEN_MEMORY);
            args.memory_base = bytes.as_ptr();
            args.memory_size = 4;
            let mut out = core::ptr::null_mut();
            assert_eq!(ft_stream_new(&mut library, &args, &mut out), 0);
            assert!(!out.is_null());
            assert_eq!((*out).base, bytes.as_ptr() as *mut u8);
            assert_eq!(((*out).size, (*out).pos), (4, 0));
            assert_eq!((*out).memory, &mut memory as *mut FtMemory);
            assert!((*out).read.is_none() && (*out).close.is_none());
            // The record came zeroed from ft_mem_alloc, so the fields
            // FT_Stream_OpenMemory does not write are null.
            assert!((*out).descriptor.is_null() && (*out).limit.is_null());

            let mut error = 0;
            assert_eq!(ft_stream_read_long(out, &mut error), 0xdead_beef_u32 as i32);
        }
    }

    #[test]
    fn stream_new_adopts_an_existing_stream_and_frees_the_fresh_one() {
        let _guard = TEST_MEMORY_LOCK.lock().unwrap();
        let mut bytes = [1u8, 2, 3, 4];
        let mut existing = memory_stream(&mut bytes);
        unsafe {
            let mut memory = test_memory::reset(false);
            let mut library = library(&mut memory);
            let mut args = open_args(FT_OPEN_STREAM);
            args.stream = &mut existing;
            let mut out = core::ptr::null_mut();
            assert_eq!(ft_stream_new(&mut library, &args, &mut out), 0);
            assert_eq!(out, &mut existing as *mut FtStream);
            // The throwaway allocation went straight back.
            assert_eq!(test_memory::alloc_calls(), 1);
            assert_eq!(test_memory::free_calls(), 1);
            // "Just to be certain": the adopted stream gets the library's
            // allocator stamped into it.
            assert_eq!(existing.memory, &mut memory as *mut FtMemory);
        }
    }

    #[test]
    fn stream_new_rejects_an_unusable_flag_set_and_frees_the_stream() {
        let _guard = TEST_MEMORY_LOCK.lock().unwrap();
        unsafe {
            let mut memory = test_memory::reset(false);
            let mut library = library(&mut memory);
            // FT_OPEN_STREAM with a null stream, and a flag set with none
            // of the three bits, both land on FT_Err_Invalid_Argument.
            for flags in [FT_OPEN_STREAM, 0, 0x10] {
                let mut memory = test_memory::reset(false);
                library.memory = &mut memory;
                let args = open_args(flags);
                let mut out = 0x1234 as *mut FtStream;
                assert_eq!(
                    ft_stream_new(&mut library, &args, &mut out),
                    FT_ERR_INVALID_ARGUMENT,
                    "flags {flags:#x}"
                );
                assert!(out.is_null(), "flags {flags:#x}");
                assert_eq!(test_memory::free_calls(), 1, "flags {flags:#x}");
            }
        }
    }

    #[test]
    fn stream_new_reports_an_allocation_failure_and_clears_astream() {
        let _guard = TEST_MEMORY_LOCK.lock().unwrap();
        unsafe {
            let mut memory = test_memory::reset(true);
            let mut library = library(&mut memory);
            let args = open_args(FT_OPEN_MEMORY);
            let mut out = 0x1234 as *mut FtStream;
            assert_eq!(
                ft_stream_new(&mut library, &args, &mut out),
                crate::ft::error::FT_ERR_OUT_OF_MEMORY
            );
            // Cleared before the allocation, and left cleared.
            assert!(out.is_null());
        }
    }

    #[test]
    fn stream_new_pathname_records_the_path_even_when_the_open_fails() {
        let _guards = (
            TEST_MEMORY_LOCK.lock().unwrap(),
            crate::ft::system::TEST_OPS_LOCK.lock().unwrap(),
        );
        let path = b"0:/nowhere\0";
        unsafe {
            // No platform file layer installed, so every open fails.
            assert!(crate::ft::system::ft_set_platform_file_ops(None).is_none());
            let mut memory = test_memory::reset(false);
            let mut library = library(&mut memory);
            let mut args = open_args(FT_OPEN_PATHNAME);
            args.pathname = path.as_ptr() as *mut core::ffi::c_void;
            let mut out = 0x1234 as *mut FtStream;
            assert_eq!(
                ft_stream_new(&mut library, &args, &mut out),
                crate::ft::error::FT_ERR_CANNOT_OPEN_RESOURCE
            );
            // The stream was freed and the handle cleared, but the
            // pathname store happened first — on the record that is now
            // back with the allocator.
            assert!(out.is_null());
            assert_eq!(test_memory::free_calls(), 1);
        }
    }

    #[test]
    fn stream_free_closes_and_returns_the_record_unless_it_is_external() {
        let _guard = TEST_MEMORY_LOCK.lock().unwrap();
        unsafe {
            *core::ptr::addr_of_mut!(CLOSE_CALLS) = 0;
            let mut memory = test_memory::reset(false);
            let mut library = library(&mut memory);
            let mut args = open_args(FT_OPEN_MEMORY);
            args.memory_size = 0;
            let mut out = core::ptr::null_mut();
            assert_eq!(ft_stream_new(&mut library, &args, &mut out), 0);
            (*out).close = Some(record_close);

            ft_stream_free(out, 0);
            assert_eq!(*core::ptr::addr_of!(CLOSE_CALLS), 1);
            assert_eq!(test_memory::freed(), vec![out as *mut u8]);

            // `external` keeps the record; the close still runs.
            let mut memory = test_memory::reset(false);
            library.memory = &mut memory;
            assert_eq!(ft_stream_new(&mut library, &args, &mut out), 0);
            (*out).close = Some(record_close);
            ft_stream_free(out, 1);
            assert_eq!(*core::ptr::addr_of!(CLOSE_CALLS), 2);
            assert_eq!(test_memory::free_calls(), 0);

            // A null stream is a no-op.
            ft_stream_free(core::ptr::null_mut(), 0);
            assert_eq!(*core::ptr::addr_of!(CLOSE_CALLS), 2);
        }
    }

    // ------------------------------------------------------------------
    // FT_Stream_ReadFields.
    // ------------------------------------------------------------------

    fn field(value: u8, size: u8, offset: u16) -> FtFrameField {
        FtFrameField { value, size, offset }
    }

    /// Reference `FT_Stream_ReadFields` over an already-entered frame,
    /// transcribed from upstream: returns `(error, cursor index)` and
    /// fills `structure`. Handles every opcode except `FT_FRAME_START`,
    /// which needs a live stream.
    fn read_fields_ref(
        frame: &[u8],
        fields: &[FtFrameField],
        structure: &mut [u8],
    ) -> (i32, usize) {
        let mut cursor = 0usize;
        for f in fields {
            let (value, sign_shift): (u32, u32) = match f.value {
                FT_FRAME_BYTES | FT_FRAME_SKIP => {
                    let len = f.size as usize;
                    if cursor + len > frame.len() {
                        return (FT_ERR_INVALID_STREAM_OPERATION, cursor);
                    }
                    if f.value == FT_FRAME_BYTES {
                        let at = f.offset as usize;
                        structure[at..at + len].copy_from_slice(&frame[cursor..cursor + len]);
                    }
                    cursor += len;
                    continue;
                }
                FT_FRAME_BYTE | FT_FRAME_SCHAR => {
                    cursor += 1;
                    (frame[cursor - 1] as u32, 24)
                }
                FT_FRAME_USHORT_BE | FT_FRAME_SHORT_BE => {
                    cursor += 2;
                    (u16::from_be_bytes([frame[cursor - 2], frame[cursor - 1]]) as u32, 16)
                }
                FT_FRAME_USHORT_LE | FT_FRAME_SHORT_LE => {
                    cursor += 2;
                    (u16::from_le_bytes([frame[cursor - 2], frame[cursor - 1]]) as u32, 16)
                }
                FT_FRAME_ULONG_BE | FT_FRAME_LONG_BE => {
                    cursor += 4;
                    (
                        u32::from_be_bytes(frame[cursor - 4..cursor].try_into().unwrap()),
                        0,
                    )
                }
                FT_FRAME_ULONG_LE | FT_FRAME_LONG_LE => {
                    cursor += 4;
                    (
                        u32::from_le_bytes(frame[cursor - 4..cursor].try_into().unwrap()),
                        0,
                    )
                }
                FT_FRAME_UOFF3_BE | FT_FRAME_OFF3_BE => {
                    cursor += 3;
                    let p = &frame[cursor - 3..cursor];
                    (
                        ((p[0] as u32) << 16) | ((p[1] as u32) << 8) | p[2] as u32,
                        8,
                    )
                }
                FT_FRAME_UOFF3_LE | FT_FRAME_OFF3_LE => {
                    cursor += 3;
                    let p = &frame[cursor - 3..cursor];
                    (
                        (p[0] as u32) | ((p[1] as u32) << 8) | ((p[2] as u32) << 16),
                        8,
                    )
                }
                _ => return (0, cursor),
            };

            let value = if f.value & FT_FRAME_OP_SIGNED != 0 {
                (((value << sign_shift) as i32) >> sign_shift) as u32
            } else {
                value
            };
            let at = f.offset as usize;
            let bytes = value.to_le_bytes();
            let width = if f.size == 1 {
                1
            } else if f.size == 2 {
                2
            } else {
                4
            };
            structure[at..at + width].copy_from_slice(&bytes[..width]);
        }
        (0, cursor)
    }

    /// Runs the port over `frame` mapped as a pre-entered frame.
    fn run_read_fields(frame: &mut [u8], fields: &[FtFrameField], structure: &mut [u8]) -> (i32, usize) {
        let base = frame.as_mut_ptr();
        let mut stream = framed_stream(frame);
        stream.cursor = base;
        let error = unsafe {
            ft_stream_read_fields(&mut stream, fields.as_ptr(), structure.as_mut_ptr())
        };
        (error, unsafe { stream.cursor.offset_from(base) } as usize)
    }

    #[test]
    fn read_fields_rejects_a_null_stream_or_table() {
        let mut bytes = [0u8; 4];
        let mut stream = memory_stream(&mut bytes);
        let fields = [field(FT_FRAME_END, 0, 0)];
        let mut out = [0u8; 4];
        unsafe {
            assert_eq!(
                ft_stream_read_fields(&mut stream, core::ptr::null(), out.as_mut_ptr()),
                FT_ERR_INVALID_ARGUMENT
            );
            assert_eq!(
                ft_stream_read_fields(core::ptr::null_mut(), fields.as_ptr(), out.as_mut_ptr()),
                FT_ERR_INVALID_ARGUMENT
            );
        }
    }

    #[test]
    fn read_fields_decodes_every_opcode_like_the_reference() {
        // One row per opcode, each into its own 4-byte slot.
        let ops = [
            FT_FRAME_BYTE,
            FT_FRAME_SCHAR,
            FT_FRAME_USHORT_BE,
            FT_FRAME_SHORT_BE,
            FT_FRAME_USHORT_LE,
            FT_FRAME_SHORT_LE,
            FT_FRAME_ULONG_BE,
            FT_FRAME_LONG_BE,
            FT_FRAME_ULONG_LE,
            FT_FRAME_LONG_LE,
            FT_FRAME_UOFF3_BE,
            FT_FRAME_OFF3_BE,
            FT_FRAME_UOFF3_LE,
            FT_FRAME_OFF3_LE,
        ];
        let source = [0x80u8, 0xff, 0x7f, 0x01, 0xfe, 0x00, 0x91, 0xa2, 0xb3, 0xc4, 0x00, 0x00];
        for (index, &op) in ops.iter().enumerate() {
            for &width in &[1u8, 2, 4] {
                let mut frame = source;
                let fields = [field(op, width, 0), field(FT_FRAME_END, 0, 0)];
                let mut got = [0xccu8; 8];
                let (error, cursor) = run_read_fields(&mut frame, &fields, &mut got);

                let mut want = [0xccu8; 8];
                let (want_error, want_cursor) = read_fields_ref(&source, &fields, &mut want);
                assert_eq!(
                    (error, cursor, got),
                    (want_error, want_cursor, want),
                    "op {op} ({index}) width {width}"
                );
            }
        }
    }

    #[test]
    fn read_fields_sign_extends_only_the_odd_opcodes() {
        // 0xff as a byte: schar -> -1, byte -> 255. Same pair at every
        // width, which is what the shared 24/16/8/0 shift buys.
        let mut frame = [0xffu8, 0xff, 0xff, 0xff, 0, 0, 0, 0];
        for (op, want) in [
            (FT_FRAME_BYTE, 0x0000_00ffu32),
            (FT_FRAME_SCHAR, 0xffff_ffff),
            (FT_FRAME_USHORT_BE, 0x0000_ffff),
            (FT_FRAME_SHORT_BE, 0xffff_ffff),
            (FT_FRAME_UOFF3_BE, 0x00ff_ffff),
            (FT_FRAME_OFF3_BE, 0xffff_ffff),
            (FT_FRAME_ULONG_BE, 0xffff_ffff),
            (FT_FRAME_LONG_BE, 0xffff_ffff),
        ] {
            let fields = [field(op, 4, 0), field(FT_FRAME_END, 0, 0)];
            let mut got = [0u8; 4];
            let (error, _) = run_read_fields(&mut frame, &fields, &mut got);
            assert_eq!((error, u32::from_le_bytes(got)), (0, want), "op {op}");
        }
    }

    #[test]
    fn read_fields_endianness_is_the_bit_1_of_the_opcode() {
        // Hardcoded expectations, so this does not lean on the
        // reference implementation sharing a mistake with the port.
        let mut frame = [0x12u8, 0x34, 0x56, 0x78, 0, 0, 0, 0];
        for (op, want) in [
            (FT_FRAME_USHORT_BE, 0x0000_1234u32),
            (FT_FRAME_USHORT_LE, 0x0000_3412),
            (FT_FRAME_UOFF3_BE, 0x0012_3456),
            (FT_FRAME_UOFF3_LE, 0x0056_3412),
            (FT_FRAME_ULONG_BE, 0x1234_5678),
            (FT_FRAME_ULONG_LE, 0x7856_3412),
        ] {
            let fields = [field(op, 4, 0), field(FT_FRAME_END, 0, 0)];
            let mut got = [0u8; 4];
            let (error, _) = run_read_fields(&mut frame, &fields, &mut got);
            assert_eq!((error, u32::from_le_bytes(got)), (0, want), "op {op}");
        }
    }

    #[test]
    fn read_fields_narrow_stores_truncate_the_value() {
        // `size` picks strb/strh/str; a sign-extended value stored into
        // one byte keeps only its low byte.
        let mut frame = [0x12u8, 0x34, 0x56, 0x78, 0, 0, 0, 0];
        let fields = [field(FT_FRAME_ULONG_BE, 2, 2), field(FT_FRAME_END, 0, 0)];
        let mut got = [0xffu8; 8];
        let (error, cursor) = run_read_fields(&mut frame, &fields, &mut got);
        assert_eq!((error, cursor), (0, 4));
        // Only the two bytes at offset 2 moved.
        assert_eq!(&got, &[0xff, 0xff, 0x78, 0x56, 0xff, 0xff, 0xff, 0xff]);
    }

    #[test]
    fn read_fields_bytes_copies_and_skip_only_advances() {
        let mut frame = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let fields = [
            field(FT_FRAME_SKIP, 2, 0),
            field(FT_FRAME_BYTES, 3, 1),
            field(FT_FRAME_END, 0, 0),
        ];
        let mut got = [0xccu8; 8];
        let (error, cursor) = run_read_fields(&mut frame, &fields, &mut got);
        assert_eq!((error, cursor), (0, 5));
        assert_eq!(&got, &[0xcc, 3, 4, 5, 0xcc, 0xcc, 0xcc, 0xcc]);

        let mut want = [0xccu8; 8];
        let source = [1u8, 2, 3, 4, 5, 6, 7, 8];
        assert_eq!(read_fields_ref(&source, &fields, &mut want), (0, 5));
        assert_eq!(got, want);
    }

    #[test]
    fn read_fields_bytes_past_the_limit_fails_without_writing_the_cursor_back() {
        // `cursor + len > limit` is the only bound this function has,
        // and the error exit skips the `stream->cursor = cursor`
        // writeback the default arm does.
        let mut frame = [1u8, 2, 3, 4];
        let base = frame.as_mut_ptr();
        let mut stream = framed_stream(&mut frame);
        stream.cursor = base;
        let fields = [
            field(FT_FRAME_SKIP, 2, 0),
            field(FT_FRAME_BYTES, 3, 0),
            field(FT_FRAME_END, 0, 0),
        ];
        let mut got = [0xccu8; 8];
        let error = unsafe {
            ft_stream_read_fields(&mut stream, fields.as_ptr(), got.as_mut_ptr())
        };
        assert_eq!(error, FT_ERR_INVALID_STREAM_OPERATION);
        assert_eq!(stream.cursor, base); // never written back
        assert!(got.iter().all(|&b| b == 0xcc));
        // Exactly `len` bytes left is still legal.
        let fields = [
            field(FT_FRAME_SKIP, 2, 0),
            field(FT_FRAME_BYTES, 2, 0),
            field(FT_FRAME_END, 0, 0),
        ];
        let (error, cursor) = run_read_fields(&mut frame, &fields, &mut got);
        assert_eq!((error, cursor), (0, 4));
    }

    #[test]
    fn read_fields_unlisted_opcodes_all_end_the_walk() {
        // The jump table covers 4..=25 with holes: 5..7 and 10..11 name
        // no opcode and fall to `default:` exactly like ft_frame_end.
        let mut frame = [0xaau8; 8];
        for op in [FT_FRAME_END, 1, 2, 3, 5, 6, 7, 10, 11, 26, 255] {
            let fields = [
                field(FT_FRAME_BYTE, 1, 0),
                field(op, 4, 4),
                field(FT_FRAME_BYTE, 1, 1),
                field(FT_FRAME_END, 0, 0),
            ];
            let mut got = [0u8; 8];
            let (error, cursor) = run_read_fields(&mut frame, &fields, &mut got);
            assert_eq!((error, cursor), (0, 1), "op {op}");
            // The second reader never ran.
            assert_eq!(got, [0xaa, 0, 0, 0, 0, 0, 0, 0], "op {op}");
        }
    }

    #[test]
    fn read_fields_start_enters_a_frame_and_always_exits_it() {
        let guards = frame_guards();
        unsafe {
            let mut memory = test_memory::reset(false);
            let mut stream = disk_stream(64);
            stream.memory = &mut memory;
            reset_io(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x2a, 0x99]);

            let fields = [
                field(FT_FRAME_START, 0, 7),
                field(FT_FRAME_ULONG_BE, 4, 0),
                field(FT_FRAME_USHORT_BE, 2, 4),
                field(FT_FRAME_SCHAR, 1, 6),
                field(FT_FRAME_END, 0, 0),
            ];
            let mut got = [0u8; 8];
            assert_eq!(
                ft_stream_read_fields(&mut stream, fields.as_ptr(), got.as_mut_ptr()),
                0
            );
            assert_eq!(u32::from_le_bytes(got[0..4].try_into().unwrap()), 0x0001_0000);
            assert_eq!(u16::from_le_bytes(got[4..6].try_into().unwrap()), 12);
            assert_eq!(got[6], 42);
            // The frame it opened is closed and its block returned.
            assert!(stream.cursor.is_null() && stream.limit.is_null());
            assert_eq!(test_memory::free_calls(), 1);
            assert_eq!(stream.pos, 7);
        }
        drop(guards);
    }

    #[test]
    fn read_fields_start_that_fails_reports_it_and_opens_no_frame() {
        let _guard = TEST_TRACE_LOCK.lock().unwrap();
        let mut bytes = [1u8, 2, 3];
        let mut stream = memory_stream(&mut bytes);
        let fields = [
            field(FT_FRAME_START, 0, 9), // longer than the stream
            field(FT_FRAME_BYTE, 1, 0),
            field(FT_FRAME_END, 0, 0),
        ];
        let mut got = [0xccu8; 4];
        let error = unsafe {
            capture::start();
            let e = ft_stream_read_fields(&mut stream, fields.as_ptr(), got.as_mut_ptr());
            capture::finish();
            e
        };
        assert_eq!(error, FT_ERR_INVALID_STREAM_OPERATION);
        assert!(got.iter().all(|&b| b == 0xcc));
        assert!(stream.cursor.is_null());
    }

    #[test]
    fn read_fields_matches_the_reference_over_random_tables() {
        let mut state = 0x2468_ace0_u32;
        let readers = [
            FT_FRAME_BYTE,
            FT_FRAME_SCHAR,
            FT_FRAME_USHORT_BE,
            FT_FRAME_SHORT_BE,
            FT_FRAME_USHORT_LE,
            FT_FRAME_SHORT_LE,
            FT_FRAME_ULONG_BE,
            FT_FRAME_LONG_BE,
            FT_FRAME_ULONG_LE,
            FT_FRAME_LONG_LE,
            FT_FRAME_UOFF3_BE,
            FT_FRAME_OFF3_BE,
            FT_FRAME_UOFF3_LE,
            FT_FRAME_OFF3_LE,
            FT_FRAME_BYTES,
            FT_FRAME_SKIP,
        ];
        for _ in 0..500 {
            let mut frame = [0u8; 32];
            for byte in frame.iter_mut() {
                *byte = next_random(&mut state) as u8;
            }
            let source = frame;

            // A table whose reads always fit inside the 32-byte frame.
            let mut fields = vec![];
            let mut consumed = 0usize;
            while consumed + 4 <= 24 {
                let op = readers[(next_random(&mut state) % readers.len() as u32) as usize];
                let size = match op {
                    FT_FRAME_BYTES | FT_FRAME_SKIP => 4,
                    _ => [1u8, 2, 4][(next_random(&mut state) % 3) as usize],
                };
                let offset = (next_random(&mut state) % 12) as u16 * 4;
                fields.push(field(op, size, offset));
                consumed += 4;
            }
            fields.push(field(FT_FRAME_END, 0, 0));

            let mut got = [0xccu8; 64];
            let (error, cursor) = run_read_fields(&mut frame, &fields, &mut got);
            let mut want = [0xccu8; 64];
            let (want_error, want_cursor) = read_fields_ref(&source, &fields, &mut want);
            assert_eq!((error, cursor), (want_error, want_cursor));
            assert_eq!(got, want);
        }
    }

    // NOT TESTED, deliberately: the null-`stream` FT_ASSERT path. It
    // diverges through `ft_panic` -> `exit`, which parks forever on
    // target and cannot be unwound out of an `extern "C"` frame on the
    // host (see the same note in src/runtime/raise.rs).
}
