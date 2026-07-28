//! FreeType `ftstream` — the byte-order-aware stream cursor
//! (`FT_Stream_Seek`, `FT_Stream_Skip` and the `FT_Stream_ReadChar` /
//! `ReadShort` / `ReadOffset` / `ReadLong` / `ReadLongLE` readers) as
//! compiled into retailOS. The `FT_ASSERT` calls of this debug build are
//! live, and their `__FILE__` pointers resolve to
//! `...\freetype\src\base\ftstream.c`, which is how these are pinned to
//! that translation unit. Call counts are binary-scanned b/bl words.
//!
//! The `__LINE__` literals the asserts carry order the readers exactly
//! as upstream `ftstream.c` lays them out — `ReadChar` 437,
//! `ReadShort` 475, `ReadOffset` 569, `ReadLong` 616, `ReadLongLE` 662 —
//! which is the second, independent confirmation of each name (the first
//! being the `"FT_Stream_ReadXxx:"` trace tag inside each function).
//! The `ReadShortLE` that upstream puts between `ReadShort` and
//! `ReadOffset` has no trace string anywhere in the image: this build
//! dropped it.
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

use crate::ft::trace::{ft_error_trace, ft_panic};

/// `FT_Err_Invalid_Stream_Operation` — the `mov r0, #85` every failure
/// path in this module stores through `error`.
pub const FT_ERR_INVALID_STREAM_OPERATION: i32 = 0x55;

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
/// `close` @ +24, `memory` @ +28, `cursor` @ +32, `limit` @ +36 — the
/// four offsets the ported functions touch (+0, +4, +8, +0x14) are
/// confirmed by the machine code.
#[repr(C)]
pub struct FtStream {
    pub base: *mut u8,
    pub size: u32,
    pub pos: u32,
    pub descriptor: *mut core::ffi::c_void,
    pub pathname: *mut core::ffi::c_void,
    pub read: Option<FtStreamIoFunc>,
    pub close: Option<FtStreamCloseFunc>,
    pub memory: *mut core::ffi::c_void,
    pub cursor: *mut u8,
    pub limit: *mut u8,
}

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

/// `FT_ASSERT`'s message and the `__FILE__` these two readers pass.
static ASSERTION_FAILED: &[u8] = b"assertion failed on line %d of file %s\n\0";
static FTSTREAM_C: &[u8] =
    b"c:\\BWA\\N25CFirmwareWin-75\\srcroot\\Firmware\\Silver\\3rdParty\\freetype\\src\\base\\ftstream.c\0";

/// `FT_ASSERT( stream )` `__LINE__` literals baked into each reader,
/// read out of its literal pool.
const ASSERT_LINE_READ_CHAR: u32 = 437;
const ASSERT_LINE_READ_SHORT: u32 = 475;
const ASSERT_LINE_READ_OFFSET: u32 = 569;
const ASSERT_LINE_READ_LONG: u32 = 616;
const ASSERT_LINE_READ_LONG_LE: u32 = 662;

/// `FT_ASSERT( stream )` — diverges through [`ft_panic`], exactly like
/// the original, whose code after the call is unreachable.
///
/// # Safety
/// Only called with a null `stream`; never returns.
#[inline]
unsafe fn assert_stream_failed(line: u32) -> ! {
    ft_panic(
        ASSERTION_FAILED.as_ptr(),
        line,
        FTSTREAM_C.as_ptr() as usize as u32,
        0,
    )
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
            crate::libc::memcpy::memcpy(
                buffer,
                (*stream).base.add(pos as usize),
                available as usize,
            );
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
            crate::libc::memcpy::memcpy(
                buffer,
                (*stream).base.add(pos as usize),
                available as usize,
            );
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
        assert_stream_failed(ASSERT_LINE_READ_CHAR);
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
        assert_stream_failed(ASSERT_LINE_READ_SHORT);
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
        assert_stream_failed(ASSERT_LINE_READ_OFFSET);
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
        assert_stream_failed(ASSERT_LINE_READ_LONG);
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
        assert_stream_failed(ASSERT_LINE_READ_LONG_LE);
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

    // NOT TESTED, deliberately: the null-`stream` FT_ASSERT path. It
    // diverges through `ft_panic` -> `exit`, which parks forever on
    // target and cannot be unwound out of an `extern "C"` frame on the
    // host (see the same note in src/runtime/raise.rs).
}
