//! Buffered FreeType stream accounting.
//!
//! The `buff`-tagged, 48-byte record in the 0x08042cfc..0x08042fd4
//! helper family fronts the FreeType I/O callbacks. Its cursor points
//! into a buffer: in output mode the span from `buffer_start` to `cursor`
//! is buffered, while in input mode the inclusive span from `cursor` to
//! `buffer_end` is available to its reader.

/// The target's 48-byte buffered-stream record.
///
/// The I/O context is a 32-bit target handle. The allocation at +0x14 is
/// released during finalization; +0x24 remains a word-sized placeholder and
/// +0x28 is the cached 64-bit stream position.
#[repr(C)]
pub struct FtBufferedStream {
    pub magic: u32,
    pub finalized: u8,
    /// Nonzero selects the input-buffer formula; zero selects output mode.
    pub is_input: u8,
    pub state_reserved: [u8; 2],
    pub io_context: u32,
    pub io_reserved: [u32; 2],
    /// +0x14: tag-4 heap allocation freed when the stream is finalized.
    pub buffer_allocation: u32,
    /// +0x18: current byte within the buffer.
    pub cursor: u32,
    /// +0x1c: first byte of an output buffer.
    pub buffer_start: u32,
    /// +0x20: last byte of an input buffer, inclusive.
    pub buffer_end: u32,
    pub position_reserved: u32,
    /// +0x28: underlying stream position cached for input mode.
    pub cached_position: u64,
}

const _: () = assert!(core::mem::size_of::<FtBufferedStream>() == 48);
const _: () = assert!(core::mem::offset_of!(FtBufferedStream, is_input) == 5);
const _: () = assert!(core::mem::offset_of!(FtBufferedStream, cursor) == 0x18);
const _: () = assert!(core::mem::offset_of!(FtBufferedStream, buffer_allocation) == 0x14);
const _: () = assert!(core::mem::offset_of!(FtBufferedStream, buffer_start) == 0x1c);
const _: () = assert!(core::mem::offset_of!(FtBufferedStream, buffer_end) == 0x20);
const _: () = assert!(core::mem::offset_of!(FtBufferedStream, cached_position) == 0x28);

/// ABI of the unported backing-stream tell helper at `0x0805b73c`.
pub type BackingStreamTellFn = unsafe extern "C" fn(io_context: u32, position: *mut u64) -> i32;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_backing_stream_tell(
    io_context: u32,
    position: *mut u64,
) -> i32 {
    let tell: BackingStreamTellFn = core::mem::transmute(0x0805b73cusize);
    tell(io_context, position)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_backing_stream_tell(_io_context: u32, _position: *mut u64) -> i32 {
    panic!("buffered_stream_tell requires backing tell 0x0805b73c")
}

/// Host-replaceable backing-position call. `0x0805b73c` is absent from
/// `names.yaml`; target builds dispatch to that verified retailOS address.
pub static mut BACKING_STREAM_TELL: BackingStreamTellFn = firmware_backing_stream_tell;

/// ABI of the unported backing-stream size helper at `0x0805b714`.
pub type BackingStreamSizeFn = unsafe extern "C" fn(io_context: u32, size: *mut u64) -> i32;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_backing_stream_size(io_context: u32, size: *mut u64) -> i32 {
    let size_query: BackingStreamSizeFn = core::mem::transmute(0x0805b714usize);
    size_query(io_context, size)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_backing_stream_size(_io_context: u32, _size: *mut u64) -> i32 {
    panic!("ft_buffered_stream_get_size requires backing size 0x0805b714")
}

/// Host-replaceable backing-size call. Target builds dispatch directly to the
/// verified but unported retailOS wrapper at `0x0805b714`.
pub static mut BACKING_STREAM_SIZE: BackingStreamSizeFn = firmware_backing_stream_size;

#[inline(always)]
unsafe fn backing_stream_size() -> BackingStreamSizeFn {
    core::ptr::read_volatile(core::ptr::addr_of!(BACKING_STREAM_SIZE))
}

#[inline(always)]
unsafe fn backing_stream_tell() -> BackingStreamTellFn {
    core::ptr::read_volatile(core::ptr::addr_of!(BACKING_STREAM_TELL))
}

/// ABI of the unported backing-stream write helper at `0x0805b834`.
pub type BackingStreamWriteFn =
    unsafe extern "C" fn(io_context: u32, transferred: *mut u32, data: u32) -> i32;

/// ABI of the unported backing-stream seek helper at `0x0805b804`.
pub type BackingStreamSeekFn = unsafe extern "C" fn(io_context: u32, position: u64) -> i32;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_backing_stream_write(
    io_context: u32,
    transferred: *mut u32,
    data: u32,
) -> i32 {
    let write: BackingStreamWriteFn = core::mem::transmute(0x0805b834usize);
    write(io_context, transferred, data)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_backing_stream_write(
    _io_context: u32,
    _transferred: *mut u32,
    _data: u32,
) -> i32 {
    panic!("ft_buffered_stream_flush requires backing write 0x0805b834")
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_backing_stream_seek(io_context: u32, position: u64) -> i32 {
    let seek: BackingStreamSeekFn = core::mem::transmute(0x0805b804usize);
    seek(io_context, position)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_backing_stream_seek(_io_context: u32, _position: u64) -> i32 {
    panic!("ft_buffered_stream_flush requires backing seek 0x0805b804")
}

/// Host-replaceable direct calls retained as volatile seams. The two helpers
/// are unported in `names.yaml`; target builds invoke their verified retailOS
/// entries.
pub static mut BACKING_STREAM_WRITE: BackingStreamWriteFn = firmware_backing_stream_write;
pub static mut BACKING_STREAM_SEEK: BackingStreamSeekFn = firmware_backing_stream_seek;

#[inline(always)]
unsafe fn backing_stream_write() -> BackingStreamWriteFn {
    core::ptr::read_volatile(core::ptr::addr_of!(BACKING_STREAM_WRITE))
}

#[inline(always)]
unsafe fn backing_stream_seek() -> BackingStreamSeekFn {
    core::ptr::read_volatile(core::ptr::addr_of!(BACKING_STREAM_SEEK))
}

/// ABI of the unported I/O-context finalizer at `0x0805b6d8`.
pub type BufferedStreamIoContextFinalizeFn = unsafe extern "C" fn(io_context: u32);

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_buffered_stream_io_context_finalize(io_context: u32) {
    let finalize: BufferedStreamIoContextFinalizeFn = core::mem::transmute(0x0805b6d8usize);
    finalize(io_context);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_buffered_stream_io_context_finalize(_io_context: u32) {
    panic!("buffered_stream_finalize requires I/O-context finalizer 0x0805b6d8")
}

/// Host-replaceable direct call retained as a volatile seam because the
/// finalizer is unported in `names.yaml`.
pub static mut BUFFERED_STREAM_IO_CONTEXT_FINALIZE: BufferedStreamIoContextFinalizeFn =
    firmware_buffered_stream_io_context_finalize;

#[inline(always)]
unsafe fn buffered_stream_io_context_finalize() -> BufferedStreamIoContextFinalizeFn {
    core::ptr::read_volatile(core::ptr::addr_of!(BUFFERED_STREAM_IO_CONTEXT_FINALIZE))
}

/// ABI of the unported data-backed I/O-context constructor at `0x0805b764`.
///
/// The raw call site passes `out_context`, `data`, input mode `1`, the
/// `data` tag, and the requested buffer size.
pub type BufferedStreamDataContextCreateFn =
    unsafe extern "C" fn(out_context: *mut u32, data: u32, is_input: u32, tag: u32, buffer_size: u32) -> i32;

/// ABI of the unported buffered-stream initializer at `0x080f06f4`.
pub type BufferedStreamInitializeFn =
    unsafe extern "C" fn(stream: *mut FtBufferedStream, data: u32, is_input: u32, buffer_size: u32, io_context: u32) -> i32;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_buffered_stream_data_context_create(
    out_context: *mut u32,
    data: u32,
    is_input: u32,
    tag: u32,
    buffer_size: u32,
) -> i32 {
    let create: BufferedStreamDataContextCreateFn = core::mem::transmute(0x0805b764usize);
    create(out_context, data, is_input, tag, buffer_size)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_buffered_stream_data_context_create(
    _out_context: *mut u32,
    _data: u32,
    _is_input: u32,
    _tag: u32,
    _buffer_size: u32,
) -> i32 {
    panic!("ft_buffered_stream_init_data requires data-context constructor 0x0805b764")
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_buffered_stream_initialize(
    stream: *mut FtBufferedStream,
    data: u32,
    is_input: u32,
    buffer_size: u32,
    io_context: u32,
) -> i32 {
    let initialize: BufferedStreamInitializeFn = core::mem::transmute(0x080f06f4usize);
    initialize(stream, data, is_input, buffer_size, io_context)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_buffered_stream_initialize(
    _stream: *mut FtBufferedStream,
    _data: u32,
    _is_input: u32,
    _buffer_size: u32,
    _io_context: u32,
) -> i32 {
    panic!("ft_buffered_stream_init_data requires stream initializer 0x080f06f4")
}

/// Host-replaceable direct calls retained as volatile seams. The two callees
/// are absent from `names.yaml`; target builds invoke their verified retailOS
/// entries.
pub static mut BUFFERED_STREAM_DATA_CONTEXT_CREATE: BufferedStreamDataContextCreateFn =
    firmware_buffered_stream_data_context_create;
pub static mut BUFFERED_STREAM_INITIALIZE: BufferedStreamInitializeFn =
    firmware_buffered_stream_initialize;

#[inline(always)]
unsafe fn buffered_stream_data_context_create() -> BufferedStreamDataContextCreateFn {
    core::ptr::read_volatile(core::ptr::addr_of!(BUFFERED_STREAM_DATA_CONTEXT_CREATE))
}

#[inline(always)]
unsafe fn buffered_stream_initialize() -> BufferedStreamInitializeFn {
    core::ptr::read_volatile(core::ptr::addr_of!(BUFFERED_STREAM_INITIALIZE))
}

/// ft_buffered_stream_init_data — original: `FUN_08042efc` @ `0x08042efc`
/// (104 bytes; 4 verified direct inbound `bl` call sites). Its body has two
/// plain `bl` calls and one `blne`.
///
/// Validates the `data` tag, creates an input I/O context for `data`, then
/// initializes `stream` with that context and the requested buffer size. If
/// context creation succeeds but stream initialization fails, it finalizes the
/// partially initialized stream. A foreign tag returns -50 without calls.
///
/// Deliberate deviation: the unported context constructor at `0x0805b764` and
/// stream initializer at `0x080f06f4` are volatile dispatch seams on host and
/// indirect dispatches to their verified retailOS entries on target. Raw `osos.dec`
/// decoding confirms the body ends with literal `0x64617461` at `0x08042f64`;
/// # Safety
///
/// `stream` must be a valid, aligned writable [`FtBufferedStream`].
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.ft_buffered_stream_init_data")]
#[inline(never)]
pub unsafe extern "C" fn ft_buffered_stream_init_data(
    data: u32,
    stream: *mut FtBufferedStream,
    buffer_size: u32,
    tag: u32,
) -> i32 {
    const DATA_TAG: u32 = u32::from_le_bytes(*b"atad");

    if tag != DATA_TAG {
        return -50;
    }

    let mut io_context = 0;
    let result = buffered_stream_data_context_create()(
        &mut io_context,
        data,
        1,
        tag,
        buffer_size,
    );
    if result != 0 {
        return result;
    }

    let result = buffered_stream_initialize()(stream, data, 1, buffer_size, io_context);
    if result != 0 {
        ft_buffered_stream_finalize(stream);
    }
    result
}

#[cfg(test)]
pub(crate) static BUFFERED_STREAM_INIT_DATA_TEST_LOCK: parking_lot::Mutex<()> =
    parking_lot::Mutex::new(());

/// ft_buffered_stream_finalize — original: `FUN_08042cfc` @ `0x08042cfc`
/// (104 bytes; 8 verified direct `bl` call sites: 6 unconditional and 2
/// `blne`).
///
/// Validates the `buff` tag, marks the stream finalized, flushes only output
/// streams, then always finalizes the I/O context. A non-null +0x14 tag-4
/// allocation is released and all 48 record bytes are zeroed. The output
/// flush result is retained across the subsequent teardown; an invalid tag
/// returns -50 without modifying the record.
///
/// Deliberate deviation: the I/O-context finalizer at `0x0805b6d8` remains a
/// volatile dispatch seam on host and an indirect call to its verified
/// retailOS entry on target. Raw `osos.dec` decoding confirms the body ends
/// at the literal `0x62756666` at `0x08042d64`, immediately before this
/// module's flush port at `0x08042d68`.
///
/// # Safety
///
/// `stream` must be a valid, aligned writable [`FtBufferedStream`]. Its
/// nonzero `buffer_allocation` must be valid for tag-4 deallocation.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.ft_buffered_stream_finalize")]
#[inline(never)]
pub unsafe extern "C" fn ft_buffered_stream_finalize(stream: *mut FtBufferedStream) -> i32 {
    if (*stream).magic != u32::from_le_bytes(*b"ffub") {
        return -50;
    }

    (*stream).finalized = 1;
    let result = if (*stream).is_input == 0 {
        ft_buffered_stream_flush(stream)
    } else {
        0
    };

    buffered_stream_io_context_finalize()((*stream).io_context);
    let allocation = (*stream).buffer_allocation;
    if allocation != 0 {
        crate::heap::veneers::free_tag4(allocation as usize as *mut u8);
    }
    crate::libc::bzero::bzero(stream.cast(), 0x30);
    result
}

#[cfg(test)]
pub(crate) static BUFFERED_STREAM_FINALIZE_TEST_LOCK: parking_lot::Mutex<()> =
    parking_lot::Mutex::new(());
/// ft_buffered_stream_flush — original: `FUN_08042d68` @ `0x08042d68`
/// (140 bytes; 4 verified direct inbound `bl` call sites, all plain).
///
/// Flushes an output buffer through its backing I/O context, requiring the
/// backing writer to consume the entire signed `cursor - buffer_start` span;
/// a short successful write becomes -34. For input streams, gets the logical
/// buffered position and seeks the backing context to it. Output mode always
/// resets the buffered cursor range, including after a write error; input mode
/// resets it only after both backing operations succeed.
///
/// Deliberate deviation: the unported backing write at `0x0805b834` and seek
/// at `0x0805b804` are volatile dispatch seams on host and indirect calls to
/// their verified retailOS entries on target. Rust explicitly preserves the
/// ARM signed comparison and wrapping subtraction for output spans.
///
/// # Safety
///
/// `stream` must point to a valid, aligned writable [`FtBufferedStream`].
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.ft_buffered_stream_flush")]
#[inline(never)]
pub unsafe extern "C" fn ft_buffered_stream_flush(stream: *mut FtBufferedStream) -> i32 {
    let stream = &mut *stream;
    if stream.is_input != 0 {
        let mut position = 0;
        let result = buffered_stream_tell(stream, &mut position);
        if result != 0 {
            return result;
        }
        let result = backing_stream_seek()(stream.io_context, position);
        if result != 0 {
            return result;
        }
        ft_buffered_stream_reset_buffer_cursor(stream);
        return 0;
    }

    let expected = stream.cursor.wrapping_sub(stream.buffer_start);
    let result = if (expected as i32) <= 0 {
        0
    } else {
        let mut transferred = expected;
        let result = backing_stream_write()(
            stream.io_context,
            &mut transferred,
            stream.buffer_start,
        );
        if result != 0 {
            result
        } else if transferred != expected {
            -34
        } else {
            0
        }
    };
    ft_buffered_stream_reset_buffer_cursor(stream);
    result
}

/// buffered_stream_tell — original: `FUN_08042e70` @ `0x08042e70` (140
/// bytes; 10 verified direct `bl` call sites, all unconditional).
///
/// Clears `position`, obtains the backing stream's 64-bit position in output
/// mode or uses the cached position in input mode, then adjusts it by the
/// signed 32-bit buffered span. Output mode adds `cursor - buffer_start`;
/// input mode subtracts the inclusive `buffer_end - cursor + 1`.
///
/// Deliberate deviation: the unported backing tell at `0x0805b73c` is an
/// indirect volatile seam on host and an indirect call to its verified
/// retailOS address on target. The stock direct `bl` is otherwise preserved
/// semantically. The raw B/BL scan found no predicated inbound calls.
///
/// # Safety
///
/// `stream` and `position` must be valid, aligned pointers.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.buffered_stream_tell")]
#[inline(never)]
pub unsafe extern "C" fn buffered_stream_tell(
    stream: *const FtBufferedStream,
    position: *mut u64,
) -> i32 {
    let stream = &*stream;
    position.write(0);

    let mut current = if stream.is_input != 0 {
        stream.cached_position
    } else {
        let result = backing_stream_tell()(stream.io_context, position);
        if result != 0 {
            return result;
        }
        position.read()
    };

    let buffered = if stream.is_input != 0 {
        stream.cursor.wrapping_sub(stream.buffer_end).wrapping_add(1)
    } else {
        stream.cursor.wrapping_sub(stream.buffer_start)
    };
    let signed_buffered = (buffered as i32) as i64;
    current = if stream.is_input != 0 {
        current.wrapping_sub(signed_buffered as u64)
    } else {
        current.wrapping_add(signed_buffered as u64)
    };
    position.write(current);
    0
}

#[cfg(test)]
pub(crate) static BACKING_STREAM_TELL_TEST_LOCK: parking_lot::Mutex<()> =
    parking_lot::Mutex::new(());

/// ft_buffered_stream_buffered_bytes — original: `FUN_08042ccc` @
/// 0x08042ccc (48 bytes).
///
/// Returns the number of bytes represented by the buffered cursor. Output
/// mode (`is_input == 0`) returns the wrapping `cursor - buffer_start`.
/// Input mode returns the inclusive `buffer_end - cursor + 1` when the
/// unsigned cursor is at or below the end, and zero otherwise. The ARM
/// `sub`/`add` sequence deliberately wraps in the full-range input case
/// (`cursor == 0`, `buffer_end == u32::MAX`), which this port preserves.
/// The buffered reader at 0x08042fd4 copies and advances `cursor` by this
/// result, while 0x08042d68 flushes the output-mode span.
///
/// # Safety
/// `stream` must point to a valid [`FtBufferedStream`].
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ft_buffered_stream_buffered_bytes(
    stream: *const FtBufferedStream,
) -> u32 {
    let stream = &*stream;
    if stream.is_input != 0 {
        if stream.cursor <= stream.buffer_end {
            stream
                .buffer_end
                .wrapping_sub(stream.cursor)
                .wrapping_add(1)
        } else {
            0
        }
    } else {
        stream.cursor.wrapping_sub(stream.buffer_start)
    }
}

/// ft_buffered_stream_get_size — original: `FUN_08042df4` @ `0x08042df4`
/// (124 bytes; 3 verified plain `bl` calls and no predicated `bl` calls).
///
/// Queries the backing stream's 64-bit size. Output streams also query the
/// current backing position, add their wrapping buffered output span, and
/// retain the unsigned maximum as the stream size. Input streams retain the
/// backing size unchanged.
///
/// Deliberate deviation: the unported backing-size wrapper at `0x0805b714`
/// remains a volatile dispatch seam on host and an indirect dispatch to its
/// verified retailOS entry on target. The port expresses ARM `adds`/`adc`
/// arithmetic as wrapping `u64` addition.
///
/// # Safety
///
/// `stream` and `size` must be valid, aligned pointers.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.ft_buffered_stream_get_size")]
#[inline(never)]
pub unsafe extern "C" fn ft_buffered_stream_get_size(
    stream: *const FtBufferedStream,
    size: *mut u64,
) -> i32 {
    let stream = &*stream;
    let result = backing_stream_size()(stream.io_context, size);
    if result != 0 || stream.is_input != 0 {
        return result;
    }

    let mut position = 0;
    let result = backing_stream_tell()(stream.io_context, &mut position);
    if result != 0 {
        return result;
    }
    let buffered_end = position.wrapping_add(ft_buffered_stream_buffered_bytes(stream) as u64);
    if buffered_end > size.read() {
        size.write(buffered_end);
    }
    0
}

/// ft_buffered_stream_reset_buffer_cursor — original: `FUN_08076b30` @
/// `0x08076b30` (44 bytes; 4 verified direct inbound `bl` call sites: 3
/// unconditional and 1 `bleq`).
///
/// Reinitializes the buffered range after an allocation or mode transition.
/// Output mode starts at `buffer_start` and exposes the record's `+0x10`
/// length word ending inclusively at `buffer_start + length - 1`; input mode
/// starts the cursor one byte after the inclusive end at `buffer_start`.
///
/// Deliberate deviation: Rust expresses the ARM `add`/`sub` arithmetic with
/// wrapping operations, preserving zero-length and full-range behavior.
///
/// # Safety
///
/// `stream` must point to a valid, aligned writable [`FtBufferedStream`].
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ft_buffered_stream_reset_buffer_cursor(
    stream: *mut FtBufferedStream,
) {
    let stream = &mut *stream;
    let buffer_start = stream.buffer_start;
    if stream.is_input == 0 {
        stream.cursor = buffer_start;
        stream.buffer_end = buffer_start
            .wrapping_add(stream.io_reserved[1])
            .wrapping_sub(1);
    } else {
        stream.cursor = buffer_start.wrapping_add(1);
        stream.buffer_end = buffer_start;
    }
}

#[cfg(test)]
mod tests {

    use parking_lot::MutexGuard;
    use super::{
        buffered_stream_tell, ft_buffered_stream_buffered_bytes, ft_buffered_stream_finalize,
        ft_buffered_stream_flush, ft_buffered_stream_get_size, ft_buffered_stream_reset_buffer_cursor,
        BackingStreamSeekFn, BackingStreamSizeFn, BackingStreamTellFn, BackingStreamWriteFn,
        BufferedStreamIoContextFinalizeFn, FtBufferedStream, BACKING_STREAM_SEEK,
        BACKING_STREAM_SIZE, BACKING_STREAM_TELL, BACKING_STREAM_TELL_TEST_LOCK,
        BACKING_STREAM_WRITE, BUFFERED_STREAM_FINALIZE_TEST_LOCK,
        BUFFERED_STREAM_IO_CONTEXT_FINALIZE,
    };

    static mut BACKING_RESULT: i32 = 0;
    static mut BACKING_POSITION: u64 = 0;
    static mut BACKING_CONTEXT: u32 = 0;
    static mut BACKING_CALLS: usize = 0;
    static mut BACKING_SIZE_RESULT: i32 = 0;
    static mut BACKING_SIZE: u64 = 0;
    static mut BACKING_SIZE_CALLS: usize = 0;
    static mut WRITE_RESULT: i32 = 0;
    static mut WRITE_TRANSFERRED: u32 = 0;
    static mut WRITE_CONTEXT: u32 = 0;
    static mut WRITE_DATA: u32 = 0;
    static mut WRITE_CALLS: usize = 0;
    static mut SEEK_RESULT: i32 = 0;
    static mut SEEK_POSITION: u64 = 0;
    static mut SEEK_CONTEXT: u32 = 0;
    static mut SEEK_CALLS: usize = 0;
    static mut FINALIZE_CONTEXT: u32 = 0;
    static mut FINALIZE_CALLS: usize = 0;

    struct BackingSeam {
        _lock: MutexGuard<'static, ()>,
        tell: BackingStreamTellFn,
        size: BackingStreamSizeFn,
    }

    impl Drop for BackingSeam {
        fn drop(&mut self) {
            unsafe {
                BACKING_STREAM_TELL = self.tell;
                BACKING_STREAM_SIZE = self.size;
            }
        }
    }

    struct FinalizeSeams {
        _lock: MutexGuard<'static, ()>,
        write: BackingStreamWriteFn,
        seek: BackingStreamSeekFn,
        finalize_context: BufferedStreamIoContextFinalizeFn,
    }

    impl Drop for FinalizeSeams {
        fn drop(&mut self) {
            unsafe {
                BACKING_STREAM_WRITE = self.write;
                BACKING_STREAM_SEEK = self.seek;
                BUFFERED_STREAM_IO_CONTEXT_FINALIZE = self.finalize_context;
            }
        }
    }

    unsafe extern "C" fn record_backing_tell(context: u32, position: *mut u64) -> i32 {
        BACKING_CALLS += 1;
        BACKING_CONTEXT = context;
        position.write(BACKING_POSITION);
        BACKING_RESULT
    }

    unsafe extern "C" fn record_backing_size(_context: u32, size: *mut u64) -> i32 {
        BACKING_SIZE_CALLS += 1;
        size.write(BACKING_SIZE);
        BACKING_SIZE_RESULT
    }

    unsafe extern "C" fn record_backing_write(
        context: u32,
        transferred: *mut u32,
        data: u32,
    ) -> i32 {
        WRITE_CALLS += 1;
        WRITE_CONTEXT = context;
        WRITE_DATA = data;
        transferred.write(WRITE_TRANSFERRED);
        WRITE_RESULT
    }

    unsafe extern "C" fn record_backing_seek(context: u32, position: u64) -> i32 {
        SEEK_CALLS += 1;
        SEEK_CONTEXT = context;
        SEEK_POSITION = position;
        SEEK_RESULT
    }

    unsafe extern "C" fn record_io_context_finalize(io_context: u32) {
        FINALIZE_CALLS += 1;
        FINALIZE_CONTEXT = io_context;
    }

    fn install_backing() -> BackingSeam {
        let lock = BACKING_STREAM_TELL_TEST_LOCK.lock();
        unsafe {
            let seam = BackingSeam {
                _lock: lock,
                tell: BACKING_STREAM_TELL,
                size: BACKING_STREAM_SIZE,
            };
            BACKING_STREAM_TELL = record_backing_tell;
            BACKING_STREAM_SIZE = record_backing_size;
            BACKING_RESULT = 0;
            BACKING_POSITION = 0;
            BACKING_CONTEXT = 0;
            BACKING_CALLS = 0;
            BACKING_SIZE_RESULT = 0;
            BACKING_SIZE = 0;
            BACKING_SIZE_CALLS = 0;
            seam
        }
    }

    fn install_finalizer() -> FinalizeSeams {
        let lock = BUFFERED_STREAM_FINALIZE_TEST_LOCK.lock();
        unsafe {
            let seams = FinalizeSeams {
                _lock: lock,
                write: BACKING_STREAM_WRITE,
                seek: BACKING_STREAM_SEEK,
                finalize_context: BUFFERED_STREAM_IO_CONTEXT_FINALIZE,
            };
            BACKING_STREAM_WRITE = record_backing_write;
            BACKING_STREAM_SEEK = record_backing_seek;
            BUFFERED_STREAM_IO_CONTEXT_FINALIZE = record_io_context_finalize;
            WRITE_RESULT = 0;
            WRITE_TRANSFERRED = 0;
            WRITE_CONTEXT = 0;
            WRITE_DATA = 0;
            WRITE_CALLS = 0;
            SEEK_RESULT = 0;
            SEEK_POSITION = 0;
            SEEK_CONTEXT = 0;
            SEEK_CALLS = 0;
            FINALIZE_CONTEXT = 0;
            FINALIZE_CALLS = 0;
            seams
        }
    }

    fn stream(is_input: u8, cursor: u32, buffer_start: u32, buffer_end: u32) -> FtBufferedStream {
        FtBufferedStream {
            magic: u32::from_le_bytes(*b"ffub"),
            finalized: 0,
            is_input,
            state_reserved: [0; 2],
            io_context: 0,
            io_reserved: [0; 2],
            buffer_allocation: 0,
            cursor,
            buffer_start,
            buffer_end,
            position_reserved: 0,
            cached_position: 0,
        }
    }

    /// A formula-only reference rather than a second implementation that
    /// shares the port's control flow.
    fn reference(is_input: u8, cursor: u32, buffer_start: u32, buffer_end: u32) -> u32 {
        match is_input {
            0 => cursor.wrapping_sub(buffer_start),
            _ if cursor > buffer_end => 0,
            _ => buffer_end.wrapping_sub(cursor).wrapping_add(1),
        }
    }

    fn port(is_input: u8, cursor: u32, buffer_start: u32, buffer_end: u32) -> u32 {
        let stream = stream(is_input, cursor, buffer_start, buffer_end);
        unsafe { ft_buffered_stream_buffered_bytes(&stream) }
    }

    #[test]
    fn output_mode_counts_the_cursor_span() {
        assert_eq!(port(0, 0x120, 0x100, 0), reference(0, 0x120, 0x100, 0));
        assert_eq!(port(0, 0x100, 0x100, 0), 0);
    }

    #[test]
    fn output_mode_underflow_wraps() {
        assert_eq!(port(0, 3, 9, 0), reference(0, 3, 9, 0));
        assert_eq!(port(0, 3, 9, 0), u32::MAX - 5);
    }

    #[test]
    fn input_mode_counts_an_inclusive_remaining_span() {
        assert_eq!(port(1, 0x100, 0, 0x100), reference(1, 0x100, 0, 0x100));
        assert_eq!(port(0xff, 0x102, 0, 0x105), reference(0xff, 0x102, 0, 0x105));
        assert_eq!(port(0xff, 0x102, 0, 0x105), 4);
    }

    #[test]
    fn input_mode_saturates_when_the_cursor_is_past_the_end() {
        assert_eq!(port(1, 0x106, 0, 0x105), reference(1, 0x106, 0, 0x105));
        assert_eq!(port(1, 0x106, 0, 0x105), 0);
    }

    #[test]
    fn input_mode_preserves_the_arm_full_range_wrap() {
        assert_eq!(port(1, 0, 0, u32::MAX), reference(1, 0, 0, u32::MAX));
        assert_eq!(port(1, 0, 0, u32::MAX), 0);
    }
    #[test]
    fn output_mode_gets_the_backing_position_then_adds_signed_buffered_span() {
        let _seam = install_backing();
        unsafe { BACKING_POSITION = 4; }
        let mut stream = stream(0, 0x10, 0x20, 0);
        stream.io_context = 0x1234_5678;
        let mut position = u64::MAX;

        assert_eq!(unsafe { buffered_stream_tell(&stream, &mut position) }, 0);
        assert_eq!(position, u64::MAX - 11);
        unsafe {
            assert_eq!(BACKING_CALLS, 1);
            assert_eq!(BACKING_CONTEXT, 0x1234_5678);
        }
    }

    #[test]
    fn input_mode_uses_cached_position_and_preserves_signed_span_wrap() {
        let _seam = install_backing();
        let mut stream = stream(1, 0, 0, 0x7fff_ffff);
        stream.cached_position = 10;
        let mut position = u64::MAX;

        assert_eq!(unsafe { buffered_stream_tell(&stream, &mut position) }, 0);
        assert_eq!(position, 0x8000_0008);
        unsafe { assert_eq!(BACKING_CALLS, 0); }
    }

    #[test]
    fn backing_error_propagates_with_the_callee_written_position() {
        let _seam = install_backing();
        unsafe {
            BACKING_RESULT = -17;
            BACKING_POSITION = 0x1122_3344_5566_7788;
        }
        let stream = stream(0, 0x100, 0x100, 0);
        let mut position = u64::MAX;

        assert_eq!(unsafe { buffered_stream_tell(&stream, &mut position) }, -17);
        assert_eq!(position, 0x1122_3344_5566_7788);
        unsafe { assert_eq!(BACKING_CALLS, 1); }
    }

    #[test]
    fn get_size_preserves_input_size_and_extends_output_size_without_overflow() {
        let _seam = install_backing();
        unsafe {
            BACKING_SIZE = 0x100;
            BACKING_POSITION = 0xf0;
        }
        let mut input = stream(1, 0x140, 0x100, 0x1ff);
        input.io_context = 0x1234_5678;
        let mut size = 0;
        assert_eq!(unsafe { ft_buffered_stream_get_size(&input, &mut size) }, 0);
        assert_eq!(size, 0x100);
        unsafe {
            assert_eq!(BACKING_SIZE_CALLS, 1);
            assert_eq!(BACKING_CALLS, 0);
        }

        let output = stream(0, 0x40, 0, 0);
        assert_eq!(unsafe { ft_buffered_stream_get_size(&output, &mut size) }, 0);
        assert_eq!(size, 0x130);
        unsafe { assert_eq!(BACKING_CALLS, 1); }

        unsafe {
            BACKING_SIZE = u64::MAX - 1;
            BACKING_POSITION = u64::MAX;
        }
        let output = stream(0, 3, 0, 0);
        assert_eq!(unsafe { ft_buffered_stream_get_size(&output, &mut size) }, 0);
        assert_eq!(size, u64::MAX - 1);
    }

    #[test]
    fn get_size_propagates_backing_errors_without_later_calls() {
        let _seam = install_backing();
        unsafe {
            BACKING_SIZE = 0x7654;
            BACKING_SIZE_RESULT = -17;
        }
        let stream = stream(0, 1, 0, 0);
        let mut size = 0;
        assert_eq!(unsafe { ft_buffered_stream_get_size(&stream, &mut size) }, -17);
        assert_eq!(size, 0x7654);
        unsafe {
            assert_eq!(BACKING_SIZE_CALLS, 1);
            assert_eq!(BACKING_CALLS, 0);
        }
    }
    #[test]
    fn flush_writes_output_span_and_rejects_short_write() {
        let _seams = install_finalizer();
        let mut stream = stream(0, 0x140, 0x100, 0);
        stream.io_context = 0x1234_5678;
        stream.io_reserved[1] = 0x80;
        unsafe { WRITE_TRANSFERRED = 0x40; }

        assert_eq!(unsafe { ft_buffered_stream_flush(&mut stream) }, 0);
        unsafe {
            assert_eq!(WRITE_CALLS, 1);
            assert_eq!(WRITE_CONTEXT, 0x1234_5678);
            assert_eq!(WRITE_DATA, 0x100);
        }
        assert_eq!(stream.cursor, 0x100);
        assert_eq!(stream.buffer_end, 0x17f);

        stream.cursor = 0x120;
        unsafe { WRITE_TRANSFERRED = 0x1f; }
        assert_eq!(unsafe { ft_buffered_stream_flush(&mut stream) }, -34);
        assert_eq!(stream.cursor, 0x100);
    }

    #[test]
    fn flush_seeks_input_position_and_propagates_seek_error() {
        let _backing = install_backing();
        let _seams = install_finalizer();
        let mut stream = stream(1, 0x100, 0, 0x10f);
        stream.io_context = 0xfeed_cafe;
        stream.cached_position = 0x200;

        assert_eq!(unsafe { ft_buffered_stream_flush(&mut stream) }, 0);
        unsafe {
            assert_eq!(SEEK_CALLS, 1);
            assert_eq!(SEEK_CONTEXT, 0xfeed_cafe);
            assert_eq!(SEEK_POSITION, 0x20e);
        }
        assert_eq!(stream.cursor, 1);
        assert_eq!(stream.buffer_end, 0);

        unsafe { SEEK_RESULT = -17; }
        assert_eq!(unsafe { ft_buffered_stream_flush(&mut stream) }, -17);
        unsafe { assert_eq!(SEEK_CALLS, 2); }
    }


    #[test]
    fn finalizer_rejects_a_foreign_tag_without_side_effects() {
        let _seams = install_finalizer();
        let mut stream = stream(0, 0, 0, 0);
        stream.magic = 0;

        assert_eq!(unsafe { ft_buffered_stream_finalize(&mut stream) }, -50);
        assert_eq!(stream.magic, 0);
        assert_eq!(stream.finalized, 0);
        unsafe {
            assert_eq!(WRITE_CALLS, 0);
            assert_eq!(FINALIZE_CALLS, 0);
        }
    }

    #[test]
    fn finalizer_flushes_output_retains_error_and_zeros_the_record() {
        let _seams = install_finalizer();
        unsafe { WRITE_RESULT = -17; }
        let mut stream = stream(0, 0x140, 0x100, 0);
        stream.io_context = 0x1234_5678;
        stream.position_reserved = 0xa5a5_a5a5;

        assert_eq!(unsafe { ft_buffered_stream_finalize(&mut stream) }, -17);
        unsafe {
            assert_eq!(WRITE_CALLS, 1);
            assert_eq!(FINALIZE_CALLS, 1);
            assert_eq!(FINALIZE_CONTEXT, 0x1234_5678);
            let bytes = core::slice::from_raw_parts(
                core::ptr::addr_of!(stream).cast::<u8>(),
                core::mem::size_of::<FtBufferedStream>(),
            );
            assert!(bytes.iter().all(|byte| *byte == 0));
        }
    }

    #[test]
    fn finalizer_skips_flush_for_input_but_finalizes_its_context() {
        let _seams = install_finalizer();
        let mut stream = stream(1, 0, 0, 0);
        stream.io_context = 0xfeed_cafe;

        assert_eq!(unsafe { ft_buffered_stream_finalize(&mut stream) }, 0);

        unsafe {
            assert_eq!(WRITE_CALLS, 0);
            assert_eq!(FINALIZE_CALLS, 1);
            assert_eq!(FINALIZE_CONTEXT, 0xfeed_cafe);
        }
    }

    #[test]
    fn reset_buffer_cursor_uses_output_range_and_preserves_wrapping() {
        let mut stream = stream(0, 0, 0x100, 0);
        stream.io_reserved[1] = 0;
        unsafe { ft_buffered_stream_reset_buffer_cursor(&mut stream); }
        assert_eq!(stream.cursor, 0x100);
        assert_eq!(stream.buffer_end, 0xff);

        stream.buffer_start = u32::MAX;
        stream.io_reserved[1] = 2;
        unsafe { ft_buffered_stream_reset_buffer_cursor(&mut stream); }
        assert_eq!(stream.cursor, u32::MAX);
        assert_eq!(stream.buffer_end, 0);
    }

    #[test]
    fn reset_buffer_cursor_uses_empty_input_range() {
        let mut stream = stream(1, 0, u32::MAX, 0);
        stream.io_reserved[1] = 0xdead_beef;

        unsafe { ft_buffered_stream_reset_buffer_cursor(&mut stream); }

        assert_eq!(stream.cursor, 0);
        assert_eq!(stream.buffer_end, u32::MAX);
    }
}

#[cfg(test)]
mod init_data_tests {
    use super::{
        ft_buffered_stream_init_data, BufferedStreamDataContextCreateFn, BufferedStreamInitializeFn,
        FtBufferedStream, BUFFERED_STREAM_DATA_CONTEXT_CREATE,
        BUFFERED_STREAM_FINALIZE_TEST_LOCK, BUFFERED_STREAM_INIT_DATA_TEST_LOCK,
        BUFFERED_STREAM_INITIALIZE, BUFFERED_STREAM_IO_CONTEXT_FINALIZE,
    };
    static mut CREATE_RESULT: i32 = 0;
    static mut INITIALIZE_RESULT: i32 = 0;
    static mut CREATE_CALLS: usize = 0;
    static mut INITIALIZE_CALLS: usize = 0;
    static mut CREATE_ARGS: (u32, u32, u32, u32) = (0, 0, 0, 0);
    static mut INITIALIZE_CONTEXT: u32 = 0;

    unsafe extern "C" fn record_create(
        out_context: *mut u32,
        data: u32,
        is_input: u32,
        tag: u32,
        buffer_size: u32,
    ) -> i32 {
        CREATE_CALLS += 1;
        CREATE_ARGS = (data, is_input, tag, buffer_size);
        out_context.write(0x1234_5678);
        CREATE_RESULT
    }

    unsafe extern "C" fn record_initialize(
        stream: *mut FtBufferedStream,
        _data: u32,
        _is_input: u32,
        _buffer_size: u32,
        io_context: u32,
    ) -> i32 {
        INITIALIZE_CALLS += 1;
        INITIALIZE_CONTEXT = io_context;
        (*stream).magic = u32::from_le_bytes(*b"ffub");
        (*stream).is_input = 1;
        INITIALIZE_RESULT
    }

    unsafe extern "C" fn ignore_io_context_finalize(_io_context: u32) {}

    fn stream() -> FtBufferedStream {
        FtBufferedStream {
            magic: 0,
            finalized: 0,
            is_input: 0,
            state_reserved: [0; 2],
            io_context: 0,
            io_reserved: [0; 2],
            buffer_allocation: 0,
            cursor: 0,
            buffer_start: 0,
            buffer_end: 0,
            position_reserved: 0,
            cached_position: 0,
        }
    }

    #[test]
    fn foreign_tag_returns_minus_50_without_calling_either_callee() {
        let _lock = BUFFERED_STREAM_INIT_DATA_TEST_LOCK.lock();
        let original_create = unsafe { BUFFERED_STREAM_DATA_CONTEXT_CREATE };
        let original_initialize = unsafe { BUFFERED_STREAM_INITIALIZE };
        unsafe {
            BUFFERED_STREAM_DATA_CONTEXT_CREATE = record_create;
            BUFFERED_STREAM_INITIALIZE = record_initialize;
            CREATE_CALLS = 0;
            INITIALIZE_CALLS = 0;
        }
        let mut stream = stream();

        assert_eq!(unsafe { ft_buffered_stream_init_data(1, &mut stream, 0x20000, 0) }, -50);
        unsafe {
            assert_eq!(CREATE_CALLS, 0);
            assert_eq!(INITIALIZE_CALLS, 0);
            BUFFERED_STREAM_DATA_CONTEXT_CREATE = original_create;
            BUFFERED_STREAM_INITIALIZE = original_initialize;
        }
    }

    #[test]
    fn context_creation_error_propagates_without_initializing_the_stream() {
        let _lock = BUFFERED_STREAM_INIT_DATA_TEST_LOCK.lock();
        let original_create = unsafe { BUFFERED_STREAM_DATA_CONTEXT_CREATE };
        let original_initialize = unsafe { BUFFERED_STREAM_INITIALIZE };
        unsafe {
            BUFFERED_STREAM_DATA_CONTEXT_CREATE = record_create;
            BUFFERED_STREAM_INITIALIZE = record_initialize;
            CREATE_RESULT = -108;
            CREATE_CALLS = 0;
            INITIALIZE_CALLS = 0;
        }
        let mut stream = stream();

        assert_eq!(unsafe { ft_buffered_stream_init_data(0x89ab_cdef, &mut stream, 0x1000, u32::from_le_bytes(*b"atad")) }, -108);
        unsafe {
            assert_eq!(CREATE_CALLS, 1);
            assert_eq!(INITIALIZE_CALLS, 0);
            assert_eq!(CREATE_ARGS, (0x89ab_cdef, 1, u32::from_le_bytes(*b"atad"), 0x1000));
            BUFFERED_STREAM_DATA_CONTEXT_CREATE = original_create;
            BUFFERED_STREAM_INITIALIZE = original_initialize;
        }
    }

    #[test]
    fn initialization_error_finalizes_the_created_input_stream() {
        let _finalize_lock = BUFFERED_STREAM_FINALIZE_TEST_LOCK.lock();
        let _lock = BUFFERED_STREAM_INIT_DATA_TEST_LOCK.lock();
        let original_create = unsafe { BUFFERED_STREAM_DATA_CONTEXT_CREATE };
        let original_initialize = unsafe { BUFFERED_STREAM_INITIALIZE };
        let original_finalize = unsafe { BUFFERED_STREAM_IO_CONTEXT_FINALIZE };
        unsafe {
            BUFFERED_STREAM_DATA_CONTEXT_CREATE = record_create;
            BUFFERED_STREAM_INITIALIZE = record_initialize;
            BUFFERED_STREAM_IO_CONTEXT_FINALIZE = ignore_io_context_finalize;
            CREATE_RESULT = 0;
            INITIALIZE_RESULT = -7;
            CREATE_CALLS = 0;
            INITIALIZE_CALLS = 0;
        }
        let mut stream = stream();

        assert_eq!(unsafe { ft_buffered_stream_init_data(3, &mut stream, 0, u32::from_le_bytes(*b"atad")) }, -7);
        unsafe {
            assert_eq!(CREATE_CALLS, 1);
            assert_eq!(INITIALIZE_CALLS, 1);
            assert_eq!(INITIALIZE_CONTEXT, 0x1234_5678);
            assert_eq!(stream.magic, 0);
            BUFFERED_STREAM_DATA_CONTEXT_CREATE = original_create;
            BUFFERED_STREAM_INITIALIZE = original_initialize;
            BUFFERED_STREAM_IO_CONTEXT_FINALIZE = original_finalize;
        }
    }
}
