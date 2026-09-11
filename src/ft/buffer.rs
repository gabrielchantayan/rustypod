//! Buffered FreeType stream accounting.
//!
//! The `buff`-tagged, 48-byte record in the 0x08042cfc..0x08042fd4
//! helper family fronts the FreeType I/O callbacks. Its cursor points
//! into a buffer: in output mode the span from `buffer_start` to `cursor`
//! is buffered, while in input mode the inclusive span from `cursor` to
//! `buffer_end` is available to its reader.

/// The target's 48-byte buffered-stream record.
///
/// The I/O context is a 32-bit target handle. The field at +0x24 remains a
/// word-sized placeholder; +0x28 is the cached 64-bit stream position.
#[repr(C)]
pub struct FtBufferedStream {
    pub magic: u32,
    pub finalized: u8,
    /// Nonzero selects the input-buffer formula; zero selects output mode.
    pub is_input: u8,
    pub state_reserved: [u8; 2],
    pub io_context: u32,
    pub io_reserved: [u32; 3],
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

#[inline(always)]
unsafe fn backing_stream_tell() -> BackingStreamTellFn {
    core::ptr::read_volatile(core::ptr::addr_of!(BACKING_STREAM_TELL))
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

#[cfg(test)]
mod tests {

    use parking_lot::MutexGuard;
    use super::{
        buffered_stream_tell, ft_buffered_stream_buffered_bytes, BackingStreamTellFn,
        FtBufferedStream, BACKING_STREAM_TELL, BACKING_STREAM_TELL_TEST_LOCK,
    };

    static mut BACKING_RESULT: i32 = 0;
    static mut BACKING_POSITION: u64 = 0;
    static mut BACKING_CONTEXT: u32 = 0;
    static mut BACKING_CALLS: usize = 0;

    struct BackingSeam {
        _lock: MutexGuard<'static, ()>,
        original: BackingStreamTellFn,
    }

    impl Drop for BackingSeam {
        fn drop(&mut self) {
            unsafe { BACKING_STREAM_TELL = self.original; }
        }
    }

    unsafe extern "C" fn record_backing_tell(context: u32, position: *mut u64) -> i32 {
        BACKING_CALLS += 1;
        BACKING_CONTEXT = context;
        position.write(BACKING_POSITION);
        BACKING_RESULT
    }

    fn install_backing() -> BackingSeam {
        let lock = BACKING_STREAM_TELL_TEST_LOCK.lock();
        unsafe {
            let seam = BackingSeam { _lock: lock, original: BACKING_STREAM_TELL };
            BACKING_STREAM_TELL = record_backing_tell;
            BACKING_RESULT = 0;
            BACKING_POSITION = 0;
            BACKING_CONTEXT = 0;
            BACKING_CALLS = 0;
            seam
        }
    }

    fn stream(is_input: u8, cursor: u32, buffer_start: u32, buffer_end: u32) -> FtBufferedStream {
        FtBufferedStream {
            magic: u32::from_le_bytes(*b"ffub"),
            finalized: 0,
            is_input,
            state_reserved: [0; 2],
            io_context: 0,
            io_reserved: [0; 3],
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
}
