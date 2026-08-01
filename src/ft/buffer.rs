//! Buffered FreeType stream accounting.
//!
//! The `buff`-tagged, 48-byte record in the 0x08042cfc..0x08042fd4
//! helper family fronts the FreeType I/O callbacks. Its cursor points
//! into a buffer: in output mode the span from `buffer_start` to `cursor`
//! is buffered, while in input mode the inclusive span from `cursor` to
//! `buffer_end` is available to its reader.

/// The target's 48-byte buffered-stream record.
///
/// The I/O context and the fields not read by this port remain word-sized
/// placeholders. Keeping every field a `u32` preserves the ARM layout on
/// host tests as well as on the target, without representing target
/// pointers as widened host pointers.
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
    pub position_reserved: [u32; 3],
}

const _: () = assert!(core::mem::size_of::<FtBufferedStream>() == 48);
const _: () = assert!(core::mem::offset_of!(FtBufferedStream, is_input) == 5);
const _: () = assert!(core::mem::offset_of!(FtBufferedStream, cursor) == 0x18);
const _: () = assert!(core::mem::offset_of!(FtBufferedStream, buffer_start) == 0x1c);
const _: () = assert!(core::mem::offset_of!(FtBufferedStream, buffer_end) == 0x20);

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
    use super::{ft_buffered_stream_buffered_bytes, FtBufferedStream};

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
            position_reserved: [0; 3],
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
}
