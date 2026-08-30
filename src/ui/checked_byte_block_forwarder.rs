//! UI checked-byte-block forwarding seam.
//!
//! `ui_checked_byte_block_forwarder` — original: `FUN_0802dd88` @
//! `0x0802dd88` (32 bytes, `0x0802dd88..0x0802dda8`). Reference:
//! `/home/gabe/Programming/ipod-decomp/decomp/c/001/0802dd88_FUN_0802dd88.c`;
//! raw ARM is authoritative because Ghidra splits this basic block from its
//! containing parser. The reader mode is live in callee-saved `r5`; the cursor
//! slots are at the containing parser frame's `sp + 0x34`, `+0x38`, `+0x2c`,
//! and `+0x30`, in that order. The incoming `r2` and `r3` words are not cursor
//! arguments. They become the reader's sixth and seventh arguments by being
//! stored at outgoing `sp + 4` and `sp + 8`. In the normal parser path these
//! are `16` rows and `0x100` bytes per row.

/// ui_checked_byte_block_forwarder — original: `FUN_0802dd88` @ `0x0802dd88`
/// (32 bytes).
///
/// Forwards the four cursor aliases and two stack-carried signed block
/// dimensions to [`crate::util::checked_byte_block::checked_byte_block_reader`],
/// returning its status unchanged. `row_count` and `bytes_per_row` are the raw
/// block's incoming `r2` and `r3`: they occupy the sixth and seventh reader
/// arguments, rather than being mistaken for cursor pointers as Ghidra did.
///
/// # Deviations
///
/// The original is an internal ARM basic block, not a normal C-ABI entry: it
/// takes `mode` from live `r5` and obtains the cursor-slot addresses as fixed
/// offsets in its containing parser's stack frame. The port exposes those
/// otherwise implicit values as explicit arguments while preserving the reader
/// call ABI.
///
/// # Safety
///
/// All four cursor-slot pointers must satisfy the reader's safety requirements.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ui_checked_byte_block_forwarder(
    mode: u32,
    input_cursor: *mut *mut u8,
    input_cursor_mirror: *mut *mut u8,
    output_cursor: *mut *mut u8,
    output_cursor_mirror: *mut *mut u8,
    row_count: i32,
    bytes_per_row: i32,
) -> u32 {
    unsafe {
        crate::util::checked_byte_block::checked_byte_block_reader(
            mode,
            input_cursor,
            input_cursor_mirror,
            output_cursor,
            output_cursor_mirror,
            row_count,
            bytes_per_row,
        )
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    #[test]
    fn forwards_to_the_ported_reader() {
        let mut source = [0x0403_0201u32, 10];
        let mut output = [0u8; 4];
        let mut input_cursor = source.as_mut_ptr().cast::<u8>();
        let mut input_cursor_mirror = input_cursor;
        let mut output_cursor = output.as_mut_ptr();
        let mut output_cursor_mirror = output_cursor;

        let status = unsafe {
            ui_checked_byte_block_forwarder(
                0,
                &mut input_cursor,
                &mut input_cursor_mirror,
                &mut output_cursor,
                &mut output_cursor_mirror,
                1,
                4,
            )
        };

        assert_eq!(status, 0);
        assert_eq!(output, [1, 2, 3, 4]);
        assert_eq!(input_cursor as usize - source.as_ptr() as usize, 8);
        assert_eq!(input_cursor_mirror, input_cursor);
        assert_eq!(output_cursor as usize - output.as_ptr() as usize, 4);
        assert_eq!(output_cursor_mirror, output_cursor);
    }
}
