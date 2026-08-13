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

/// Exact ABI of the unported checked-byte-block reader `FUN_0802b6a8`.
///
/// The reader copies `row_count * bytes_per_row` bytes from the input cursor
/// to the output cursor, verifies the following mode-transformed word against
/// the wrapping byte sum, and returns `0` or `4`. On success it advances both
/// aliases of each cursor; otherwise it leaves them untouched.
pub type CheckedByteBlockReader = unsafe extern "C" fn(
    mode: u32,
    input_cursor: *mut *mut u8,
    input_cursor_mirror: *mut *mut u8,
    output_cursor: *mut *mut u8,
    output_cursor_mirror: *mut *mut u8,
    row_count: u32,
    bytes_per_row: u32,
) -> u32;

/// Calls outside this one-function port.
#[derive(Clone, Copy)]
pub struct UiCheckedByteBlockForwarderOps {
    pub checked_byte_block_reader: CheckedByteBlockReader,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_checked_byte_block_reader(
    mode: u32,
    input_cursor: *mut *mut u8,
    input_cursor_mirror: *mut *mut u8,
    output_cursor: *mut *mut u8,
    output_cursor_mirror: *mut *mut u8,
    row_count: u32,
    bytes_per_row: u32,
) -> u32 {
    let reader: CheckedByteBlockReader = unsafe { core::mem::transmute(0x0802_b6a8usize) };
    unsafe {
        reader(
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

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_checked_byte_block_reader(
    _mode: u32,
    _input_cursor: *mut *mut u8,
    _input_cursor_mirror: *mut *mut u8,
    _output_cursor: *mut *mut u8,
    _output_cursor_mirror: *mut *mut u8,
    _row_count: u32,
    _bytes_per_row: u32,
) -> u32 {
    panic!("ui_checked_byte_block_forwarder requires reader 0x0802b6a8")
}

#[cfg(target_os = "none")]
pub const DEFAULT_UI_CHECKED_BYTE_BLOCK_FORWARDER_OPS: UiCheckedByteBlockForwarderOps =
    UiCheckedByteBlockForwarderOps {
        checked_byte_block_reader: firmware_checked_byte_block_reader,
    };
#[cfg(not(target_os = "none"))]
pub const DEFAULT_UI_CHECKED_BYTE_BLOCK_FORWARDER_OPS: UiCheckedByteBlockForwarderOps =
    UiCheckedByteBlockForwarderOps {
        checked_byte_block_reader: missing_checked_byte_block_reader,
    };

/// Target builds call `FUN_0802b6a8`; host tests replace this seam with a
/// recorder until that reader is independently ported.
pub static mut UI_CHECKED_BYTE_BLOCK_FORWARDER_OPS: UiCheckedByteBlockForwarderOps =
    DEFAULT_UI_CHECKED_BYTE_BLOCK_FORWARDER_OPS;

#[inline(always)]
fn checked_byte_block_forwarder_ops() -> UiCheckedByteBlockForwarderOps {
    unsafe {
        core::ptr::read_volatile(core::ptr::addr_of!(
            UI_CHECKED_BYTE_BLOCK_FORWARDER_OPS
        ))
    }
}

/// ui_checked_byte_block_forwarder — original: `FUN_0802dd88` @ `0x0802dd88`
/// (32 bytes).
///
/// Forwards the four cursor aliases and the two stack-carried block dimensions
/// to the checked byte-block reader unchanged, returning its status unchanged.
/// `row_count` and `bytes_per_row` are the raw block's incoming `r2` and `r3`:
/// they occupy the sixth and seventh reader arguments, respectively, rather
/// than being mistaken for the cursor pointers Ghidra assigned to them.
///
/// # Deviations
///
/// The original is an internal ARM basic block, not a normal C-ABI entry: it
/// takes `mode` from live `r5` and obtains the cursor-slot addresses as fixed
/// offsets in its containing parser's stack frame. The port exposes those
/// otherwise implicit values as explicit arguments while preserving the exact
/// `FUN_0802b6a8` call ABI. The reader remains a target/host seam until it is
/// independently ported.
///
/// # Safety
///
/// All four cursor-slot pointers must be valid for the unported reader.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ui_checked_byte_block_forwarder(
    mode: u32,
    input_cursor: *mut *mut u8,
    input_cursor_mirror: *mut *mut u8,
    output_cursor: *mut *mut u8,
    output_cursor_mirror: *mut *mut u8,
    row_count: u32,
    bytes_per_row: u32,
) -> u32 {
    let reader = checked_byte_block_forwarder_ops().checked_byte_block_reader;
    unsafe {
        reader(
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
    use std::sync::Mutex;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut SEEN: [usize; 7] = [0; 7];
    static mut STATUS: u32 = 0;

    unsafe extern "C" fn recorder(
        mode: u32,
        input_cursor: *mut *mut u8,
        input_cursor_mirror: *mut *mut u8,
        output_cursor: *mut *mut u8,
        output_cursor_mirror: *mut *mut u8,
        row_count: u32,
        bytes_per_row: u32,
    ) -> u32 {
        unsafe {
            SEEN = [
                mode as usize,
                input_cursor as usize,
                input_cursor_mirror as usize,
                output_cursor as usize,
                output_cursor_mirror as usize,
                row_count as usize,
                bytes_per_row as usize,
            ];
            STATUS
        }
    }

    #[test]
    fn forwards_cursor_layout_stack_dimensions_and_reader_status() {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let mut input = [0u8; 16];
        let mut output = [0u8; 16];
        let mut input_cursor = input.as_mut_ptr();
        let mut input_cursor_mirror = input.as_mut_ptr();
        let mut output_cursor = output.as_mut_ptr();
        let mut output_cursor_mirror = output.as_mut_ptr();
        let expected = [
            0x1usize,
            (&mut input_cursor as *mut *mut u8) as usize,
            (&mut input_cursor_mirror as *mut *mut u8) as usize,
            (&mut output_cursor as *mut *mut u8) as usize,
            (&mut output_cursor_mirror as *mut *mut u8) as usize,
            0x10,
            0x100,
        ];
        let previous = unsafe { UI_CHECKED_BYTE_BLOCK_FORWARDER_OPS };

        unsafe {
            STATUS = 4;
            UI_CHECKED_BYTE_BLOCK_FORWARDER_OPS = UiCheckedByteBlockForwarderOps {
                checked_byte_block_reader: recorder,
            };
        }
        let result = unsafe {
            ui_checked_byte_block_forwarder(
                1,
                &mut input_cursor,
                &mut input_cursor_mirror,
                &mut output_cursor,
                &mut output_cursor_mirror,
                0x10,
                0x100,
            )
        };
        let seen = unsafe { SEEN };
        unsafe { UI_CHECKED_BYTE_BLOCK_FORWARDER_OPS = previous };

        assert_eq!(result, 4, "the reader status returns unchanged");
        assert_eq!(seen, expected, "cursor aliases and outgoing stack words forward exactly");
    }
}
