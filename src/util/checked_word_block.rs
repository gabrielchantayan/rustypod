//! `checked_word_block_convert` — initial-word decoder in the checked binary
//! word-block reader.
//!
//! Original: `FUN_0802b654` @ 0x0802b654 (84 bytes,
//! 0x0802b654..0x0802b6a8; 54 `bl` call sites, no tail branches).
//!
//! It reads `**input_cursor_mirror`, applies `FUN_0802b538`'s mode-controlled
//! transform (only mode 1 reverses the four bytes), stores that decoded leading
//! word, and calls `FUN_0802b5d4` with its six original arguments unchanged.
//! The unported core converts `word_count` words, verifies that the following
//! transformed source word equals their wrapping sum, advances its input/output
//! cursor aliases on success, and returns 0; it returns 4 without advancing on
//! a mismatch. Callers use the stored leading word as a binary-record field and
//! the status to continue/reject parsing. The higher-level record format is not
//! identified, so the name remains structural.
//!
//! Deliberate deviation: the unported core uses [`CHECKED_WORD_BLOCK_OPS`]
//! (firmware address on target, panicking default on host); the tiny local
//! `FUN_0802b538` transform is reproduced directly rather than exposed as a
//! second port.

use core::ptr::addr_of_mut;

/// The core's checksum-mismatch result.
pub const CHECKSUM_MISMATCH: u32 = 4;

#[inline(always)]
const fn transform_word_for_mode(mode: u32, word: u32) -> u32 {
    if mode == 1 { word.swap_bytes() } else { word }
}

/// Exact ABI of the unported `FUN_0802b5d4` block conversion/checksum core.
pub type CheckedWordBlockCore = unsafe extern "C" fn(
    mode: u32,
    input_cursor: *mut *mut u32,
    input_cursor_mirror: *mut *mut u32,
    output_cursor: *mut *mut u32,
    output_cursor_mirror: *mut *mut u32,
    word_count: u32,
) -> u32;

#[derive(Clone, Copy)]
pub struct CheckedWordBlockOps {
    pub convert_core: CheckedWordBlockCore,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_convert_core(
    mode: u32,
    input_cursor: *mut *mut u32,
    input_cursor_mirror: *mut *mut u32,
    output_cursor: *mut *mut u32,
    output_cursor_mirror: *mut *mut u32,
    word_count: u32,
) -> u32 {
    let f: CheckedWordBlockCore = unsafe { core::mem::transmute(0x0802_b5d4usize) };
    unsafe { f(mode, input_cursor, input_cursor_mirror, output_cursor, output_cursor_mirror, word_count) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_convert_core(
    _mode: u32,
    _input_cursor: *mut *mut u32,
    _input_cursor_mirror: *mut *mut u32,
    _output_cursor: *mut *mut u32,
    _output_cursor_mirror: *mut *mut u32,
    _word_count: u32,
) -> u32 {
    panic!("checked_word_block_convert requires core 0x0802b5d4")
}

#[cfg(target_os = "none")]
const DEFAULT_CHECKED_WORD_BLOCK_OPS: CheckedWordBlockOps = CheckedWordBlockOps { convert_core: firmware_convert_core };
#[cfg(not(target_os = "none"))]
const DEFAULT_CHECKED_WORD_BLOCK_OPS: CheckedWordBlockOps = CheckedWordBlockOps { convert_core: missing_convert_core };

/// Target defaults call the firmware core; host tests replace this slot.
pub static mut CHECKED_WORD_BLOCK_OPS: CheckedWordBlockOps = DEFAULT_CHECKED_WORD_BLOCK_OPS;

/// checked_word_block_convert — original: `FUN_0802b654` @ 0x0802b654
/// (84 bytes; 54 `bl` call sites).
///
/// Decodes and stores the current leading input word, then forwards all core
/// arguments unchanged and returns the core's status.
///
/// # Safety
/// `input_cursor_mirror` and its current word must be readable,
/// `out_leading_word` writable, and all cursor aliases valid for the core.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn checked_word_block_convert(
    mode: u32,
    input_cursor: *mut *mut u32,
    input_cursor_mirror: *mut *mut u32,
    output_cursor: *mut *mut u32,
    output_cursor_mirror: *mut *mut u32,
    word_count: u32,
    out_leading_word: *mut u32,
) -> u32 {
    let source = unsafe { core::ptr::read_volatile(input_cursor_mirror) };
    let leading = transform_word_for_mode(mode, unsafe { core::ptr::read_volatile(source) });
    unsafe { core::ptr::write_volatile(out_leading_word, leading) };
    let core = unsafe { addr_of_mut!(CHECKED_WORD_BLOCK_OPS).read_volatile().convert_core };
    unsafe { core(mode, input_cursor, input_cursor_mirror, output_cursor, output_cursor_mirror, word_count) }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::Mutex;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut SEEN: [usize; 6] = [0; 6];
    static mut STATUS: u32 = 0;

    unsafe extern "C" fn recorder(
        mode: u32,
        input: *mut *mut u32,
        input_mirror: *mut *mut u32,
        output: *mut *mut u32,
        output_mirror: *mut *mut u32,
        count: u32,
    ) -> u32 {
        unsafe {
            SEEN = [mode as usize, input as usize, input_mirror as usize, output as usize, output_mirror as usize, count as usize];
            STATUS
        }
    }

    fn invoke(mode: u32, status: u32) -> (u32, u32, [usize; 6], [usize; 6]) {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut source = [0x1020_3040u32, 0];
        let mut target = [0u32; 2];
        let mut input = source.as_mut_ptr();
        let mut input_mirror = source.as_mut_ptr();
        let mut output = target.as_mut_ptr();
        let mut output_mirror = target.as_mut_ptr();
        let mut leading = 0;
        let expected = [
            mode as usize,
            (&mut input as *mut *mut u32) as usize,
            (&mut input_mirror as *mut *mut u32) as usize,
            (&mut output as *mut *mut u32) as usize,
            (&mut output_mirror as *mut *mut u32) as usize,
            0x17,
        ];
        unsafe {
            CHECKED_WORD_BLOCK_OPS = CheckedWordBlockOps { convert_core: recorder };
            STATUS = status;
            let result = checked_word_block_convert(mode, &mut input, &mut input_mirror, &mut output, &mut output_mirror, 0x17, &mut leading);
            let seen = SEEN;
            CHECKED_WORD_BLOCK_OPS = DEFAULT_CHECKED_WORD_BLOCK_OPS;
            (result, leading, seen, expected)
        }
    }

    #[test]
    fn mode_zero_preserves_the_leading_word_and_forwards_all_arguments() {
        let (status, leading, seen, expected) = invoke(0, CHECKSUM_MISMATCH);
        assert_eq!(status, CHECKSUM_MISMATCH, "core status returns unchanged");
        assert_eq!(leading, 0x1020_3040, "mode 0 is identity");
        assert_eq!(seen, expected, "all six core arguments forward verbatim and in order");
    }

    #[test]
    fn mode_one_swaps_the_leading_word_before_the_core_runs() {
        let (status, leading, seen, expected) = invoke(1, 0);
        assert_eq!(status, 0);
        assert_eq!(leading, 0x4030_2010, "mode 1 reverses all four bytes");
        assert_eq!(seen, expected, "mode 1 preserves all core arguments");
    }
}
