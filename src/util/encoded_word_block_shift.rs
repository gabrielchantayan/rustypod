//! `encoded_word_block_shift` — signed shift-direction dispatcher for the
//! encoded-count word-block family.
//!
//! Original: `FUN_08342d70` @ `0x08342d70` (52 bytes,
//! `0x08342d70..0x08342da4`; the next function begins with `push` at
//! `0x08342da4`). A complete decode of every ARM `B`/`BL` word in
//! `work/firmware/osos.dec` found 15 direct call sites: all are unconditional
//! `bl`, with no predicated calls or tail-branch callers.
//!
//! The dispatcher returns zero without dereferencing its block for a zero
//! signed distance. A positive distance tail-transfers to the stock right-shift
//! routine at `0x08322c48`; a negative distance tail-transfers the wrapping
//! absolute magnitude to the stock left-shift routine at `0x08341910`.
//! `i32::MIN` therefore reaches the left routine with `0x80000000`, exactly as
//! ARM's `rsb` does.
//!
//! Deliberate deviation: none on target; release codegen restores the frame
//! and tail-branches through the selected fixed entry. Host builds replace that
//! address with a volatile callback seam so tests can observe dispatch without
//! mapping firmware addresses.

#[cfg(not(target_os = "none"))]
use core::ptr;

use super::encoded_word_block::EncodedWordBlock;

/// Real entry point of the stock routine selected by a positive distance.
pub const ENCODED_WORD_BLOCK_SHIFT_RIGHT_ADDRESS: usize = 0x0832_2c48;
/// Real entry point of the stock routine selected by a negative distance.
pub const ENCODED_WORD_BLOCK_SHIFT_LEFT_ADDRESS: usize = 0x0834_1910;

/// ABI shared by the two unported direction-specific retailOS routines.
pub type EncodedWordBlockShiftDirection =
    unsafe extern "C" fn(magnitude: u32, block: *mut EncodedWordBlock) -> u32;

/// Host-test replacement points for the two stock direction routines.
#[derive(Clone, Copy)]
pub struct EncodedWordBlockShiftOps {
    pub shift_right: EncodedWordBlockShiftDirection,
    pub shift_left: EncodedWordBlockShiftDirection,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_encoded_word_block_shift(
    _magnitude: u32,
    _block: *mut EncodedWordBlock,
) -> u32 {
    0
}

/// Host default for unported direction-specific firmware routines.
#[cfg(not(target_os = "none"))]
pub const DEFAULT_ENCODED_WORD_BLOCK_SHIFT_OPS: EncodedWordBlockShiftOps =
    EncodedWordBlockShiftOps {
        shift_right: missing_encoded_word_block_shift,
        shift_left: missing_encoded_word_block_shift,
    };

/// Volatile host seam for the two unported retailOS routines.
#[cfg(not(target_os = "none"))]
pub static mut ENCODED_WORD_BLOCK_SHIFT_OPS: EncodedWordBlockShiftOps =
    DEFAULT_ENCODED_WORD_BLOCK_SHIFT_OPS;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn shift_right(magnitude: u32, block: *mut EncodedWordBlock) -> u32 {
    let routine: EncodedWordBlockShiftDirection =
        core::mem::transmute(ENCODED_WORD_BLOCK_SHIFT_RIGHT_ADDRESS);
    routine(magnitude, block)
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn shift_right(magnitude: u32, block: *mut EncodedWordBlock) -> u32 {
    let ops = ptr::read_volatile(ptr::addr_of!(ENCODED_WORD_BLOCK_SHIFT_OPS));
    (ops.shift_right)(magnitude, block)
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn shift_left(magnitude: u32, block: *mut EncodedWordBlock) -> u32 {
    let routine: EncodedWordBlockShiftDirection =
        core::mem::transmute(ENCODED_WORD_BLOCK_SHIFT_LEFT_ADDRESS);
    routine(magnitude, block)
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn shift_left(magnitude: u32, block: *mut EncodedWordBlock) -> u32 {
    let ops = ptr::read_volatile(ptr::addr_of!(ENCODED_WORD_BLOCK_SHIFT_OPS));
    (ops.shift_left)(magnitude, block)
}

/// Selects the stock encoded-word-block shift direction from a signed distance.
///
/// Original: `FUN_08342d70` @ `0x08342d70` (52 bytes; 15 unconditional `bl`
/// call sites). A zero distance returns zero before touching `block`. Positive
/// distances enter the right-shift routine; negative distances enter the
/// left-shift routine with their ARM-wrapping absolute magnitude.
///
/// # Safety
/// For a nonzero distance, `block` must meet the selected stock shift
/// routine's requirements. A zero distance accepts any pointer, including
/// NULL, because the firmware does not dereference it.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn encoded_word_block_shift(
    block: *mut EncodedWordBlock,
    signed_distance: i32,
) -> u32 {
    if signed_distance == 0 {
        return 0;
    }

    if signed_distance > 0 {
        shift_right(signed_distance as u32, block)
    } else {
        shift_left((signed_distance as u32).wrapping_neg(), block)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::ptr;
    use parking_lot::Mutex;
    use std::vec;
    use std::vec::Vec;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: Vec<(bool, u32, usize)> = Vec::new();
    static mut RESULT: u32 = 0;

    unsafe extern "C" fn record_right(magnitude: u32, block: *mut EncodedWordBlock) -> u32 {
        CALLS.push((false, magnitude, block as usize));
        RESULT
    }

    unsafe extern "C" fn record_left(magnitude: u32, block: *mut EncodedWordBlock) -> u32 {
        CALLS.push((true, magnitude, block as usize));
        RESULT
    }

    unsafe fn install_recorders(result: u32) {
        CALLS.clear();
        RESULT = result;
        ptr::write_volatile(
            ptr::addr_of_mut!(ENCODED_WORD_BLOCK_SHIFT_OPS),
            EncodedWordBlockShiftOps {
                shift_right: record_right,
                shift_left: record_left,
            },
        );
    }

    #[test]
    fn zero_returns_without_dereferencing_or_dispatching() {
        let _guard = TEST_LOCK.lock();
        unsafe {
            install_recorders(0xfeed_beef);
            assert_eq!(encoded_word_block_shift(ptr::null_mut(), 0), 0);
            assert!(CALLS.is_empty());
        }
    }

    #[test]
    fn positive_distance_preserves_pointer_and_returns_right_result() {
        let _guard = TEST_LOCK.lock();
        let block = 0x1234usize as *mut EncodedWordBlock;
        unsafe {
            install_recorders(0x1234_5678);
            assert_eq!(encoded_word_block_shift(block, i32::MAX), 0x1234_5678);
            assert_eq!(CALLS, vec![(false, i32::MAX as u32, block as usize)]);
        }
    }

    #[test]
    fn negative_distances_use_left_with_wrapping_magnitude() {
        let _guard = TEST_LOCK.lock();
        let block = 0x5678usize as *mut EncodedWordBlock;
        unsafe {
            install_recorders(0x8765_4321);
            assert_eq!(encoded_word_block_shift(block, -1), 0x8765_4321);
            assert_eq!(encoded_word_block_shift(block, i32::MIN), 0x8765_4321);
            assert_eq!(
                CALLS,
                vec![
                    (true, 1, block as usize),
                    (true, 0x8000_0000, block as usize),
                ],
            );
        }
    }
}
