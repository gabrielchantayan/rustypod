//! `iram_queue_transfer_with_default_mode_veneer` — original:
//! `thunk_EXT_FUN_22008648` @ `0x08038018` (8 bytes).
//!
//! Raw `osos.dec` words establish the complete veneer: `ldr pc, [pc, #-4]` at
//! `0x08038018`, followed by its literal target `0x22008648`; `0x08038020` is
//! the next independent veneer. The literal is the IRAM mirror of the already
//! ported `queue_transfer_with_default_mode` at `0x08008648`. Whole-image A32
//! decoding finds three inbound plain `bl` calls (`0x080f7dcc`, `0x0836b04c`,
//! and `0x0836b0b4`) and no predicated `bl` calls. The veneer preserves all
//! five argument words and tail-transfers to the default-control DMA transfer
//! wrapper.
//!
//! # Deliberate deviation
//!
//! Rust expresses the ARM `ldr pc` tail transfer as an ordinary call to the
//! ported target. The target returns `void`, so this preserves all observable
//! argument and return behavior while emitting a call/return pair rather than
//! an absolute IRAM-mirror jump.

use crate::drivers::transfer_default_mode::queue_transfer_with_default_mode;

type QueueTransferWithDefaultMode = unsafe extern "C" fn(u32, u32, u32, u32, u32);

#[inline(always)]
unsafe fn dispatch_queue_transfer_with_default_mode(
    target: QueueTransferWithDefaultMode,
    first: u32,
    second: u32,
    length: u32,
    transfer_type: u32,
    transfer_slot: u32,
) {
    unsafe { target(first, second, length, transfer_type, transfer_slot) };
}

/// Tail-dispatches the five transfer words through the IRAM-mirrored default
/// DMA-transfer wrapper at `0x22008648` (`0x08008648` in the OSOS image).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn iram_queue_transfer_with_default_mode_veneer(
    first: u32,
    second: u32,
    length: u32,
    transfer_type: u32,
    transfer_slot: u32,
) {
    unsafe {
        dispatch_queue_transfer_with_default_mode(
            queue_transfer_with_default_mode,
            first,
            second,
            length,
            transfer_type,
            transfer_slot,
        );
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static RECORDED_ARGUMENTS: Mutex<[u32; 5]> = Mutex::new([0; 5]);
    static CALL_COUNT: Mutex<u32> = Mutex::new(0);

    unsafe extern "C" fn record_transfer(
        first: u32,
        second: u32,
        length: u32,
        transfer_type: u32,
        transfer_slot: u32,
    ) {
        *RECORDED_ARGUMENTS.lock() = [first, second, length, transfer_type, transfer_slot];
        *CALL_COUNT.lock() += 1;
    }

    #[test]
    fn forwards_zero_and_word_boundary_arguments_unchanged() {
        let _lock = TEST_LOCK.lock();
        *RECORDED_ARGUMENTS.lock() = [0; 5];
        *CALL_COUNT.lock() = 0;

        unsafe {
            dispatch_queue_transfer_with_default_mode(record_transfer, 0, u32::MAX, 0x8000_0000, 1, 0xffff_fffe);
        }

        assert_eq!(*CALL_COUNT.lock(), 1);
        assert_eq!(*RECORDED_ARGUMENTS.lock(), [0, u32::MAX, 0x8000_0000, 1, 0xffff_fffe]);
    }
}
