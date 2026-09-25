//! I2S transfer-channel teardown — `i2s_transfer_channel_teardown` @ 0x080085fc.
//!
//! Original: `FUN_080085fc` @ 0x080085fc (72 bytes; the next function opens
//! at 0x08008648). Raw ARM contains two plain unconditional `bl` instructions
//! and no predicated `bl` instructions.
//!
//! For a nonzero slot and a controller other than -1, retailOS first releases
//! the transfer slot through 0x08004c4c, then calls 0x080080cc to clear the
//! controller channel's active bit and signal its completion mask. It finally
//! clears the byte at `0x22010000 + slot * 8 + controller - 8`. The stock
//! routine always returns zero. No deliberate deviations.

use super::i2s_transfer_slot::i2s_transfer_slot_cleanup;

/// Firmware literal loaded at 0x08008644. It is the active-byte table base.
pub static mut I2S_TRANSFER_CHANNEL_ACTIVE_TABLE: *mut u8 = 0x2201_0000usize as *mut u8;

/// Observed ABI of `FUN_080080cc` at 0x080080cc.
pub type I2sTransferChannelDeactivate = unsafe extern "C" fn(i32, i32) -> u32;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_i2s_transfer_channel_deactivate(slot: i32, controller: i32) -> u32 {
    let deactivate: I2sTransferChannelDeactivate = core::mem::transmute(0x0800_80ccusize);
    deactivate(slot, controller)
}

#[cfg(target_os = "none")]
const DEFAULT_I2S_TRANSFER_CHANNEL_DEACTIVATE: I2sTransferChannelDeactivate =
    firmware_i2s_transfer_channel_deactivate;
#[cfg(not(target_os = "none"))]
const DEFAULT_I2S_TRANSFER_CHANNEL_DEACTIVATE: I2sTransferChannelDeactivate =
    missing_i2s_transfer_channel_deactivate;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_i2s_transfer_channel_deactivate(_slot: i32, _controller: i32) -> u32 {
    panic!("i2s_transfer_channel_teardown requires FUN_080080cc")
}

/// The unported controller-specific deactivate routine; host tests replace it.
pub static mut I2S_TRANSFER_CHANNEL_DEACTIVATE: I2sTransferChannelDeactivate =
    DEFAULT_I2S_TRANSFER_CHANNEL_DEACTIVATE;

/// i2s_transfer_channel_teardown — original: `FUN_080085fc` @ 0x080085fc
/// (72 bytes).
///
/// Releases and deactivates a valid I2S transfer channel, then clears its
/// active byte. Slot zero and controller -1 are invalid sentinels and leave all
/// state unchanged. Returns zero in every case.
///
/// # Safety
/// The active table and both retailOS callees must be valid for the supplied
/// slot and controller.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn i2s_transfer_channel_teardown(slot: i32, controller: i32) -> u32 {
    if slot != 0 && controller != -1 {
        i2s_transfer_slot_cleanup(slot, controller);
        I2S_TRANSFER_CHANNEL_DEACTIVATE(slot, controller);
        I2S_TRANSFER_CHANNEL_ACTIVE_TABLE
            .offset(slot as isize * 8 + controller as isize - 8)
            .write_volatile(0);
    }
    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use crate::util::i2s_transfer_slot::{I2S_TRANSFER_CLEANUP, I2S_TRANSFER_SLOT_TABLE_BASE};
    use super::{
        i2s_transfer_channel_teardown, I2S_TRANSFER_CHANNEL_ACTIVE_TABLE,
        I2S_TRANSFER_CHANNEL_DEACTIVATE,
    };
    use core::sync::atomic::{AtomicBool, Ordering};

    static TEST_LOCK: AtomicBool = AtomicBool::new(false);
    static mut CALL_COUNT: u32 = 0;
    static mut SEEN_SLOT: i32 = 0;
    static mut SEEN_CONTROLLER: i32 = 0;

    struct TestLock;
    impl Drop for TestLock {
        fn drop(&mut self) { TEST_LOCK.store(false, Ordering::Release); }
    }

    fn lock() -> TestLock {
        while TEST_LOCK.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
            core::hint::spin_loop();
        }
        TestLock
    }

    unsafe extern "C" fn record_deactivate(slot: i32, controller: i32) -> u32 {
        CALL_COUNT += 1;
        SEEN_SLOT = slot;
        SEEN_CONTROLLER = controller;
        0
    }

    unsafe extern "C" fn ignore_cleanup(_handle: u32, _controller: u32) {}

    struct SeamReset {
        table: *mut u8,
        deactivate: unsafe extern "C" fn(i32, i32) -> u32,
        slot_table: *mut u32,
        cleanup: unsafe extern "C" fn(u32, u32),
    }
    impl Drop for SeamReset {
        fn drop(&mut self) {
            unsafe {
                I2S_TRANSFER_CHANNEL_ACTIVE_TABLE = self.table;
                I2S_TRANSFER_CHANNEL_DEACTIVATE = self.deactivate;
                I2S_TRANSFER_SLOT_TABLE_BASE = self.slot_table;
                I2S_TRANSFER_CLEANUP = self.cleanup;
            }
        }
    }

    fn fresh(table: *mut u8, slot_table: *mut u32) -> (TestLock, SeamReset) {
        let lock = lock();
        unsafe {
            let reset = SeamReset {
                table: I2S_TRANSFER_CHANNEL_ACTIVE_TABLE,
                deactivate: I2S_TRANSFER_CHANNEL_DEACTIVATE,
                slot_table: I2S_TRANSFER_SLOT_TABLE_BASE,
                cleanup: I2S_TRANSFER_CLEANUP,
            };
            I2S_TRANSFER_CHANNEL_ACTIVE_TABLE = table;
            I2S_TRANSFER_CHANNEL_DEACTIVATE = record_deactivate;
            I2S_TRANSFER_SLOT_TABLE_BASE = slot_table;
            I2S_TRANSFER_CLEANUP = ignore_cleanup;
            CALL_COUNT = 0;
            SEEN_SLOT = 0;
            SEEN_CONTROLLER = 0;
            (lock, reset)
        }
    }

    #[test]
    fn sentinel_slot_or_controller_leaves_the_active_byte_unchanged() {
        let mut active = [0xa5u8; 32];
        let mut slots = [0u32; 32];
        let (_lock, _reset) = fresh(active.as_mut_ptr().wrapping_add(8), unsafe { slots.as_mut_ptr().add(8) });

        assert_eq!(unsafe { i2s_transfer_channel_teardown(0, 2) }, 0);
        assert_eq!(unsafe { i2s_transfer_channel_teardown(1, -1) }, 0);

        assert_eq!(unsafe { CALL_COUNT }, 0);
        assert_eq!(active, [0xa5; 32]);
    }

    #[test]
    fn valid_channel_deactivates_and_clears_retail_byte_layout() {
        let mut active = [0xa5u8; 48];
        let mut slots = [0u32; 32];
        let base = unsafe { active.as_mut_ptr().add(8) };
        let (_lock, _reset) = fresh(base, unsafe { slots.as_mut_ptr().add(8) });
        active[8 + 2 * 8 + 3 - 8] = 0x7f;

        assert_eq!(unsafe { i2s_transfer_channel_teardown(2, 3) }, 0);

        assert_eq!(unsafe { CALL_COUNT }, 1);
        assert_eq!(unsafe { SEEN_SLOT }, 2);
        assert_eq!(unsafe { SEEN_CONTROLLER }, 3);
        assert_eq!(active[19], 0);
    }
}
