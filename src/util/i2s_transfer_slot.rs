//! I2S transfer-slot cleanup — `i2s_transfer_slot_cleanup` @ 0x08004c4c.
//!
//! Original: `FUN_08004c4c` @ 0x08004c4c (40 bytes).
//!
//! The I2S transfer setup path at 0x080083c4 obtains a transfer handle through
//! the companion setter at 0x08004c78.  The sole recovered teardown caller
//! (0x080085fc) passes the same controller and channel indices here before it
//! clears that channel's active flag.  The literal table base is 0x2200ae7c;
//! its first meaningful cell is 0x20 bytes before that address.  Thus the
//! handle cell is `base + controller * 0x20 + channel * 4 - 0x20`.
//!
//! If that cell is nonzero, the original calls the unported transfer cleanup
//! core at 0x0804b614 with the cell word in r0 and the channel in r1, then
//! always clears the cell.  The cleanup core's recovered decompilation has
//! live-register stack state, but its ARM entry immediately consumes r0/r1;
//! the two-register seam below preserves the observed call ABI.  The table is
//! a firmware-addressed mutable global on target and is replaceable, together
//! with the cleanup callback, by deterministic host tests.


/// Firmware literal loaded at 0x08004c4c.  It points 0x20 bytes after the
/// controller-zero/channel-zero handle cell.
pub static mut I2S_TRANSFER_SLOT_TABLE_BASE: *mut u32 = 0x2200_ae7cusize as *mut u32;

/// Observed register ABI for the unported cleanup core at 0x0804b614.
pub type I2sTransferCleanup = unsafe extern "C" fn(u32, u32);

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_i2s_transfer_cleanup(handle: u32, channel: u32) {
    let cleanup: I2sTransferCleanup = core::mem::transmute(0x0804_b614usize);
    cleanup(handle, channel);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_i2s_transfer_cleanup(_handle: u32, _channel: u32) {
    panic!("i2s_transfer_slot_cleanup requires transfer cleanup core 0x0804b614")
}

#[cfg(target_os = "none")]
const DEFAULT_I2S_TRANSFER_CLEANUP: I2sTransferCleanup = firmware_i2s_transfer_cleanup;
#[cfg(not(target_os = "none"))]
const DEFAULT_I2S_TRANSFER_CLEANUP: I2sTransferCleanup = missing_i2s_transfer_cleanup;

/// The unported transfer cleanup core; target builds call retailOS and host
/// tests replace this callback.
pub static mut I2S_TRANSFER_CLEANUP: I2sTransferCleanup = DEFAULT_I2S_TRANSFER_CLEANUP;

/// i2s_transfer_slot_cleanup — original: `FUN_08004c4c` @ 0x08004c4c
/// (40 bytes).
///
/// Computes the I2S transfer-handle cell for `controller` and `channel`.
/// When it holds a nonzero handle, invokes the transfer cleanup core with that
/// handle and `channel`; regardless of its prior value, clears the cell.
///
/// # Safety
/// `I2S_TRANSFER_SLOT_TABLE_BASE` must identify the original word-addressed
/// table and the selected cell must be readable and writable.  The callback
/// must implement the retailOS cleanup core's observed r0/r1 ABI.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn i2s_transfer_slot_cleanup(controller: i32, channel: i32) {
    const CONTROLLER_STRIDE_WORDS: isize = 8;
    const BASE_TO_FIRST_CELL_WORDS: isize = 8;

    let cell = I2S_TRANSFER_SLOT_TABLE_BASE.offset(
        controller as isize * CONTROLLER_STRIDE_WORDS + channel as isize - BASE_TO_FIRST_CELL_WORDS,
    );
    let handle = cell.read_volatile();
    if handle != 0 {
        I2S_TRANSFER_CLEANUP(handle, channel as u32);
    }
    cell.write_volatile(0);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::{i2s_transfer_slot_cleanup, I2S_TRANSFER_CLEANUP, I2S_TRANSFER_SLOT_TABLE_BASE};
    use core::sync::atomic::{AtomicBool, Ordering};

    static TEST_LOCK: AtomicBool = AtomicBool::new(false);
    struct TestLock;

    impl Drop for TestLock {
        fn drop(&mut self) {
            TEST_LOCK.store(false, Ordering::Release);
        }
    }

    fn lock() -> TestLock {
        while TEST_LOCK
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        TestLock
    }

    fn fresh(table_base: *mut u32) -> (TestLock, SeamReset) {
        let lock = lock();
        unsafe {
            let reset = SeamReset {
                table_base: I2S_TRANSFER_SLOT_TABLE_BASE,
                cleanup: I2S_TRANSFER_CLEANUP,
            };
            I2S_TRANSFER_SLOT_TABLE_BASE = table_base;
            I2S_TRANSFER_CLEANUP = record_cleanup;
            CALL_COUNT = 0;
            SEEN_HANDLE = 0;
            SEEN_CHANNEL = 0;
            (lock, reset)
        }
    }

    static mut CALL_COUNT: u32 = 0;
    static mut SEEN_HANDLE: u32 = 0;
    static mut SEEN_CHANNEL: u32 = 0;

    unsafe extern "C" fn record_cleanup(handle: u32, channel: u32) {
        CALL_COUNT += 1;
        SEEN_HANDLE = handle;
        SEEN_CHANNEL = channel;
    }

    struct SeamReset {
        table_base: *mut u32,
        cleanup: unsafe extern "C" fn(u32, u32),
    }

    impl Drop for SeamReset {
        fn drop(&mut self) {
            unsafe {
                I2S_TRANSFER_SLOT_TABLE_BASE = self.table_base;
                I2S_TRANSFER_CLEANUP = self.cleanup;
            }
        }
    }


    #[test]
    fn zero_cell_is_cleared_without_invoking_cleanup() {
        let mut table = [0xfeed_faceu32; 32];
        let base = unsafe { table.as_mut_ptr().add(8) };
        let (_lock, _reset) = fresh(base);
        table[8 + 2 * 8 + 3 - 8] = 0;

        unsafe { i2s_transfer_slot_cleanup(2, 3) };

        assert_eq!(unsafe { CALL_COUNT }, 0);
        assert_eq!(table[19], 0);
    }

    #[test]
    fn nonzero_cell_is_cleaned_then_cleared() {
        let mut table = [0u32; 32];
        let base = unsafe { table.as_mut_ptr().add(8) };
        let (_lock, _reset) = fresh(base);
        table[8 + 1 * 8 + 6 - 8] = 0xa5a5_5a5a;

        unsafe { i2s_transfer_slot_cleanup(1, 6) };

        assert_eq!(unsafe { CALL_COUNT }, 1);
        assert_eq!(unsafe { SEEN_HANDLE }, 0xa5a5_5a5a);
        assert_eq!(unsafe { SEEN_CHANNEL }, 6);
        assert_eq!(table[14], 0);
    }

    #[test]
    fn controller_and_channel_use_the_retail_word_layout() {
        let mut table = [0u32; 40];
        let base = unsafe { table.as_mut_ptr().add(8) };
        let (_lock, _reset) = fresh(base);
        table[8] = 0x1111_1111; // controller 1, channel 0
        table[8 + 2 * 8 + 7 - 8] = 0x2222_2222; // controller 2, channel 7

        unsafe { i2s_transfer_slot_cleanup(2, 7) };

        assert_eq!(unsafe { CALL_COUNT }, 1);
        assert_eq!(unsafe { SEEN_HANDLE }, 0x2222_2222);
        assert_eq!(table[8], 0x1111_1111, "a controller stride is 0x20 bytes");
        assert_eq!(table[23], 0, "a channel stride is one word");
    }
}
