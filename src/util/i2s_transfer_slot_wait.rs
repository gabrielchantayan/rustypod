//! I2S transfer-slot wait — `i2s_transfer_slot_wait` @ 0x08008690.
//!
//! Original: `FUN_08008690` @ 0x08008690 (48 bytes). Raw ARM is
//! `0x08008690..0x080086c0`; the following word at 0x080086c0 is its table
//! literal and 0x080086c4 begins the next function. It has four inbound plain
//! `bl` calls (0x080049f0, 0x0800836c, 0x08008380, 0x080085a0), no predicated
//! inbound `bl` calls, and one unconditional outbound `bl` (0x080086b0).
//!
//! Looks up `base + controller * 0x20 + channel * 4 - 0x20` in the shared I2S
//! transfer table. A zero cell returns 0x11. Otherwise it calls the raw veneer
//! at 0x080039f8, whose literal resolves to the unidentified core at
//! 0x0804bacc, with the cell word in r0 and channel in r1, then returns zero.
//! Deliberate deviation: ARM calls the resolved veneer target directly because
//! the separately linked Rust payload cannot branch to the stock veneer.

/// Firmware literal at 0x080086c0, shared with transfer setup and cleanup.
pub static mut I2S_TRANSFER_SLOT_WAIT_TABLE_BASE: *mut u32 = 0x2200_ae7cusize as *mut u32;

/// Observed register ABI of the unidentified core reached through 0x080039f8.
pub type I2sTransferWaitCore = unsafe extern "C" fn(u32, u32);

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_i2s_transfer_wait_core(handle: u32, channel: u32) {
    let core: I2sTransferWaitCore = core::mem::transmute(0x0804_baccusize);
    core(handle, channel);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_i2s_transfer_wait_core(_handle: u32, _channel: u32) {
    panic!("i2s_transfer_slot_wait requires retailOS core 0x0804bacc")
}

#[cfg(target_os = "none")]
const DEFAULT_I2S_TRANSFER_WAIT_CORE: I2sTransferWaitCore = firmware_i2s_transfer_wait_core;
#[cfg(not(target_os = "none"))]
const DEFAULT_I2S_TRANSFER_WAIT_CORE: I2sTransferWaitCore = missing_i2s_transfer_wait_core;

/// The unported core reached through the retailOS 0x080039f8 veneer.
pub static mut I2S_TRANSFER_WAIT_CORE: I2sTransferWaitCore = DEFAULT_I2S_TRANSFER_WAIT_CORE;

/// i2s_transfer_slot_wait — original: `FUN_08008690` @ 0x08008690 (48 bytes).
///
/// Returns 0x11 when the selected transfer-handle cell is zero. Otherwise,
/// invokes the unknown transfer core with the handle and channel, returning 0.
///
/// # Safety
/// `I2S_TRANSFER_SLOT_WAIT_TABLE_BASE` must identify the original
/// word-addressed table and the selected cell must be readable. The callback
/// must implement the observed r0/r1 ABI.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn i2s_transfer_slot_wait(controller: i32, channel: i32) -> u32 {
    const CONTROLLER_STRIDE_WORDS: isize = 8;
    const BASE_TO_FIRST_CELL_WORDS: isize = 8;

    let cell = I2S_TRANSFER_SLOT_WAIT_TABLE_BASE.offset(
        controller as isize * CONTROLLER_STRIDE_WORDS + channel as isize - BASE_TO_FIRST_CELL_WORDS,
    );
    let handle = cell.read_volatile();
    if handle == 0 {
        0x11
    } else {
        I2S_TRANSFER_WAIT_CORE(handle, channel as u32);
        0
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::{
        i2s_transfer_slot_wait, I2S_TRANSFER_SLOT_WAIT_TABLE_BASE, I2S_TRANSFER_WAIT_CORE,
    };
    use core::sync::atomic::{AtomicBool, Ordering};
    static TEST_LOCK: AtomicBool = AtomicBool::new(false);
    static mut CALL_COUNT: u32 = 0;
    static mut SEEN_HANDLE: u32 = 0;
    static mut SEEN_CHANNEL: u32 = 0;

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

    unsafe extern "C" fn record_wait(handle: u32, channel: u32) {
        CALL_COUNT += 1;
        SEEN_HANDLE = handle;
        SEEN_CHANNEL = channel;
    }

    struct SeamReset {
        table_base: *mut u32,
        wait_core: unsafe extern "C" fn(u32, u32),
    }

    impl Drop for SeamReset {
        fn drop(&mut self) {
            unsafe {
                I2S_TRANSFER_SLOT_WAIT_TABLE_BASE = self.table_base;
                I2S_TRANSFER_WAIT_CORE = self.wait_core;
            }
        }
    }

    fn fresh(table_base: *mut u32) -> (TestLock, SeamReset) {
        let lock = lock();
        unsafe {
            let reset = SeamReset {
                table_base: I2S_TRANSFER_SLOT_WAIT_TABLE_BASE,
                wait_core: I2S_TRANSFER_WAIT_CORE,
            };
            I2S_TRANSFER_SLOT_WAIT_TABLE_BASE = table_base;
            I2S_TRANSFER_WAIT_CORE = record_wait;
            CALL_COUNT = 0;
            SEEN_HANDLE = 0;
            SEEN_CHANNEL = 0;
            (lock, reset)
        }
    }

    #[test]
    fn empty_slot_returns_busy_without_calling_core() {
        let mut table = [0u32; 32];
        let base = unsafe { table.as_mut_ptr().add(8) };
        let (_lock, _reset) = fresh(base);

        assert_eq!(unsafe { i2s_transfer_slot_wait(2, 3) }, 0x11);
        assert_eq!(unsafe { CALL_COUNT }, 0);
    }

    #[test]
    fn populated_slot_calls_core_with_handle_and_channel() {
        let mut table = [0u32; 32];
        let base = unsafe { table.as_mut_ptr().add(8) };
        let (_lock, _reset) = fresh(base);
        table[8 + 1 * 8 + 6 - 8] = 0xa5a5_5a5a;

        assert_eq!(unsafe { i2s_transfer_slot_wait(1, 6) }, 0);
        assert_eq!(unsafe { CALL_COUNT }, 1);
        assert_eq!(unsafe { SEEN_HANDLE }, 0xa5a5_5a5a);
        assert_eq!(unsafe { SEEN_CHANNEL }, 6);
    }
}
