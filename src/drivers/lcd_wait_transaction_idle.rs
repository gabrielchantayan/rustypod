//! LCD transaction-completion polling.

#[cfg(not(target_os = "none"))]
use core::sync::atomic::{AtomicU32, Ordering};

const LCD_CONTROLLER_BASE: usize = 0x3830_0000;
const LCD_TRANSACTION_STATUS_OFFSET: usize = 0x8c;

#[cfg(not(target_os = "none"))]
static HOST_LCD_TRANSACTION_STATUS: AtomicU32 = AtomicU32::new(0);
#[cfg(all(test, not(target_os = "none")))]
static HOST_LCD_TRANSACTION_READS: AtomicU32 = AtomicU32::new(0);

#[inline(always)]
unsafe fn lcd_transaction_status() -> u32 {
    #[cfg(target_os = "none")]
    {
        core::ptr::read_volatile(
            (LCD_CONTROLLER_BASE + LCD_TRANSACTION_STATUS_OFFSET) as *const u32,
        )
    }
    #[cfg(not(target_os = "none"))]
    {
        let status = HOST_LCD_TRANSACTION_STATUS.load(Ordering::SeqCst);
        #[cfg(test)]
        HOST_LCD_TRANSACTION_READS.fetch_add(1, Ordering::SeqCst);
        status
    }
}

/// lcd_wait_transaction_idle — original: `FUN_080d510c` @ `0x080d510c`.
///
/// True extent is 24 bytes: five A32 instructions (20 bytes), followed by
/// literal `0x38300000` at `0x080d5120`; the next function starts at
/// `0x080d5124`. Whole-image raw decoding finds one plain inbound BL at
/// `0x080c5ddc` and one BLNE at `0x080c5e34`; no outbound calls.
///
/// Repeatedly reads LCD transaction status at +0x8c until both low busy bits
/// clear. Returns the entire final word left in r0, including unrelated high
/// bits. No writes, timeout, or scheduler yield. Deliberate deviations:
/// volatile target MMIO and an atomic host register model; unlike Ghidra's
/// void prototype, the ABI exposes the final status word.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn lcd_wait_transaction_idle() -> u32 {
    wait_for_transaction_idle()
}

/// lcd_wait_display_idle — original: `FUN_080c907c` @ `0x080c907c`.
///
/// True extent: 24 bytes (20 instruction bytes plus the LCD base literal
/// at `0x080c9090`); next real function begins at `0x080c9094`.
/// Raw A32 decoding verifies one plain inbound BL at `0x080af6c8` and
/// one BLNE at `0x080af720`, with no outbound calls.
///
/// Poll aligned LCD status at `0x3830008c` until bits 0 and 1 clear,
/// returning the complete final status left in r0. No writes or timeout.
/// Deliberate deviations: volatile MMIO, atomic host model, and a u32
/// return instead of Ghidra's void. Shares the identical polling body with
/// lcd_wait_transaction_idle; LLVM may intentionally fold the two exports.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn lcd_wait_display_idle() -> u32 {
    wait_for_transaction_idle()
}

#[inline(always)]
unsafe fn wait_for_transaction_idle() -> u32 {
    loop {
        let status = lcd_transaction_status();
        if status & 3 == 0 {
            return status;
        }
    }
}

#[cfg(test)]
mod transaction_tests {
    extern crate std;
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn waits_for_each_busy_bit_and_returns_unmasked_final_status() {
        for wait in [lcd_wait_transaction_idle, lcd_wait_display_idle] {
        for busy in [0, 1, 2, 3, 0xffff_ffff] {
            HOST_LCD_TRANSACTION_READS.store(0, Ordering::SeqCst);
            HOST_LCD_TRANSACTION_STATUS.store(busy, Ordering::SeqCst);
            if busy == 0 {
                assert_eq!(unsafe { wait() }, 0);
                assert_eq!(HOST_LCD_TRANSACTION_READS.load(Ordering::SeqCst), 1);
                continue;
            }
            let worker = std::thread::spawn(move || unsafe { wait() });
            let deadline = Instant::now() + Duration::from_secs(5);
            while HOST_LCD_TRANSACTION_READS.load(Ordering::SeqCst) < 2 {
                if Instant::now() >= deadline {
                    HOST_LCD_TRANSACTION_STATUS.store(0, Ordering::SeqCst);
                    worker.join().unwrap();
                    panic!("poller did not reread busy status");
                }
                std::thread::yield_now();
            }
            assert!(!worker.is_finished(), "returned while a busy bit remained set");
            HOST_LCD_TRANSACTION_STATUS.store(0xa5a5_5a5c, Ordering::SeqCst);
            assert_eq!(worker.join().unwrap(), 0xa5a5_5a5c);
        }
            HOST_LCD_TRANSACTION_STATUS.store(0xffff_fffc, Ordering::SeqCst);
            assert_eq!(unsafe { wait() }, 0xffff_fffc);
        }
    }
}
