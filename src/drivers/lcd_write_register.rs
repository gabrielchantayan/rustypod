//! LCD controller register write.
//!
//! Port: [`lcd_write_register`] — original: `FUN_080d4b14` @ `0x080d4b14`
//! (24 bytes, `0x080d4b14..0x080d4b28`; **12 unconditional `bl` call sites,
//! no predicated forms**). Raw disassembly places the next function at
//! `0x080d4b2c`; no literal pool belongs to this body. Decoding every ARM
//! B/BL word in `osos.dec` finds no direct B or data-word references.
//!
//! The 0x3830_0000 LCD controller uses bit 4 of status +0x1c as busy. This
//! routine waits for that bit to clear, writes `register_index` to +0x04,
//! waits again, then writes `value` to +0x40. It has no timeout or validation;
//! callers rely on the panel controller becoming ready. The separate waits are
//! required: the firmware calls the same readiness helper before each store.
//!
//! # Deliberate deviation
//!
//! The ARM body reaches the two stores through unported 24-byte helpers at
//! `0x080d7b60` and `0x080bb5f4`. Their complete observable behavior is the
//! readiness poll and one respective MMIO store, so this port inlines those
//! helpers instead of inventing dispatch seams. Device MMIO accesses are
//! volatile; host builds use atomic register models solely for behavioral
//! tests.

const LCD_CONTROLLER_BASE: usize = 0x3830_0000;
const LCD_STATUS_OFFSET: usize = 0x1c;
const LCD_REGISTER_INDEX_OFFSET: usize = 0x04;
const LCD_REGISTER_VALUE_OFFSET: usize = 0x40;
const LCD_BUSY: u32 = 1 << 4;

#[cfg(not(target_os = "none"))]
use core::sync::atomic::{AtomicU32, Ordering};

#[cfg(not(target_os = "none"))]
static HOST_LCD_STATUS: AtomicU32 = AtomicU32::new(0);
#[cfg(not(target_os = "none"))]
static HOST_LCD_REGISTER_INDEX: AtomicU32 = AtomicU32::new(0);
#[cfg(not(target_os = "none"))]
static HOST_LCD_REGISTER_VALUE: AtomicU32 = AtomicU32::new(0);
#[cfg(all(test, not(target_os = "none")))]
static HOST_LCD_STATUS_READS: AtomicU32 = AtomicU32::new(0);

#[inline(always)]
unsafe fn lcd_status() -> u32 {
    #[cfg(target_os = "none")]
    {
        unsafe {
            core::ptr::read_volatile((LCD_CONTROLLER_BASE + LCD_STATUS_OFFSET) as *const u32)
        }
    }

    #[cfg(not(target_os = "none"))]
    {
        #[cfg(test)]
        HOST_LCD_STATUS_READS.fetch_add(1, Ordering::SeqCst);
        HOST_LCD_STATUS.load(Ordering::SeqCst)
    }
}

#[inline(always)]
unsafe fn lcd_write_word(offset: usize, value: u32) {
    #[cfg(target_os = "none")]
    unsafe {
        core::ptr::write_volatile((LCD_CONTROLLER_BASE + offset) as *mut u32, value);
    }

    #[cfg(not(target_os = "none"))]
    match offset {
        LCD_REGISTER_INDEX_OFFSET => HOST_LCD_REGISTER_INDEX.store(value, Ordering::SeqCst),
        LCD_REGISTER_VALUE_OFFSET => HOST_LCD_REGISTER_VALUE.store(value, Ordering::SeqCst),
        _ => unreachable!(),
    }
}

#[inline(always)]
unsafe fn lcd_wait_ready() {
    while unsafe { lcd_status() } & LCD_BUSY != 0 {}
}

/// lcd_write_register — original: `FUN_080d4b14` @ `0x080d4b14` (24 bytes;
/// **12 unconditional `bl` call sites, no predicated forms**).
///
/// Waits for the LCD controller before issuing `register_index`, waits again,
/// then writes `value`. Neither argument is restricted to the panel's known
/// register/value ranges, matching the raw ARM stores.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn lcd_write_register(register_index: u32, value: u32) {
    unsafe { lcd_wait_ready() };
    unsafe { lcd_write_word(LCD_REGISTER_INDEX_OFFSET, register_index) };
    unsafe { lcd_wait_ready() };
    unsafe { lcd_write_word(LCD_REGISTER_VALUE_OFFSET, value) };
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::{lcd_write_register, HOST_LCD_REGISTER_INDEX, HOST_LCD_REGISTER_VALUE,
        HOST_LCD_STATUS, HOST_LCD_STATUS_READS, LCD_BUSY};
    use core::sync::atomic::Ordering;
    use parking_lot::Mutex;
    use std::sync::mpsc;
    use std::time::Duration;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn reset_host_controller(status: u32) {
        HOST_LCD_STATUS.store(status, Ordering::SeqCst);
        HOST_LCD_REGISTER_INDEX.store(u32::MAX, Ordering::SeqCst);
        HOST_LCD_REGISTER_VALUE.store(u32::MAX, Ordering::SeqCst);
        HOST_LCD_STATUS_READS.store(0, Ordering::SeqCst);
    }

    #[test]
    fn writes_full_width_register_and_value_after_each_ready_check() {
        let _guard = TEST_LOCK.lock();

        for (register_index, value) in [
            (0, 0),
            (0x0210, 0x8000_0000),
            (u32::MAX, u32::MAX),
        ] {
            reset_host_controller(0);
            unsafe { lcd_write_register(register_index, value) };
            assert_eq!(HOST_LCD_REGISTER_INDEX.load(Ordering::SeqCst), register_index);
            assert_eq!(HOST_LCD_REGISTER_VALUE.load(Ordering::SeqCst), value);
            assert_eq!(HOST_LCD_STATUS_READS.load(Ordering::SeqCst), 2);
        }
    }

    #[test]
    fn busy_status_blocks_both_writes_until_bit_four_clears() {
        let _guard = TEST_LOCK.lock();
        reset_host_controller(LCD_BUSY);
        let (started_tx, started_rx) = mpsc::channel();
        let (finished_tx, finished_rx) = mpsc::channel();

        let worker = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            unsafe { lcd_write_register(0x0213, 0x1234_5678) };
            finished_tx.send(()).unwrap();
        });

        started_rx.recv().unwrap();
        assert!(finished_rx.recv_timeout(Duration::from_millis(25)).is_err());
        assert_eq!(HOST_LCD_REGISTER_INDEX.load(Ordering::SeqCst), u32::MAX);
        assert_eq!(HOST_LCD_REGISTER_VALUE.load(Ordering::SeqCst), u32::MAX);

        HOST_LCD_STATUS.store(0, Ordering::SeqCst);
        finished_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        worker.join().unwrap();
        assert_eq!(HOST_LCD_REGISTER_INDEX.load(Ordering::SeqCst), 0x0213);
        assert_eq!(HOST_LCD_REGISTER_VALUE.load(Ordering::SeqCst), 0x1234_5678);
    }
}
