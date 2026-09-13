//! LCD controller data-port writes.
//!
//! Ports:
//! - [`lcd_write_value`] — original: `FUN_080bb5f4` @ `0x080bb5f4` (28
//!   bytes including its literal pool, `0x080bb5f4..0x080bb60f`; **9
//!   unconditional `bl` call sites, no predicated forms**).
//! - [`lcd_write_register`] — original: `FUN_080d4b14` @ `0x080d4b14` (24
//!   bytes, `0x080d4b14..0x080d4b28`; **12 unconditional `bl` call sites, no
//!   predicated forms**).
//! - [`lcd_begin_command_transaction`] — original: `FUN_080dbdb8` @
//!   `0x080dbdb8` (100 bytes; **7 unconditional `bl` call sites, no
//!   predicated forms**). Preserves the LCD control word while preparing the
//!   controller for a script of register writes.
//!
//! Raw disassembly puts the next separately linked function after
//! `lcd_write_value` at `0x080bb610`; its final word at `0x080bb60c` is the
//! `0x3830_0000` literal pool. Decoding every ARM B/BL immediate in
//! `osos.dec` finds the nine inbound calls are all unconditional `bl`; the
//! sole direct B is the tail call at `0x080d4b28` from `lcd_write_register`.
//!
//! The 0x3830_0000 LCD controller uses bit 4 of status +0x1c as busy.
//! `lcd_write_value` retains its input across the readiness wait and stores it
//! at +0x40. `lcd_write_register` waits before selecting +0x04, then delegates
//! the second wait and +0x40 store to `lcd_write_value`. Neither function
//! validates its input or has a timeout.
//!
//! # Deliberate deviation
//!
//! The device uses volatile MMIO loads and stores. Host builds use atomic
//! register models solely for behavioral tests.

const LCD_CONTROLLER_BASE: usize = 0x3830_0000;
const LCD_STATUS_OFFSET: usize = 0x1c;
const LCD_REGISTER_INDEX_OFFSET: usize = 0x04;
const LCD_REGISTER_VALUE_OFFSET: usize = 0x40;
const LCD_BUSY: u32 = 1 << 4;
const LCD_CONTROL_OFFSET: usize = 0x00;
const LCD_COMMAND_READY: u32 = 1 << 1;

#[cfg(not(target_os = "none"))]
use core::sync::atomic::{AtomicU32, Ordering};

#[cfg(not(target_os = "none"))]
static HOST_LCD_STATUS: AtomicU32 = AtomicU32::new(0);
#[cfg(not(target_os = "none"))]
static HOST_LCD_CONTROL: AtomicU32 = AtomicU32::new(0);
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
        LCD_CONTROL_OFFSET => HOST_LCD_CONTROL.store(value, Ordering::SeqCst),
        LCD_REGISTER_INDEX_OFFSET => HOST_LCD_REGISTER_INDEX.store(value, Ordering::SeqCst),
        LCD_REGISTER_VALUE_OFFSET => HOST_LCD_REGISTER_VALUE.store(value, Ordering::SeqCst),
        _ => unreachable!(),
    }
}

#[inline(always)]
unsafe fn lcd_control() -> u32 {
    #[cfg(target_os = "none")]
    {
        core::ptr::read_volatile((LCD_CONTROLLER_BASE + LCD_CONTROL_OFFSET) as *const u32)
    }

    #[cfg(not(target_os = "none"))]
    {
        HOST_LCD_CONTROL.load(Ordering::SeqCst)
    }
}

#[inline(always)]
unsafe fn lcd_write_control(value: u32) {
    unsafe { lcd_write_word(LCD_CONTROL_OFFSET, value) };
}

#[inline(always)]
unsafe fn lcd_wait_ready() {
    while unsafe { lcd_status() } & LCD_BUSY != 0 {}
}

#[inline(always)]
unsafe fn lcd_wait_command_ready() {
    while unsafe { lcd_status() } & LCD_COMMAND_READY == 0 {}
}

/// lcd_write_value — original: `FUN_080bb5f4` @ `0x080bb5f4` (28 bytes,
/// including the literal pool; **9 unconditional `bl` call sites, no
/// predicated forms**).
///
/// Preserves `value` through the readiness wait, then stores all 32 bits at
/// the LCD controller's data port (+0x40). The original has no NULL pointer,
/// range, or busy-timeout guard. Host builds deliberately model the volatile
/// MMIO registers with atomics.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn lcd_write_value(value: u32) {
    unsafe { lcd_wait_ready() };
    unsafe { lcd_write_word(LCD_REGISTER_VALUE_OFFSET, value) };
}

/// lcd_write_register — original: `FUN_080d4b14` @ `0x080d4b14` (24 bytes;
/// **12 unconditional `bl` call sites, no predicated forms**).
///
/// Waits for the LCD controller before issuing `register_index`, then
/// tail-calls [`lcd_write_value`] for the second readiness wait and `value`
/// store. Neither argument is restricted to the panel's known register/value
/// ranges, matching the raw ARM stores.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn lcd_write_register(register_index: u32, value: u32) {
    unsafe { lcd_wait_ready() };
    unsafe { lcd_write_word(LCD_REGISTER_INDEX_OFFSET, register_index) };
    unsafe { lcd_write_value(value) };
}

/// ABI of the unported display-mode query at `0x080a3f48`.
pub type LcdCommandModeFn = unsafe extern "C" fn() -> u32;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_lcd_command_mode() -> u32 {
    let mode: LcdCommandModeFn = core::mem::transmute(0x080a3f48usize);
    mode()
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_lcd_command_mode() -> u32 {
    panic!("lcd_begin_command_transaction requires display-mode query 0x080a3f48")
}

/// Host-replaceable direct call to the unported display-mode query.
///
/// `FUN_080a3f48` is absent from `names.yaml`; target builds call its verified
/// retailOS entry while host tests substitute a deterministic mode source.
pub static mut LCD_COMMAND_MODE: LcdCommandModeFn = firmware_lcd_command_mode;

#[inline(always)]
unsafe fn lcd_command_mode() -> u32 {
    core::ptr::read_volatile(core::ptr::addr_of!(LCD_COMMAND_MODE))()
}

/// lcd_begin_command_transaction — original: `FUN_080dbdb8` @ `0x080dbdb8`
/// (100 bytes; **7 verified direct `bl` call sites: all unconditional, zero
/// predicated**).
///
/// Saves the LCD control word, waits until status +0x1c raises command-ready
/// bit 1, delays one microsecond through the already-ported IRAM veneer, then
/// queries the display mode. Modes 0/1 retain only control bit 31 and bits
/// 0..2 before setting `0xc20`; modes 2/3 use `0xda8`; every other mode leaves
/// the control word untouched. The saved word is always returned for the
/// paired restore helper at `0x080dbe20`.
///
/// Deliberate deviation: target MMIO accesses remain volatile; host builds use
/// atomic controller words and a replaceable unported mode-query boundary.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn lcd_begin_command_transaction() -> u32 {
    let saved_control = unsafe { lcd_control() };
    unsafe { lcd_wait_command_ready() };
    unsafe { crate::drivers::timer::iram_usec_delay_veneer(1) };

    let control = match unsafe { lcd_command_mode() } {
        0 | 1 => Some((saved_control & 0x8000_0007) | 0x0c20),
        2 | 3 => Some((saved_control & 0x8000_0007) | 0x0da8),
        _ => None,
    };
    if let Some(control) = control {
        unsafe { lcd_write_control(control) };
    }

    saved_control
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::{lcd_begin_command_transaction, lcd_write_register, lcd_write_value,
        LcdCommandModeFn, HOST_LCD_CONTROL, HOST_LCD_REGISTER_INDEX,
        HOST_LCD_REGISTER_VALUE, HOST_LCD_STATUS, HOST_LCD_STATUS_READS,
        LCD_BUSY, LCD_COMMAND_MODE, LCD_COMMAND_READY};
    use core::sync::atomic::{AtomicU32, Ordering};
    use parking_lot::Mutex;
    use std::sync::mpsc;
    use std::time::Duration;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    static HOST_LCD_COMMAND_MODE: AtomicU32 = AtomicU32::new(0);
    static HOST_LCD_COMMAND_MODE_CALLS: AtomicU32 = AtomicU32::new(0);

    unsafe extern "C" fn host_lcd_command_mode() -> u32 {
        HOST_LCD_COMMAND_MODE_CALLS.fetch_add(1, Ordering::SeqCst);
        HOST_LCD_COMMAND_MODE.load(Ordering::SeqCst)
    }

    struct LcdCommandModeSeam {
        original: LcdCommandModeFn,
    }

    impl Drop for LcdCommandModeSeam {
        fn drop(&mut self) {
            unsafe { LCD_COMMAND_MODE = self.original };
        }
    }

    fn install_lcd_command_mode() -> LcdCommandModeSeam {
        let original = unsafe {
            core::ptr::read_volatile(core::ptr::addr_of!(LCD_COMMAND_MODE))
        };
        unsafe { LCD_COMMAND_MODE = host_lcd_command_mode };
        HOST_LCD_COMMAND_MODE_CALLS.store(0, Ordering::SeqCst);
        LcdCommandModeSeam { original }
    }

    fn reset_host_controller(status: u32) {
        HOST_LCD_STATUS.store(status, Ordering::SeqCst);
        HOST_LCD_REGISTER_INDEX.store(u32::MAX, Ordering::SeqCst);
        HOST_LCD_REGISTER_VALUE.store(u32::MAX, Ordering::SeqCst);
        HOST_LCD_STATUS_READS.store(0, Ordering::SeqCst);
        HOST_LCD_CONTROL.store(u32::MAX, Ordering::SeqCst);
    }

    #[test]
    fn writes_full_width_value_after_ready_check() {
        let _guard = TEST_LOCK.lock();

        for value in [0, 0x8000_0000, u32::MAX] {
            reset_host_controller(0);
            unsafe { lcd_write_value(value) };
            assert_eq!(HOST_LCD_REGISTER_INDEX.load(Ordering::SeqCst), u32::MAX);
            assert_eq!(HOST_LCD_REGISTER_VALUE.load(Ordering::SeqCst), value);
            assert_eq!(HOST_LCD_STATUS_READS.load(Ordering::SeqCst), 1);
        }
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
    #[test]
    fn command_transaction_selects_control_bits_for_supported_modes() {
        let _guard = TEST_LOCK.lock();
        let _timer = crate::drivers::timer::configure_usec_timer_for_test(0, 1);
        let _mode_seam = install_lcd_command_mode();

        for (mode, base, suffix) in [
            (0, 0x8000_0005, 0x0c20),
            (1, 0x5a5a_5a53, 0x0c20),
            (2, 0x8000_0007, 0x0da8),
            (3, 0x1234_567d, 0x0da8),
        ] {
            reset_host_controller(LCD_COMMAND_READY);
            HOST_LCD_CONTROL.store(base, Ordering::SeqCst);
            HOST_LCD_COMMAND_MODE.store(mode, Ordering::SeqCst);

            assert_eq!(unsafe { lcd_begin_command_transaction() }, base);
            assert_eq!(
                HOST_LCD_CONTROL.load(Ordering::SeqCst),
                (base & 0x8000_0007) | suffix,
                "mode {mode}"
            );
        }
        assert_eq!(HOST_LCD_COMMAND_MODE_CALLS.load(Ordering::SeqCst), 4);
    }

    #[test]
    fn command_transaction_keeps_control_for_unsupported_modes() {
        let _guard = TEST_LOCK.lock();
        let _timer = crate::drivers::timer::configure_usec_timer_for_test(0, 1);
        let _mode_seam = install_lcd_command_mode();

        for (mode, control) in [(4, 0x8123_4567), (u32::MAX, 0x0000_0000)] {
            reset_host_controller(LCD_COMMAND_READY);
            HOST_LCD_CONTROL.store(control, Ordering::SeqCst);
            HOST_LCD_COMMAND_MODE.store(mode, Ordering::SeqCst);

            assert_eq!(unsafe { lcd_begin_command_transaction() }, control);
            assert_eq!(HOST_LCD_CONTROL.load(Ordering::SeqCst), control, "mode {mode:#x}");
        }
        assert_eq!(HOST_LCD_COMMAND_MODE_CALLS.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn command_transaction_waits_for_command_ready() {
        let _guard = TEST_LOCK.lock();
        let _timer = crate::drivers::timer::configure_usec_timer_for_test(0, 1);
        let _mode_seam = install_lcd_command_mode();
        let saved_control = 0x8000_0003;
        reset_host_controller(0);
        HOST_LCD_CONTROL.store(saved_control, Ordering::SeqCst);
        HOST_LCD_COMMAND_MODE.store(2, Ordering::SeqCst);
        let (started_tx, started_rx) = mpsc::channel();
        let (finished_tx, finished_rx) = mpsc::channel();

        let worker = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            let saved = unsafe { lcd_begin_command_transaction() };
            finished_tx.send(saved).unwrap();
        });

        started_rx.recv().unwrap();
        assert!(finished_rx.recv_timeout(Duration::from_millis(25)).is_err());
        assert_eq!(HOST_LCD_CONTROL.load(Ordering::SeqCst), saved_control);

        HOST_LCD_STATUS.store(LCD_COMMAND_READY, Ordering::SeqCst);
        assert_eq!(
            finished_rx.recv_timeout(Duration::from_secs(1)).unwrap(),
            saved_control
        );
        worker.join().unwrap();
        assert_eq!(
            HOST_LCD_CONTROL.load(Ordering::SeqCst),
            (saved_control & 0x8000_0007) | 0x0da8
        );
    }
}
