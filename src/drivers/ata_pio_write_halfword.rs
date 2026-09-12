//! ATA PIO halfword-write primitive.
//!
//! Port: [`ata_pio_write_halfword`] — original: `FUN_080c9a4c` @ `0x080c9a4c`
//! (28 bytes, `0x080c9a4c..0x080c9a68`; **8 `bl` call sites, all
//! unconditional**). The next function begins at `0x080c9a6c`; the intervening
//! word at `0x080c9a68` is this function's `0x38700000` literal pool. Decoding
//! every ARM B/BL word in `osos.dec` finds no DATA word containing this entry,
//! so it is never virtually dispatched.
//!
//! The S5L8702 ATA controller's `ATA_PIO_READY` register is
//! `0x38700078`. The routine polls bit 1 until the PIO engine accepts a write,
//! stores `value` to the caller-selected ATA task-file register, and returns
//! zero. It deliberately has no NULL or timeout path; callers must supply a
//! live, halfword-aligned PIO register and the controller must progress.
//!
//! # Deliberate deviation
//!
//! Device builds read the physical ready register with a volatile load. Host
//! builds model that register with an atomic word solely to exercise the
//! readiness gate; the destination store remains volatile in both builds.

const ATA_PIO_READY: *const u32 = 0x3870_0078 as *const u32;
const ATA_PIO_WRITE_READY: u32 = 1 << 1;

#[cfg(not(target_os = "none"))]
use core::sync::atomic::{AtomicU32, Ordering};

/// Host model of [`ATA_PIO_READY`].
#[cfg(not(target_os = "none"))]
static HOST_ATA_PIO_READY: AtomicU32 = AtomicU32::new(ATA_PIO_WRITE_READY);

#[inline(always)]
unsafe fn ata_pio_ready() -> u32 {
    #[cfg(target_os = "none")]
    {
        unsafe { core::ptr::read_volatile(ATA_PIO_READY) }
    }

    #[cfg(not(target_os = "none"))]
    {
        HOST_ATA_PIO_READY.load(Ordering::SeqCst)
    }
}

/// ata_pio_write_halfword — original: `FUN_080c9a4c` @ `0x080c9a4c` (28 bytes;
/// **8 `bl` call sites, all unconditional**).
///
/// Waits for `ATA_PIO_READY` bit 1, then writes `value` to `destination` and
/// returns the firmware's zero status. The halfword store deliberately does not
/// validate the destination or impose a timeout.
///
/// # Safety
///
/// `destination` must be a valid, writable, halfword-aligned ATA task-file
/// register.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ata_pio_write_halfword(destination: *mut u16, value: u16) -> i32 {
    while unsafe { ata_pio_ready() } & ATA_PIO_WRITE_READY == 0 {}
    unsafe { core::ptr::write_volatile(destination, value) };
    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::{ata_pio_write_halfword, HOST_ATA_PIO_READY};
    use core::sync::atomic::Ordering;
    use std::sync::mpsc;
    use std::time::Duration;

    #[test]
    fn waits_for_write_ready_bit_before_storing_halfword() {
        HOST_ATA_PIO_READY.store(0, Ordering::SeqCst);
        let (entered_tx, entered_rx) = mpsc::channel();
        let (completed_tx, completed_rx) = mpsc::channel();

        let worker = std::thread::spawn(move || {
            let mut destination = 0;
            entered_tx.send(()).unwrap();
            let status = unsafe { ata_pio_write_halfword(&mut destination, 0xa5c3) };
            completed_tx.send((status, destination)).unwrap();
        });

        entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        // Bit 0 signals PIO read data ready; it must not permit a write.
        HOST_ATA_PIO_READY.store(1, Ordering::SeqCst);
        assert!(completed_rx.recv_timeout(Duration::from_millis(25)).is_err());

        HOST_ATA_PIO_READY.store(2, Ordering::SeqCst);
        let result = completed_rx.recv_timeout(Duration::from_secs(1));
        HOST_ATA_PIO_READY.store(u32::MAX, Ordering::SeqCst);
        worker.join().unwrap();
        assert_eq!(result.unwrap(), (0, 0xa5c3));
        HOST_ATA_PIO_READY.store(2, Ordering::SeqCst);
    }
}
