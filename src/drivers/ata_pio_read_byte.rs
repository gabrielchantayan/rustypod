//! ATA PIO byte-read primitive.
//!
//! Port: [`ata_pio_read_byte`] — original: `FUN_080bb610` @ `0x080bb610`
//! (52 bytes, `0x080bb610..0x080bb644`; the next real function starts at
//! `0x080bb648`; **4 inbound plain `bl` call sites and zero predicated
//! forms**). The final word is the `0x3870_0000` literal pool.
//!
//! The S5L8702 ATA controller's `ATA_PIO_READY` register is `0x38700078`.
//! The routine waits for bit 1, volatile-reads `source` and stores that byte
//! to `destination`; it then waits for bit 0 and overwrites `destination`
//! with the byte at `ATA_PIO_READ_DATA` (`0x3870007c`). It returns zero
//! without a NULL guard or timeout; callers must provide valid byte pointers
//! and the controller must progress.
//!
//! # Deliberate deviation
//!
//! Device builds use volatile physical MMIO reads. Host builds model the two
//! fixed MMIO registers with atomics solely to exercise both readiness gates
//! and the final controller-data overwrite; caller pointers remain volatile.

const ATA_PIO_READY: *const u32 = 0x3870_0078 as *const u32;
const ATA_PIO_READ_DATA: *const u8 = 0x3870_007c as *const u8;
const ATA_PIO_TRIGGER_READY: u32 = 1 << 1;
const ATA_PIO_READ_READY: u32 = 1;

#[cfg(not(target_os = "none"))]
use core::sync::atomic::{AtomicU32, AtomicU8, Ordering};

#[cfg(not(target_os = "none"))]
static HOST_ATA_PIO_READY: AtomicU32 = AtomicU32::new(ATA_PIO_TRIGGER_READY | ATA_PIO_READ_READY);
#[cfg(not(target_os = "none"))]
static HOST_ATA_PIO_READ_DATA: AtomicU8 = AtomicU8::new(0);

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

#[inline(always)]
unsafe fn ata_pio_read_data() -> u8 {
    #[cfg(target_os = "none")]
    {
        unsafe { core::ptr::read_volatile(ATA_PIO_READ_DATA) }
    }

    #[cfg(not(target_os = "none"))]
    {
        HOST_ATA_PIO_READ_DATA.load(Ordering::SeqCst)
    }
}

/// ata_pio_read_byte — original: `FUN_080bb610` @ 0x080bb610 (52 bytes;
/// **4 inbound plain `bl` call sites, zero predicated forms**).
///
/// Waits for bit 1, copies `source` to `destination`, then waits for bit 0 and
/// overwrites `destination` with the ATA PIO read-data byte. Returns the
/// firmware's zero status without validating either caller pointer or timing
/// out.
///
/// # Safety
///
/// `source` must be a valid, readable PIO register and `destination` must be
/// a valid, writable byte buffer.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ata_pio_read_byte(source: *const u8, destination: *mut u8) -> i32 {
    while unsafe { ata_pio_ready() } & ATA_PIO_TRIGGER_READY == 0 {}
    let source_value = unsafe { core::ptr::read_volatile(source) };
    unsafe { core::ptr::write_volatile(destination, source_value) };
    while unsafe { ata_pio_ready() } & ATA_PIO_READ_READY == 0 {}
    let read_data = unsafe { ata_pio_read_data() };
    unsafe { core::ptr::write_volatile(destination, read_data) };
    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::{ata_pio_read_byte, ATA_PIO_READ_READY, ATA_PIO_TRIGGER_READY, HOST_ATA_PIO_READ_DATA, HOST_ATA_PIO_READY};
    use core::sync::atomic::Ordering;
    use std::sync::mpsc;
    use std::time::Duration;

    #[test]
    fn waits_for_both_readiness_bits_and_returns_controller_byte() {
        HOST_ATA_PIO_READY.store(0, Ordering::SeqCst);
        HOST_ATA_PIO_READ_DATA.store(0xa5, Ordering::SeqCst);
        let (entered_tx, entered_rx) = mpsc::channel();
        let (completed_tx, completed_rx) = mpsc::channel();

        let worker = std::thread::spawn(move || {
            let source = 0x3c;
            let mut destination = 0;
            entered_tx.send(()).unwrap();
            let status = unsafe { ata_pio_read_byte(&source, &mut destination) };
            completed_tx.send((status, destination)).unwrap();
        });

        entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        HOST_ATA_PIO_READY.store(ATA_PIO_READ_READY, Ordering::SeqCst);
        assert!(completed_rx.recv_timeout(Duration::from_millis(25)).is_err());

        HOST_ATA_PIO_READY.store(ATA_PIO_TRIGGER_READY, Ordering::SeqCst);
        assert!(completed_rx.recv_timeout(Duration::from_millis(25)).is_err());

        HOST_ATA_PIO_READY.store(ATA_PIO_TRIGGER_READY | ATA_PIO_READ_READY, Ordering::SeqCst);
        let result = completed_rx.recv_timeout(Duration::from_secs(1));
        HOST_ATA_PIO_READY.store(u32::MAX, Ordering::SeqCst);
        worker.join().unwrap();
        assert_eq!(result.unwrap(), (0, 0xa5));
        HOST_ATA_PIO_READ_DATA.store(0, Ordering::SeqCst);
        HOST_ATA_PIO_READY.store(ATA_PIO_TRIGGER_READY | ATA_PIO_READ_READY, Ordering::SeqCst);
    }
}
