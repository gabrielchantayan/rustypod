//! PMU status bit selected by board generation.
//!
//! `pmu_board_version_status_bit` — original: `FUN_082e5b64` @
//! `0x082e5b64` (76 bytes; the distinct `push {r4,r5,r6,lr}` prologue at
//! `0x082e5bb0` confirms the extent).
//!
//! Binary decoding of every ARM B/BL word in `osos.dec` finds **8 direct
//! `bl` callers**, all unconditional (cond=e; no predicated forms):
//! 0x080608a8, 0x08060958, 0x080609c0, 0x080c8898, 0x080d3ce8,
//! 0x080e36a8, 0x082e5798, and 0x08392ff8.
//!
//! The routine snapshots the incoming r3 word into its stack byte, obtains
//! the lazily cached board version, then holds PMU transaction semaphores 17
//! and 5 while reading one PCF50635 byte. Boards whose high version halfword
//! is 0x11 read register 0x4b and return bit 0; every other board reads
//! register 0x12 and returns bit 2. The raw I2C status is deliberately
//! ignored, so a failed transfer leaves the saved incoming-r3 byte and its
//! selected bit becomes the result.
//!
//! # Deviations
//!
//! The retail ABI has no declared arguments but preserves its incoming r3 in
//! the stack scratch byte before the transfer. Rust exposes r0-r3 explicitly
//! so `incoming_r3` retains that observable failed-transfer behavior; the
//! other three words remain unused. The six direct retail calls resolve to
//! their already-ported Rust functions, replacing direct `bl` edges with
//! normal Rust calls.

use crate::drivers::i2c::pmu_i2c_read;
use crate::kernel::task_lock::{kernel_sem17_signal, kernel_sem17_wait, kernel_sem5_signal, kernel_sem5_wait};
use crate::sysinfo::board_version;

/// PCF50635 register read only on boards whose version high halfword is 0x11.
const PMU_BOARD_0X11_STATUS_REGISTER: u32 = 0x4b;
/// PCF50635 register read on every other board generation.
const PMU_OTHER_BOARD_STATUS_REGISTER: u32 = 0x12;

/// pmu_board_version_status_bit — original: `FUN_082e5b64` @ `0x082e5b64`
/// (76 bytes; 8 unconditional `bl` call sites, binary-verified).
///
/// Reads the generation-selected PMU status byte while holding semaphore 17
/// then semaphore 5, releases 5 then 17 unconditionally, and returns the
/// selected one-bit field. The I2C status is ignored exactly as in retail;
/// therefore its failed-transfer result derives from the low byte of the
/// incoming r3 scratch word.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn pmu_board_version_status_bit(
    _incoming_r0: u32,
    _incoming_r1: u32,
    _incoming_r2: u32,
    incoming_r3: u32,
) -> u32 {
    let version = board_version();

    let version_0x11 = (version >> 16 == 0x11) as u32;
    kernel_sem17_wait();
    kernel_sem5_wait();

    let register = PMU_OTHER_BOARD_STATUS_REGISTER
        + version_0x11 * (PMU_BOARD_0X11_STATUS_REGISTER - PMU_OTHER_BOARD_STATUS_REGISTER);
    let mut status_byte = incoming_r3 as u8;
    pmu_i2c_read(register, 1, &mut status_byte);

    kernel_sem5_signal();
    kernel_sem17_signal();

    ((status_byte as u32 >> ((1 - version_0x11) << 1)) & 1) as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drivers::i2c::tests::{install_raw_i2c_for_test, raw_i2c_calls_for_test};
    use crate::sysinfo::install_host_cached_board_version;
    extern crate std;

    #[test]
    fn board_0x11_reads_register_4b_and_returns_bit_zero() {
        let _board = install_host_cached_board_version(0x0011_0000);
        let _i2c = install_raw_i2c_for_test(0, 0, 0b0000_0001);

        assert_eq!(unsafe { pmu_board_version_status_bit(0, 0, 0, 0) }, 1);
        let (writes, reads, semaphores) = unsafe { raw_i2c_calls_for_test() };
        assert_eq!(writes, std::vec![(0x73, 1, PMU_BOARD_0X11_STATUS_REGISTER as u8)]);
        assert_eq!(reads.len(), 1, "a successful one-byte register read occurs");
        assert_eq!(reads[0].0, 0x73);
        assert_eq!(reads[0].1, 1);
        assert_eq!(semaphores, std::vec![(0, 0x11), (0, 5), (1, 5), (1, 0x11)]);
    }

    #[test]
    fn other_boards_read_register_12_and_return_bit_two() {
        let _board = install_host_cached_board_version(0x0010_ffff);
        let _i2c = install_raw_i2c_for_test(0, 0, 0b0000_0100);

        assert_eq!(unsafe { pmu_board_version_status_bit(0, 0, 0, 0) }, 1);
        let (writes, reads, semaphores) = unsafe { raw_i2c_calls_for_test() };
        assert_eq!(writes, std::vec![(0x73, 1, PMU_OTHER_BOARD_STATUS_REGISTER as u8)]);
        assert_eq!(reads.len(), 1);
        assert_eq!(semaphores, std::vec![(0, 0x11), (0, 5), (1, 5), (1, 0x11)]);
    }

    #[test]
    fn failed_write_preserves_the_incoming_r3_scratch_bit() {
        let _board = install_host_cached_board_version(0x0011_0000);
        let _i2c = install_raw_i2c_for_test(-5, 0, 0);

        assert_eq!(unsafe { pmu_board_version_status_bit(0, 0, 0, 1) }, 1);
        let (writes, reads, semaphores) = unsafe { raw_i2c_calls_for_test() };
        assert_eq!(writes, std::vec![(0x73, 1, PMU_BOARD_0X11_STATUS_REGISTER as u8)]);
        assert!(reads.is_empty(), "a failed register write suppresses the read");
        assert_eq!(semaphores, std::vec![(0, 0x11), (0, 5), (1, 5), (1, 0x11)]);
    }
}
