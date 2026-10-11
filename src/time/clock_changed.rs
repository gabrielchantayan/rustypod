//! Clock metadata notification — `FUN_0805caa8` @ `0x0805caa8`.
//!
//! True extent: 64 bytes, 0x0805caa8..0x0805cae8 (56 instruction bytes
//! and two literals). Raw aligned ARM decoding finds two incoming plain BLs
//! at 0x080674e8 and 0x080e1d94, no predicated incoming BLs, and one outgoing
//! plain BL at 0x0805cad8, no predicated outgoing BLs.
//!
//! If the current clock status is nonzero, submit the four-byte `Vctr`
//! marker followed by the UTC offset and DST bytes. Raw 0x0809eff0..0x0809f02c
//! writes byte +5 to PMU register 5, byte +4 to register 4, and four bytes
//! starting at +0 to register 0 through pmu_i2c_write_locked (0x082e5bb0).
//! The helper remains a fixed-address call: only this function is ported.
//!
//! Deliberate deviations: zero the unused last two packet bytes rather than
//! exposing the original saved r3 upper half. The verified callee reads only
//! the first six bytes. Host builds inject that helper; target uses retailOS.

use core::ptr;
use super::sync_best_clock::current_clock;

#[repr(C)]
pub struct ClockMetadataPacket {
    pub marker: u32,
    pub utc_offset_quarters: i8,
    pub dst_active: u8,
    pub unused: [u8; 2],
}

type WriteClockMetadata = unsafe extern "C" fn(*const ClockMetadataPacket);

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_write(_packet: *const ClockMetadataPacket) {
    panic!("install clock metadata writer before notifying clock changes")
}
#[cfg(not(target_os = "none"))]
pub static mut WRITE_CLOCK_METADATA: WriteClockMetadata = missing_write;

/// Notify the PMU when any current-clock status bit is set.
/// Caller must serialize access to the firmware-owned current clock.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn clock_changed() {
    let clock = current_clock();
    if ptr::read_volatile(ptr::addr_of!((*clock).status)) == 0 { return; }
    let packet = ClockMetadataPacket {
        marker: 0x7274_6356,
        utc_offset_quarters: ptr::read_volatile(ptr::addr_of!((*clock).utc_offset_quarters)),
        dst_active: ptr::read_volatile(ptr::addr_of!((*clock).dst_active)),
        unused: [0; 2],
    };
    #[cfg(target_os = "none")]
    let write: WriteClockMetadata = core::mem::transmute(0x0809_eff0usize);
    #[cfg(not(target_os = "none"))]
    let write = ptr::read_volatile(ptr::addr_of!(WRITE_CLOCK_METADATA));
    write(&packet);
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::sync_best_clock::{CURRENT_CLOCK, tests::install};
    static mut SEEN: Option<(u32, i8, u8)> = None;
    unsafe extern "C" fn record(packet: *const ClockMetadataPacket) {
        SEEN = Some(((*packet).marker, (*packet).utc_offset_quarters, (*packet).dst_active));
    }

    #[test]
    fn status_gates_notification_without_filtering_metadata() {
        unsafe {
            let _fixture = install();
            let previous = WRITE_CLOCK_METADATA;
            WRITE_CLOCK_METADATA = record;
            for (status, offset, dst) in [(0, -128, 255), (1, -128, 255), (2, 127, 0), (128, -1, 128), (255, 0, 1)] {
                CURRENT_CLOCK.status = status;
                CURRENT_CLOCK.utc_offset_quarters = offset;
                CURRENT_CLOCK.dst_active = dst;
                SEEN = None;
                clock_changed();
                assert_eq!(SEEN, if status == 0 { None } else { Some((0x7274_6356, offset, dst)) });
                assert_eq!((CURRENT_CLOCK.status, CURRENT_CLOCK.utc_offset_quarters, CURRENT_CLOCK.dst_active), (status, offset, dst));
            }
            WRITE_CLOCK_METADATA = previous;
        }
    }
}
