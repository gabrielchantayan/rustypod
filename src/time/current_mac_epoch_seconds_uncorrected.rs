//! Current Macintosh-epoch seconds without UTC/DST correction.
//!
//! Original: `FUN_08054fbc` @ **0x08054fbc**, true extent **8 bytes**
//! (`0x08054fbc..0x08054fc4`): raw words `e3a00000 eafff374`, or
//! `mov r0,#0; b 0x08051d98`. The next independent wrapper starts at
//! 0x08054fc4 with `mov r0,#1`. Whole-image aligned ARM decoding verifies
//! **2 plain inbound BLs** (0x08058018, 0x0806cb10), **0 predicated BLs**;
//! the body has no BL instructions and one unconditional tail branch.
//!
//! The shared target queries a normalized DateTime, ignores query status,
//! then converts it to wrapping signed Macintosh-epoch seconds with offset
//! correction disabled. Incoming r0 is overwritten, so there are no arguments.
//!
//! Deliberate deviations: inline the shared target's two existing Rust ports
//! rather than introduce a firmware seam. Zero-initialize stack padding instead
//! of spilling caller register residue; neither calendar operation reads it.

use super::datetime::DateTime;

/// Returns current signed Macintosh-epoch seconds without querying UTC/DST.
///
/// # Safety
/// Installed calendar-query and day-number normalization handlers must accept
/// their documented output records.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn current_mac_epoch_seconds_uncorrected() -> i32 {
    let mut datetime: DateTime = core::mem::zeroed();
    super::current_datetime::current_datetime_to_normalized_record(&mut datetime);
    super::datetime_to_mac_epoch::datetime_to_mac_epoch_seconds(&mut datetime, 0)
}
