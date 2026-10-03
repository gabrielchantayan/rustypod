//! Wait/timer clock query — `FUN_08262158` @ 0x08262158.
//!
//! True extent: 24 bytes, 0x08262158..0x08262170; the next independent
//! prologue is at 0x08262170. Raw aligned-word decoding finds two inbound
//! plain BLs (0x08262488, 0x08262710), zero predicated BLs. The body has
//! one plain BL to 0x08261d58, zero predicated BLs, and a tail B to
//! 0x082c372c. Normalize clock selectors 0..3 unchanged, all others to -1,
//! then query the clock into the caller's timespec and return its result.
//!
//! Deliberate deviations: inline the pure selector conversion verified from
//! the nine words at 0x08261d58 instead of introducing an unported-call seam;
//! reuse the ported clock_gettime implementation and its host dispatch seams.
//! LLVM need not preserve ADS's save/restore frame or tail-branch encoding.

use super::clock_gettime::{clock_gettime, ClockTimespec};

/// `out` must be null or writable for the selected clock callback.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn wait_clock_gettime(clock_selector: i32, out: *mut ClockTimespec) -> i32 {
    let clock_id = if (clock_selector as u32) < 4 { clock_selector } else { -1 };
    clock_gettime(clock_id, out)
}
