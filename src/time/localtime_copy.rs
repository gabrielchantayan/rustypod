//! Copy RetailOS's static localtime result into a caller-provided `struct tm`.
//!
//! Original: `FUN_08087450` @ 0x08087450, 40 bytes. Ghidra's reported
//! 44-byte extent includes the following, separate four-byte branch veneer at
//! 0x0808747c; the next real entry is therefore 0x0808747c. Raw ARM has two
//! internal plain `bl` instructions (`localtime` @ 0x080312a0 and the IRAM
//! memcpy veneer @ 0x08037df8), no predicated `bl`; whole-image decoding finds
//! three plain inbound `bl` sites (0x08039e9c, 0x0803a4ec, 0x0803a5b8) and no
//! predicated sites.
//!
//! Calls `localtime` for the `time_t` in r0, copies its 36-byte static `Tm`
//! result to r1 when non-null, and returns the original destination; a null
//! localtime result returns null without touching the destination.
//!
//! Deliberate deviation: calls the already-ported IRAM memcpy veneer rather
//! than spelling out its word-copy body, preserving the original call seam.

use crate::libc::iram_veneers::iram_memcpy_veneer;
use crate::time::localtime::{localtime, Tm};

/// Original @ 0x08087450. `dst` must be valid for one [`Tm`] when `time` is
/// valid; the retail function does not validate either pointer.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn localtime_copy(time: *const i32, dst: *mut Tm) -> *mut Tm {
    let tm = localtime(time);
    if tm.is_null() {
        return core::ptr::null_mut();
    }

    iram_memcpy_veneer(dst.cast(), tm.cast_const().cast(), core::mem::size_of::<Tm>());
    dst
}

#[cfg(test)]
mod tests {
    use super::localtime_copy;
    use crate::time::localtime::{localtime, Tm};

    #[test]
    fn copies_epoch_and_returns_destination() {
        let time = 0;
        let mut dst = Tm {
            tm_sec: -1,
            tm_min: -1,
            tm_hour: -1,
            tm_mday: -1,
            tm_mon: -1,
            tm_year: -1,
            tm_wday: -1,
            tm_yday: -1,
            tm_isdst: -1,
        };

        let dst_ptr = &mut dst as *mut Tm;
        unsafe {
            assert_eq!(localtime_copy(&time, dst_ptr), dst_ptr);
            assert_eq!(dst, *localtime(&time));
        }
    }

    #[test]
    fn copies_negative_one_special_case() {
        let time = -1;
        let mut dst = core::mem::MaybeUninit::<Tm>::uninit();

        unsafe {
            assert_eq!(localtime_copy(&time, dst.as_mut_ptr()), dst.as_mut_ptr());
            assert_eq!((*dst.as_ptr()).tm_mday, 1);
            assert_eq!(*dst.as_ptr(), *localtime(&time));
        }
    }
}
