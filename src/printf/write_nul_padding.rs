//! `write_nul_padding` — original: `FUN_080f47e4` @ 0x080f47e4 (76 bytes).
//!
//! Raw ARM establishes the exact extent `0x080f47e4..0x080f482f`; the word
//! at `0x080f4830` is the literal pointer `0x08977f9c`, and the next function
//! begins at `0x080f4834`. There are three inbound plain `bl` calls
//! (`0x0807530c`, `0x08075468`, and `0x08075560`) and no predicated direct
//! `bl` calls. The body has one unconditional indirect `blx` through its
//! callback argument.
//!
//! Calls the supplied writer with the first byte at `0x08977f9c` (verified to
//! be NUL) and length one until `count` successful calls have completed.
//! Non-positive signed counts succeed without calling the writer; a zero
//! writer result stops immediately with failure. The host build deliberately
//! uses a local NUL byte instead of dereferencing the firmware data address.

use core::ffi::c_void;

/// Callback ABI used by the retail writer.
pub type WriteBytes = unsafe extern "C" fn(*mut c_void, *const u8, u32) -> u32;

#[cfg(target_os = "none")]
const RETAIL_NUL_BYTE: *const u8 = 0x0897_7f9c as *const u8;

#[cfg(not(target_os = "none"))]
static HOST_NUL_BYTE: u8 = 0;

#[inline(always)]
fn nul_byte() -> *const u8 {
    #[cfg(target_os = "none")]
    { RETAIL_NUL_BYTE }

    #[cfg(not(target_os = "none"))]
    { core::ptr::addr_of!(HOST_NUL_BYTE) }
}

/// Write `count` NUL bytes through `writer`. Port of `FUN_080f47e4` @
/// 0x080f47e4.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn write_nul_padding(
    writer: WriteBytes,
    context: *mut c_void,
    count: i32,
) -> u32 {
    let mut written = 0i32;
    while written < count {
        if unsafe { writer(context, nul_byte(), 1) } == 0 {
            return 0;
        }
        written = written.wrapping_add(1);
    }
    1
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::vec::Vec;

    struct Fixture {
        bytes: Vec<u8>,
        calls: usize,
        fail_at: usize,
    }

    unsafe extern "C" fn record_nul(context: *mut c_void, bytes: *const u8, len: u32) -> u32 {
        let fixture = unsafe { &mut *context.cast::<Fixture>() };
        fixture.calls += 1;
        assert_eq!(len, 1);
        fixture.bytes.push(unsafe { *bytes });
        u32::from(fixture.calls != fixture.fail_at)
    }

    #[test]
    fn non_positive_counts_succeed_without_a_callback() {
        let mut fixture = Fixture { bytes: Vec::new(), calls: 0, fail_at: usize::MAX };

        assert_eq!(unsafe { write_nul_padding(record_nul, (&mut fixture as *mut Fixture).cast(), 0) }, 1);
        assert_eq!(unsafe { write_nul_padding(record_nul, (&mut fixture as *mut Fixture).cast(), -1) }, 1);
        assert_eq!(fixture.calls, 0);
    }

    #[test]
    fn writes_each_requested_nul_byte() {
        let mut fixture = Fixture { bytes: Vec::new(), calls: 0, fail_at: usize::MAX };

        assert_eq!(unsafe { write_nul_padding(record_nul, (&mut fixture as *mut Fixture).cast(), 3) }, 1);
        assert_eq!(fixture.calls, 3);
        assert_eq!(fixture.bytes, [0, 0, 0]);
    }

    #[test]
    fn callback_failure_stops_before_the_next_byte() {
        let mut fixture = Fixture { bytes: Vec::new(), calls: 0, fail_at: 2 };

        assert_eq!(unsafe { write_nul_padding(record_nul, (&mut fixture as *mut Fixture).cast(), 5) }, 0);
        assert_eq!(fixture.calls, 2);
        assert_eq!(fixture.bytes, [0, 0]);
    }
}
