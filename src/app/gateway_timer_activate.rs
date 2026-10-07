//! One-time gateway request followed by fifteen-second timer re-arm.
//!
//! Original: FUN_0814ab18 @ 0x0814ab18, 56 bytes [0x0814ab18, 0x0814ab50).
//! Raw A32 scan: two incoming plain BLs (0x0814aeec, 0x0814af58), zero
//! predicated; body contains two plain BLs, zero predicated. The next real
//! function starts at 0x0814ab50, not at the next PUSH at 0x0814ab6c.
//!
//! If object byte +0x50 is zero, issue gateway_request_blocking(25, 0), then
//! set the byte to one. Always re-arm the embedded +0x54 timer for 15000 ms
//! via timer_rearm_after_15000, and return one. Any nonzero byte suppresses
//! the request and is preserved. No new seams or algorithmic deviations;
//! inherited gateway/timer dispatch behavior is that of the existing ports.

use crate::app::timer_rearm_after_15000::timer_rearm_after_15000;
use crate::kernel::gateway_request_blocking::gateway_request_blocking;

#[inline(always)]
unsafe fn activate_with(
    object: *mut u8,
    request: impl FnOnce(usize, usize),
    rearm: impl FnOnce(*mut u8),
) -> u32 {
    let requested = unsafe { object.add(0x50) };
    if unsafe { requested.read_volatile() } == 0 {
        request(25, 0);
        unsafe { requested.write_volatile(1) };
    }
    rearm(object);
    1
}

/// Object must contain a writable request byte and a valid embedded timer.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn gateway_timer_activate(object: *mut u8) -> u32 {
    unsafe {
        activate_with(object,
            |payload, flag| gateway_request_blocking(payload, flag),
            |object| timer_rearm_after_15000(object))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;

    #[test]
    fn first_request_commits_flag_after_gateway_and_before_rearm() {
        let mut object = [0xa5u8; 0x80];
        object[0x50] = 0;
        let base = object.as_mut_ptr();
        let phase = Cell::new(0);
        unsafe {
            assert_eq!(activate_with(base, |payload, flag| {
                assert_eq!((payload as usize, flag), (25, 0));
                assert_eq!(base.add(0x50).read(), 0);
                // The request may modify the byte; the subsequent store wins.
                base.add(0x50).write(0xff);
                phase.set(1);
            }, |object| {
                assert_eq!(phase.get(), 1);
                assert_eq!(object.add(0x50).read(), 1);
                phase.set(2);
            }), 1);
            assert_eq!(activate_with(base, |_, _| panic!("duplicate request"), |object| {
                assert_eq!(object.add(0x50).read(), 1);
                phase.set(3);
            }), 1);
        }
        assert_eq!(phase.get(), 3);
        assert!(object[..0x50].iter().chain(object[0x51..].iter()).all(|&b| b == 0xa5));
    }

    #[test]
    fn every_nonzero_flag_is_preserved_and_timer_still_rearms() {
        for initial in 1..=255u8 {
            let mut object = [0x5au8; 0x80];
            object[0x50] = initial;
            let base = object.as_mut_ptr();
            unsafe {
                assert_eq!(activate_with(base, |_, _| panic!("already requested"), |object| {
                    assert_eq!(object.add(0x50).read(), initial);
                    object.add(0x54).write(0x99);
                }), 1);
            }
            assert_eq!(object[0x50], initial);
            assert_eq!(object[0x54], 0x99);
            object[0x50] = 0x5a;
            object[0x54] = 0x5a;
            assert_eq!(object, [0x5a; 0x80]);
        }
    }
}
