//! `gateway_signal_object_checked` — original: `FUN_080860c0` @
//! **0x080860c0** (36 bytes).
//!
//! # Extent and calls, binary-verified
//!
//! Raw words at 0x080860c0 are `e92d4010 e5900000 e3500000 03a0001a
//! 08bd8010 ebfec767 e1b00000 13a00027 e8bd8010`; the next independent
//! `push {r4,lr}` starts at 0x080860e4. The body contains one plain `bl` to
//! the 0x08037e78 signal gateway veneer and no predicated calls. Decoding all
//! ARM branch-immediate words in osos.dec finds four inbound plain `bl` calls
//! and no predicated inbound `bl` calls.
//!
//! # Algorithm
//!
//! Loads the object id from `object_slot`. A zero id returns 0x1a without
//! signalling. Otherwise it invokes the RTXC signal gateway; zero status is
//! success and every nonzero status becomes 0x27.
//!
//! # Deliberate deviations
//!
//! The retail body branches to the literal ROM veneer at 0x08037e78. This port
//! calls the existing `gateway_signal_object` port, which preserves the
//! gateway request and its status result. There is deliberately no NULL guard:
//! retail dereferences r0 before testing the loaded id.

use crate::kernel::gateway_signal::gateway_signal_object;

const EMPTY_OBJECT: u32 = 0x1a;
const SIGNAL_FAILED: u32 = 0x27;

#[inline(always)]
unsafe fn gateway_signal_object_checked_with<Signal>(object_slot: *const u32, signal: Signal) -> u32
where
    Signal: FnOnce(u32) -> u32,
{
    let object = object_slot.read();
    if object == 0 {
        EMPTY_OBJECT
    } else if signal(object) == 0 {
        0
    } else {
        SIGNAL_FAILED
    }
}

/// Signals the nonzero object id stored in `object_slot`.
///
/// # Safety
///
/// `object_slot` must point to a readable `u32`; as in retailOS, NULL is not
/// accepted. A nonzero object id must satisfy [`gateway_signal_object`]'s
/// gateway-object contract.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn gateway_signal_object_checked(object_slot: *const u32) -> u32 {
    gateway_signal_object_checked_with(object_slot, |object| gateway_signal_object(object))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_object_is_rejected_without_signalling() {
        let object = 0;
        let status = unsafe {
            gateway_signal_object_checked_with(&object, |_| panic!("zero object must not signal"))
        };
        assert_eq!(status, EMPTY_OBJECT);
    }

    #[test]
    fn nonzero_object_is_signalled_and_status_is_translated() {
        for (object, signal_status, expected) in [
            (1, 0, 0),
            (0xffff_ffff, 0, 0),
            (0x2e, 1, SIGNAL_FAILED),
            (0x8000_0000, 0xffff_ffff, SIGNAL_FAILED),
        ] {
            let mut signalled = 0;
            let status = unsafe {
                gateway_signal_object_checked_with(&object, |id| {
                    signalled = id;
                    signal_status
                })
            };
            assert_eq!(signalled, object);
            assert_eq!(status, expected);
        }
    }
}
