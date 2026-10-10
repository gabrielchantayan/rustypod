//! `gateway_wake_object_checked` — original: `FUN_080860e4` @
//! **0x080860e4** (36 bytes).
//!
//! Raw words: `e92d4010 e5900000 e3500000 03a0001a 08bd8010 ebfec76a
//! e1b00000 13a00014 e8bd8010`. The next independent prologue starts at
//! 0x08086108. One internal plain BL targets 0x08037ea8; no predicated BLs.
//! Full-image ARM branch decoding finds two inbound plain BLs, at
//! 0x080c9870 and 0x080cdf00, and no predicated inbound BLs.
//!
//! Loads the object id from `object_slot`. Zero returns 0x1a without waking;
//! otherwise invokes the selector-1 wake gateway, returning zero on success
//! and 0x14 for every nonzero gateway status.
//!
//! Deliberate deviation: calls the existing `gateway_wake_object` port rather
//! than the literal veneer to IRAM 0x22004368 (osos mirror 0x08004368).
//! Its request and returned status preserve the contract. No NULL guard:
//! retail dereferences the slot before checking the loaded id.

//!
//! Verification: host suite and ARM release build pass; standalone host
//! smoke exercises empty rejection, success, and high-bit error translation.
//! `match.py` reports a structural diff: LLVM delays the stack frame until
//! after the empty-id return and uses `cmp` instead of `movs`. The ARM call
//! relocation is `R_ARM_CALL gateway_wake_object`; both return constants and
//! status translation match retail. No device execution performed.
use crate::kernel::gateway_wake::gateway_wake_object;

const EMPTY_OBJECT: u32 = 0x1a;
const WAKE_FAILED: u32 = 0x14;

/// Wakes the nonzero object id stored in `object_slot`.
///
/// # Safety
///
/// `object_slot` must point to a readable, aligned `u32`. A nonzero object
/// id must satisfy the gateway-object contract of [`gateway_wake_object`].
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn gateway_wake_object_checked(object_slot: *const u32) -> u32 {
    let object = object_slot.read();
    if object == 0 {
        EMPTY_OBJECT
    } else if gateway_wake_object(object) == 0 {
        0
    } else {
        WAKE_FAILED
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::message_dispatch_veneer::tests::DISPATCH_OPS_LOCK;
    use crate::runtime::message_dispatch_veneer::{
        MessageDispatchVeneerOps, MESSAGE_DISPATCH_VENEER_OPS,
    };

    static mut STATUS: u32 = 0;
    static mut CALLS: u32 = 0;
    static mut EXPECTED_OBJECT: u32 = 0;

    struct Restore(MessageDispatchVeneerOps);

    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe { MESSAGE_DISPATCH_VENEER_OPS = self.0 };
        }
    }

    unsafe extern "C" fn dispatch(request: *mut u32) {
        assert_eq!(request.read(), 1);
        assert_eq!(request.add(1).read(), 0);
        assert_eq!(request.add(2).read(), EXPECTED_OBJECT);
        assert_eq!(request.add(3).read(), 0);
        CALLS += 1;
        request.add(1).write(STATUS);
    }

    #[test]
    fn rejects_empty_ids_and_translates_gateway_status() {
        let _lock = DISPATCH_OPS_LOCK.lock();
        let _restore = Restore(unsafe { MESSAGE_DISPATCH_VENEER_OPS });
        unsafe {
            MESSAGE_DISPATCH_VENEER_OPS = MessageDispatchVeneerOps { dispatch };
            for object in [0, 1, 0x8000_0000, u32::MAX] {
                for status in [0, 1, 0x8000_0000, u32::MAX] {
                    EXPECTED_OBJECT = object;
                    STATUS = status;
                    CALLS = 0;
                    let expected = if object == 0 { EMPTY_OBJECT }
                        else if status == 0 { 0 } else { WAKE_FAILED };
                    assert_eq!(gateway_wake_object_checked(&object), expected);
                    let calls = CALLS;
                    assert_eq!(calls, if object == 0 { 0 } else { 1 });
                    assert_eq!(object, EXPECTED_OBJECT);
                }
            }
        }
    }
}
