//! `signal_object_51` — original: `FUN_082dafdc` @ **0x082dafdc** (8 bytes).
//!
//! # Extent and calls, binary-verified
//!
//! Raw `osos.dec` words are `mov r0,#0x33` (`0xe3a00033`) and
//! `b 0x08037e78` (`0xeaf573a4`). The next real function begins at
//! `0x082dafe4`, so the true extent is 8 bytes, as Ghidra reports. Decoding
//! every ARM B/BL word finds three direct calls: one plain `bl` at
//! `0x081e63c8` and two predicated `blne` calls at `0x081e6458` and
//! `0x081e647c`; there are no other direct call forms.
//!
//! The wrapper fixes the object id to 51 then tail-branches to the literal
//! veneer at `0x08037e78`, whose ROM target is the recovered signal gateway.
//! Rust calls that existing port and returns its status rather than preserving
//! the ARM tail branch; this deliberate ABI-preserving deviation makes the
//! fixed-id wrapper testable on the host.

use crate::kernel::gateway_signal::gateway_signal_object;

/// Signals kernel object 51 and returns the gateway status word.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn signal_object_51() -> u32 {
    unsafe { gateway_signal_object(51) }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::runtime::message_dispatch_veneer::tests::DISPATCH_OPS_LOCK;
    use crate::runtime::message_dispatch_veneer::{MessageDispatchVeneerOps, MESSAGE_DISPATCH_VENEER_OPS};
    use parking_lot::MutexGuard;

    static mut OBSERVED_OBJECT: u32 = 0;
    static mut STATUS_TO_WRITE: u32 = 0;

    struct Recorder {
        _lock: MutexGuard<'static, ()>,
        saved: MessageDispatchVeneerOps,
    }

    impl Drop for Recorder {
        fn drop(&mut self) {
            unsafe { MESSAGE_DISPATCH_VENEER_OPS = self.saved };
        }
    }

    unsafe extern "C" fn record_dispatch(request: *mut u32) {
        assert_eq!(request.read(), 2);
        assert_eq!(request.add(1).read(), 0);
        OBSERVED_OBJECT = request.add(2).read();
        request.add(1).write(STATUS_TO_WRITE);
    }

    fn install(status: u32) -> Recorder {
        let lock = DISPATCH_OPS_LOCK.lock();
        let saved = unsafe { MESSAGE_DISPATCH_VENEER_OPS };
        unsafe {
            OBSERVED_OBJECT = 0;
            STATUS_TO_WRITE = status;
            MESSAGE_DISPATCH_VENEER_OPS = MessageDispatchVeneerOps { dispatch: record_dispatch };
        }
        Recorder { _lock: lock, saved }
    }

    #[test]
    fn signals_fixed_object_51_and_forwards_success() {
        let _recorder = install(0);
        assert_eq!(unsafe { signal_object_51() }, 0);
        assert_eq!(unsafe { OBSERVED_OBJECT }, 51);
    }

    #[test]
    fn forwards_gateway_failure_status() {
        let _recorder = install(0x27);
        assert_eq!(unsafe { signal_object_51() }, 0x27);
        assert_eq!(unsafe { OBSERVED_OBJECT }, 51);
    }
}
