//! `signal_object_8` — original: `FUN_082e4bc8` @ **0x082e4bc8** (8 bytes).
//!
//! # Extent and calls, binary-verified
//!
//! Raw `osos.dec` words are `mov r0,#8` (`0xe3a00008`) and
//! `b 0x08037e78` (`0xeaf54ca9`). The next real function begins at
//! `0x082e4bd0`, so the true extent is 8 bytes, as Ghidra reports. Decoding
//! every ARM B/BL word finds two direct calls, both predicated `blne` at
//! `0x080608f4` and `0x0806804c`; there are no plain `bl` calls.
//!
//! The wrapper fixes the object id to 8 then tail-branches to the literal
//! veneer at `0x08037e78`, whose ROM target is the recovered signal gateway.
//! Rust calls that existing port and returns its status rather than preserving
//! the ARM tail branch; this deliberate ABI-preserving deviation makes the
//! fixed-id wrapper testable on the host.

use crate::kernel::gateway_signal::gateway_signal_object;

/// Signals kernel object 8 and returns the gateway status word.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn signal_object_8() -> u32 {
    unsafe { gateway_signal_object(8) }
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
    fn signals_fixed_object_8_and_forwards_success() {
        let _recorder = install(0);
        assert_eq!(unsafe { signal_object_8() }, 0);
        assert_eq!(unsafe { OBSERVED_OBJECT }, 8);
    }

    #[test]
    fn forwards_gateway_failure_status() {
        let _recorder = install(0x27);
        assert_eq!(unsafe { signal_object_8() }, 0x27);
        assert_eq!(unsafe { OBSERVED_OBJECT }, 8);
    }
}
