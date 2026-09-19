//! IRAM message-0x23 veneer — `thunk_EXT_FUN_22003da8` @ 0x08038268 (8 bytes).
//!
//! Raw `osos.dec` has `ldr pc, [pc, #-4]` (`0xe51ff004`) followed by the
//! literal `0x22003da8`; the next veneer begins at 0x08038270. The boot
//! relocator mirrors this target from 0x08003da8, whose 32-byte body builds
//! `{ 0x23, r0, r1, r2 }`, dispatches it via 0x08003660 to the unported
//! dispatcher at 0x0802dca8, then returns the dispatcher-updated word two.
//!
//! Every immediate ARM B/BL word in the raw image was decoded: four direct
//! callers, all unconditional `bl`; no predicated BL calls. Deliberate
//! deviation: Rust calls and returns from the dispatcher rather than tail-
//! dispatching through the literal veneer; the shared volatile seam retains
//! the firmware boundary and permits host verification.

use crate::runtime::message_0x17::{MessageDispatchOps, MESSAGE_DISPATCH_OPS};

/// RTXC message command placed first in the stack record.
const MESSAGE_COMMAND: u32 = 0x23;

/// Reads the installable dispatcher seam without letting LLVM fold it away.
#[inline(always)]
unsafe fn message_dispatch_ops() -> MessageDispatchOps {
    core::ptr::read_volatile(core::ptr::addr_of!(MESSAGE_DISPATCH_OPS))
}

/// iram_dispatch_message_0x23_veneer — original:
/// `thunk_EXT_FUN_22003da8` @ 0x08038268 (8-byte veneer), target mirror
/// `FUN_08003da8` @ 0x08003da8 (32 bytes).
///
/// Builds `{ 0x23, arg1, arg2, arg3 }`, dispatches it through the target's
/// 0x08003660 veneer, and returns record word two after dispatch.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn iram_dispatch_message_0x23_veneer(
    arg1: u32,
    arg2: u32,
    arg3: u32,
) -> u32 {
    let mut record = [MESSAGE_COMMAND, arg1, arg2, arg3];
    (message_dispatch_ops().dispatch)(record.as_mut_ptr());
    record[2]
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::MutexGuard;

    static mut CALL_COUNT: usize = 0;
    static mut OBSERVED_RECORD: [u32; 4] = [0; 4];

    struct TestOps {
        _lock: MutexGuard<'static, ()>,
        saved: MessageDispatchOps,
    }

    impl Drop for TestOps {
        fn drop(&mut self) {
            unsafe { MESSAGE_DISPATCH_OPS = self.saved };
        }
    }

    fn install_recording_dispatcher() -> TestOps {
        let lock = crate::testing::MESSAGE_DISPATCH_OPS_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            let saved = core::ptr::read_volatile(core::ptr::addr_of!(MESSAGE_DISPATCH_OPS));
            MESSAGE_DISPATCH_OPS = MessageDispatchOps { dispatch: record_dispatch };
            core::ptr::addr_of_mut!(CALL_COUNT).write(0);
            core::ptr::addr_of_mut!(OBSERVED_RECORD).write([0; 4]);
            TestOps { _lock: lock, saved }
        }
    }

    unsafe extern "C" fn record_dispatch(record: *mut u32) {
        core::ptr::addr_of_mut!(CALL_COUNT).write(core::ptr::addr_of!(CALL_COUNT).read() + 1);
        core::ptr::addr_of_mut!(OBSERVED_RECORD).write(record.cast::<[u32; 4]>().read());
        record.add(2).write(0xa5a5_5a5a);
    }

    #[test]
    fn forwards_message_0x23_and_returns_dispatcher_result() {
        let _ops = install_recording_dispatcher();
        let returned = unsafe {
            iram_dispatch_message_0x23_veneer(0x1111_2222, 0x3333_4444, 0x5555_6666)
        };

        unsafe {
            assert_eq!(CALL_COUNT, 1, "the dispatcher is called exactly once");
            assert_eq!(
                OBSERVED_RECORD,
                [MESSAGE_COMMAND, 0x1111_2222, 0x3333_4444, 0x5555_6666],
                "tag and ABI arguments occupy words zero through three"
            );
        }
        assert_eq!(returned, 0xa5a5_5a5a, "returns the callback-updated third word");
    }
}
