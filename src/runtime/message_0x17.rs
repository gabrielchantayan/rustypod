//! Message-0x17 dispatcher wrapper — `FUN_08003b6c` @ 0x08003b6c (32 bytes).
//!
//! The ARM entry builds a four-word message on its stack: command `0x17`, then
//! r1, r2, and r3.  It passes that record through the literal veneer at
//! 0x08003660, whose target is the unported system dispatcher at 0x0802dca8,
//! then returns the record's third word.  r0 is pushed only to make room for
//! the stack record and is overwritten by the command word.  The dispatcher
//! may therefore update the returned word in place.  The target default calls
//! the ROM dispatcher directly; host tests replace that boundary with a
//! recording callback.

/// Command word placed first in this wrapper's stack message.
const MESSAGE_COMMAND: u32 = 0x17;
/// Target of the literal-dispatch veneer at 0x08003660.
const ROM_MESSAGE_DISPATCH: usize = 0x0802_dca8;

/// ABI of the system's unported message dispatcher.
pub type MessageDispatchFn = unsafe extern "C" fn(record: *mut u32);

/// Runtime integration seam for dispatching stack-built message records.
#[derive(Clone, Copy)]
pub struct MessageDispatchOps {
    pub dispatch: MessageDispatchFn,
}

unsafe extern "C" fn rom_message_dispatch(record: *mut u32) {
    let dispatch: MessageDispatchFn = core::mem::transmute(ROM_MESSAGE_DISPATCH);
    dispatch(record);
}

/// Direct-ROM default; host tests install a recording dispatcher.
pub static mut MESSAGE_DISPATCH_OPS: MessageDispatchOps = MessageDispatchOps {
    dispatch: rom_message_dispatch,
};

/// Volatile slot read preserves the installable target seam in target code.
#[inline(always)]
unsafe fn message_dispatch_ops() -> MessageDispatchOps {
    core::ptr::read_volatile(core::ptr::addr_of!(MESSAGE_DISPATCH_OPS))
}

/// dispatch_message_0x17 — original: `FUN_08003b6c` @ 0x08003b6c (32 bytes).
///
/// Builds the exact four-word stack record `{ 0x17, arg2, arg3, arg4 }`,
/// dispatches it through the 0x08003660 veneer target, and returns word two
/// after dispatch. `unused` is the incoming r0 which the ARM prologue saves
/// but then overwrites with the command tag.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn dispatch_message_0x17(
    _unused: u32,
    arg2: u32,
    arg3: u32,
    arg4: u32,
) -> u32 {
    let mut record = [MESSAGE_COMMAND, arg2, arg3, arg4];
    (message_dispatch_ops().dispatch)(record.as_mut_ptr());
    record[2]
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut CALL_COUNT: usize = 0;
    static mut OBSERVED_RECORD: [u32; 4] = [0; 4];
    static mut OBSERVED_ADDRESS: *mut u32 = core::ptr::null_mut();

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
        let lock = OPS_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            let saved = core::ptr::read_volatile(core::ptr::addr_of!(MESSAGE_DISPATCH_OPS));
            MESSAGE_DISPATCH_OPS = MessageDispatchOps {
                dispatch: record_dispatch,
            };
            core::ptr::addr_of_mut!(CALL_COUNT).write(0);
            core::ptr::addr_of_mut!(OBSERVED_RECORD).write([0; 4]);
            core::ptr::addr_of_mut!(OBSERVED_ADDRESS).write(core::ptr::null_mut());
            TestOps { _lock: lock, saved }
        }
    }

    unsafe extern "C" fn record_dispatch(record: *mut u32) {
        core::ptr::addr_of_mut!(CALL_COUNT).write(core::ptr::addr_of!(CALL_COUNT).read() + 1);
        core::ptr::addr_of_mut!(OBSERVED_ADDRESS).write(record);
        core::ptr::addr_of_mut!(OBSERVED_RECORD).write(record.cast::<[u32; 4]>().read());
        // The caller reloads +8 after returning, so this is also the returned
        // value rather than merely the inbound r2 value.
        record.add(2).write(0xa5a5_5a5a);
    }

    #[test]
    fn forwards_the_four_word_message_in_order_and_returns_post_dispatch_word_two() {
        let _ops = install_recording_dispatcher();

        let returned = unsafe {
            dispatch_message_0x17(0xffff_ffff, 0x1111_2222, 0x3333_4444, 0x5555_6666)
        };

        unsafe {
            assert_eq!(CALL_COUNT, 1, "the dispatcher is called exactly once");
            assert!(!OBSERVED_ADDRESS.is_null(), "the callback receives the stack record");
            assert_eq!(
                OBSERVED_RECORD,
                [MESSAGE_COMMAND, 0x1111_2222, 0x3333_4444, 0x5555_6666],
                "tag and ABI arguments occupy words 0 through 3"
            );
        }
        assert_eq!(returned, 0xa5a5_5a5a, "returns the callback-updated third word");
    }
}
