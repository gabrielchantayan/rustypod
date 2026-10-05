//! `message_handler_dispatch` — `FUN_081e13e8` @ 0x081e13e8.
//! True extent: 96 bytes, [0x081e13e8, 0x081e1448), including the
//! literal 0x089d01e4 at 0x081e1444. Raw word scanning verifies two plain
//! inbound BLs (0x081e1534, 0x081e1584), zero predicated BLs. The body has
//! three plain BLs and one register BLX.
//!
//! Constructs a temporary kind-zero message. If the handler address's low
//! byte is 0xff, calls the kind-zero singleton dispatch at 0x08298850 with
//! the global handle address 0x089d01e4, ignores its result, and returns 1.
//! Otherwise calls the handler's vtable +0x30 with the original message,
//! preserving the entire returned word. Destructs the temporary afterward.
//!
//! Deliberate deviations: native pointer fields allow host fixtures; on ARM
//! the vtable slots remain four bytes apart. The unported singleton dispatch
//! stays a firmware-address boundary, not a guessed Rust implementation.

//! LLVM eliminates the already-ported identity destructor; match.py confirms
//! the constructor, sentinel branch and +0x30 dispatch remain.
use crate::app::message_kind::{message_kind_construct, message_kind_destruct, MessageKind};

type HandleMessage = unsafe extern "C" fn(*mut MessageHandler, *mut MessageKind) -> u32;

#[repr(C)]
pub struct MessageHandler {
    pub vtable: *const HandleMessage,
}

#[cfg(target_os = "none")]
unsafe fn singleton_dispatch() {
    // Raw 0x08298850 preserves its r0 handle pointer, initializes the singleton,
    // then loads [handle] and tail-calls 0x0811a4d0 with the singleton in r1.
    let dispatch: unsafe extern "C" fn(*const u32) -> u32 =
        core::mem::transmute(0x0829_8850usize);
    let _ = dispatch(0x089d_01e4usize as *const u32);
}

#[cfg(not(target_os = "none"))]
unsafe fn singleton_dispatch() {
    panic!("kind-zero singleton dispatch requires retailOS state")
}

unsafe fn dispatch_with<Sentinel>(
    handler: *mut MessageHandler, message: *mut MessageKind, sentinel: Sentinel,
) -> u32
where Sentinel: FnOnce(),
{
    let mut temporary = core::mem::MaybeUninit::<MessageKind>::uninit();
    message_kind_construct(temporary.as_mut_ptr(), 0);
    let result = if handler as usize & 0xff == 0xff {
        sentinel();
        1
    } else {
        let vtable = core::ptr::addr_of!((*handler).vtable).read_volatile();
        let dispatch = vtable.add(12).read_volatile();
        dispatch(handler, message)
    };
    message_kind_destruct(temporary.as_mut_ptr());
    result
}

/// # Safety
/// Unless its low byte is 0xff, `handler` must contain a valid vtable with a
/// callable +0x30 slot. The message and retail singleton state must satisfy
/// their respective dispatch callees' contracts. The owner is unused in ARM.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn message_handler_dispatch(
    _owner: *mut u8, handler: *mut MessageHandler, message: *mut MessageKind,
) -> u32 {
    dispatch_with(handler, message, || singleton_dispatch())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sentinel_checks_only_low_byte_and_never_dereferences_handler() {
        for address in [0xffusize, 0x12ff, 0xffff_ffff] {
            let mut calls = 0;
            let result = unsafe {
                dispatch_with(address as *mut MessageHandler, core::ptr::null_mut(), || calls += 1)
            };
            assert_eq!(result, 1);
            assert_eq!(calls, 1);
        }
    }

    unsafe extern "C" fn wrong_slot(_: *mut MessageHandler, _: *mut MessageKind) -> u32 {
        panic!("wrong vtable slot")
    }

    #[repr(C)]
    struct Fixture {
        handler: MessageHandler,
        expected_message: *mut MessageKind,
        result: u32,
    }

    unsafe extern "C" fn handle(handler: *mut MessageHandler, message: *mut MessageKind) -> u32 {
        let fixture = &mut *handler.cast::<Fixture>();
        assert_eq!(message, fixture.expected_message);
        (*message).kind = (*message).kind.wrapping_add(1);
        fixture.result
    }

    #[test]
    fn invokes_slot_twelve_with_original_message_and_preserves_full_result() {
        let mut slots = [wrong_slot as HandleMessage; 13];
        slots[12] = handle;
        let mut storage = [0u32, 0xffff_ffff];
        let message = storage.as_mut_ptr().cast::<MessageKind>();
        let mut fixture = Fixture {
            handler: MessageHandler { vtable: slots.as_ptr() },
            expected_message: message,
            result: 0,
        };
        for result in [0, 1, 0x8000_0000, 0xffff_ffff] {
            fixture.result = result;
            let before = storage[1];
            assert_eq!(unsafe {
                dispatch_with(&mut fixture.handler, message, || panic!("not a sentinel"))
            }, result);
            assert_eq!(storage[1], before.wrapping_add(1));
            assert_eq!(storage[0], 0);
        }
    }
}
