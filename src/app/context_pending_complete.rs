//! Pending-context completion — `FUN_0814b004` @ `0x0814b004`.
//! True size: 52 bytes, ending at the independent PUSH at `0x0814b038`.
//! Raw A32 decoding: one outgoing plain BL, zero predicated BLs; two
//! incoming plain BLs at `0x0814abfc` and `0x0814b164`, zero predicated.
//!
//! For event 0x52800008, clear current_context (+0x34) only if it matches
//! the supplied context word. Invoke the unported operation at 0x081f065c
//! with that word and event, then clear pending_event (+0x84). Its raw body
//! locks context+0x50, operates on context+0x64 and tail-unlocks +0x50;
//! no broader callee identity is inferred. Deliberate deviations: a fixed
//! address Rust call uses BLX rather than BL; host execution injects that
//! operation. Retain its opaque r0 result (known callers ignore it).

use core::ptr;

type ContextOperation = unsafe extern "C" fn(u32, u32) -> u32;

#[repr(C)]
pub struct PendingContextOwner {
    pub unresolved_prefix: [u32; 13],
    pub current_context: u32,
    pub unresolved_middle: [u32; 19],
    pub pending_event: u32,
}

#[inline(always)]
unsafe fn complete_with_operation(owner: *mut PendingContextOwner, context: u32, event: u32, operation: ContextOperation) -> u32 {
    if event == 0x5280_0008 && ptr::read_volatile(ptr::addr_of!((*owner).current_context)) == context {
        ptr::write_volatile(ptr::addr_of_mut!((*owner).current_context), 0);
    }
    let result = operation(context, event);
    ptr::write_volatile(ptr::addr_of_mut!((*owner).pending_event), 0);
    result
}

/// Completes the pending operation, clearing matching current context first.
///
/// # Safety
/// `owner` must be aligned and writable through +0x84. `context` must satisfy
/// the retail operation at 0x081f065c, including its embedded lock contract.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn context_pending_complete(owner: *mut PendingContextOwner, context: u32, event: u32) -> u32 {
    #[cfg(target_os = "none")]
    { complete_with_operation(owner, context, event, core::mem::transmute(0x081f_065cusize)) }
    #[cfg(not(target_os = "none"))]
    { let _ = (owner, context, event); panic!("context_pending_complete requires retailOS operation on host") }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::cell::Cell;

    std::thread_local! {
        static OWNER: Cell<*mut PendingContextOwner> = const { Cell::new(ptr::null_mut()) };
        static EXPECTED: Cell<(u32, u32, u32)> = const { Cell::new((0, 0, 0)) };
    }

    unsafe extern "C" fn observe(context: u32, event: u32) -> u32 {
        OWNER.with(|slot| {
            let owner = &mut *slot.get();
            EXPECTED.with(|expected| {
                let (expected_context, expected_event, current) = expected.get();
                assert_eq!((context, event), (expected_context, expected_event));
                assert_eq!(owner.current_context, current);
            });
            assert_eq!(owner.pending_event, 0xfeed);
            // Callee changes must survive except for the subsequent pending clear.
            owner.current_context = 0x9876;
            owner.pending_event = 0xbeef;
        });
        0x8765_4321
    }

    #[test]
    fn event_and_identity_control_clear_before_operation() {
        for (current, context, event) in [
            (7, 7, 0x5280_0008), (7, 8, 0x5280_0008),
            (7, 7, 0x5280_0007), (7, 7, 0x5280_0009),
            (0, 0, 0x5280_0008), (u32::MAX, u32::MAX, 0),
        ] {
            let mut owner = PendingContextOwner {
                unresolved_prefix: [0x1234; 13], current_context: current,
                unresolved_middle: [0x5678; 19], pending_event: 0xfeed,
            };
            OWNER.with(|slot| slot.set(&mut owner));
            let expected_current = if event == 0x5280_0008 && current == context { 0 } else { current };
            EXPECTED.with(|slot| slot.set((context, event, expected_current)));
            let result = unsafe { complete_with_operation(&mut owner, context, event, observe) };
            assert_eq!(result, 0x8765_4321);
            assert_eq!(owner.current_context, 0x9876);
            assert_eq!(owner.pending_event, 0);
            assert_eq!(owner.unresolved_prefix, [0x1234; 13]);
            assert_eq!(owner.unresolved_middle, [0x5678; 19]);
            OWNER.with(|slot| slot.set(ptr::null_mut()));
        }
    }
}
