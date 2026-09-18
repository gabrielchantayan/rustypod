//! `conditional_callback_dispatch` — original: `FUN_081a2158` @ `0x081a2158`
//! (184 bytes; four unconditional plain `bl` instructions, two predicated
//! `blxne` instructions, and one indirect tail `bx`).
//!
//! # Algorithm
//!
//! Initializes two retailOS global contexts, reads their one-byte selectors,
//! and dispatches vtable slot `+0xa0` on one callback target selected from the
//! controller's `+0x14`, `+0x18`, `+0x1c`, or `+0x20` fields. When both
//! selectors are nonzero, it also invokes that slot on the `+0x18` target and
//! each non-NULL global target at `0x08a09ed8`, `0x08a09edc`, and
//! `0x08a09ee0`, before tail-dispatching the last target.
//!
//! # Deliberate deviations
//!
//! The target build retains the verified ARM body because the four direct
//! callees have no recovered semantic identities. Host builds expose those
//! calls as fixture operations and model the target-only four-byte callback
//! fields structurally with `#[repr(C)]` pointer fields.

/// A callback target whose vtable slot `+0xa0` consumes an event word.
#[repr(C)]
pub struct CallbackTarget {
    pub vtable: *const CallbackTargetVtable,
}

/// Recovered portion of a callback target vtable.
#[repr(C)]
pub struct CallbackTargetVtable {
    /// Slots `+0x00..+0x9c`, not resolved by this wrapper.
    pub unresolved_00_9c: [usize; 40],
    /// Slot `+0xa0`: receives this target and the original event word.
    pub dispatch_event: unsafe extern "C" fn(*mut CallbackTarget, u32),
}

/// Controller fields selected by the two retailOS byte selectors.
#[repr(C)]
pub struct ConditionalCallbackController {
    pub unresolved_00_10: [u32; 5],
    pub primary_when_enabled: *mut CallbackTarget,
    pub active_target: *mut CallbackTarget,
    pub primary_when_disabled: *mut CallbackTarget,
    pub fallback_target: *mut CallbackTarget,
}

/// Host stand-ins for the four direct, still-unidentified retailOS callees.
#[derive(Clone, Copy)]
pub struct ConditionalCallbackDispatchOps {
    pub initialize_first_context: unsafe extern "C" fn(),
    pub first_selector: unsafe extern "C" fn() -> u8,
    pub initialize_second_context: unsafe extern "C" fn(),
    pub second_selector: unsafe extern "C" fn() -> u8,
    pub first_global_target: unsafe extern "C" fn() -> *mut CallbackTarget,
    pub second_global_target: unsafe extern "C" fn() -> *mut CallbackTarget,
    pub final_global_target: unsafe extern "C" fn() -> *mut CallbackTarget,
}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_context() {}
#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_selector() -> u8 { 0 }
#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_target() -> *mut CallbackTarget { core::ptr::null_mut() }

#[cfg(not(target_arch = "arm"))]
pub const DEFAULT_CONDITIONAL_CALLBACK_DISPATCH_OPS: ConditionalCallbackDispatchOps = ConditionalCallbackDispatchOps {
    initialize_first_context: missing_context,
    first_selector: missing_selector,
    initialize_second_context: missing_context,
    second_selector: missing_selector,
    first_global_target: missing_target,
    second_global_target: missing_target,
    final_global_target: missing_target,
};

#[cfg(not(target_arch = "arm"))]
pub static mut CONDITIONAL_CALLBACK_DISPATCH_OPS: ConditionalCallbackDispatchOps = DEFAULT_CONDITIONAL_CALLBACK_DISPATCH_OPS;

#[cfg(not(target_arch = "arm"))]
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn conditional_callback_dispatch(controller: *mut ConditionalCallbackController, event: u32) {
    let ops = core::ptr::read_volatile(core::ptr::addr_of!(CONDITIONAL_CALLBACK_DISPATCH_OPS));
    (ops.initialize_first_context)();
    let target = if (ops.first_selector)() == 1 {
        (ops.initialize_second_context)();
        if (ops.second_selector)() == 0 {
            (*controller).primary_when_enabled
        } else {
            dispatch((*controller).active_target, event);
            dispatch_if_present((ops.first_global_target)(), event);
            dispatch_if_present((ops.second_global_target)(), event);
            let final_target = (ops.final_global_target)();
            if final_target.is_null() { return; }
            final_target
        }
    } else {
        (ops.initialize_second_context)();
        if (ops.second_selector)() == 0 { (*controller).primary_when_disabled } else { (*controller).fallback_target }
    };
    dispatch(target, event);
}

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
unsafe fn dispatch_if_present(target: *mut CallbackTarget, event: u32) {
    if !target.is_null() { dispatch(target, event); }
}

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
unsafe fn dispatch(target: *mut CallbackTarget, event: u32) {
    ((*(*target).vtable).dispatch_event)(target, event);
}

#[cfg(target_arch = "arm")]
core::arch::global_asm!(r#"
    .syntax unified
    .arm
    .p2align 2
    .globl conditional_callback_dispatch
    .type conditional_callback_dispatch, %function
conditional_callback_dispatch:
    push    {{r4, r5, r6, lr}}
    mov     r5, r1
    mov     r4, r0
    bl      0x081eb0c4
    bl      0x081eda10
    cmp     r0, #1
    bne     1f
    bl      0x081f77a4
    bl      0x081fa044
    cmp     r0, #0
    ldreq   r0, [r4, #20]
    beq     2f
    ldr     r0, [r4, #24]
    ldr     r1, [r0]
    ldr     r2, [r1, #160]
    mov     r1, r5
    blx     r2
    ldr     r0, 3f
    ldr     r0, [r0]
    cmp     r0, #0
    ldrne   r1, [r0]
    ldrne   r2, [r1, #160]
    movne   r1, r5
    blxne   r2
    ldr     r0, 4f
    ldr     r0, [r0]
    cmp     r0, #0
    ldrne   r1, [r0]
    ldrne   r2, [r1, #160]
    movne   r1, r5
    blxne   r2
    ldr     r0, 5f
    ldr     r0, [r0]
    cmp     r0, #0
    popeq   {{r4, r5, r6, pc}}
    b       2f
1:
    bl      0x081f77a4
    bl      0x081fa044
    cmp     r0, #0
    ldreq   r0, [r4, #28]
    ldrne   r0, [r4, #32]
2:
    ldr     r1, [r0]
    ldr     r2, [r1, #160]
    mov     r1, r5
    pop     {{r4, r5, r6, lr}}
    bx      r2
3:  .word   0x08a09ed8
4:  .word   0x08a09edc
5:  .word   0x08a09ee0
    .size conditional_callback_dispatch, . - conditional_callback_dispatch
"#);

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::{Mutex, MutexGuard};

    static LOCK: Mutex<()> = Mutex::new(());
    static mut FIRST: u8 = 0;
    static mut SECOND: u8 = 0;
    static mut CALLS: [u32; 8] = [0; 8];
    static mut ORDER: [u8; 8] = [0; 8];
    static mut ORDER_LEN: usize = 0;

    unsafe extern "C" fn initialize_first() { ORDER[ORDER_LEN] = 1; ORDER_LEN += 1; }
    unsafe extern "C" fn first_selector() -> u8 { ORDER[ORDER_LEN] = 2; ORDER_LEN += 1; FIRST }
    unsafe extern "C" fn initialize_second() { ORDER[ORDER_LEN] = 3; ORDER_LEN += 1; }
    unsafe extern "C" fn second_selector() -> u8 { ORDER[ORDER_LEN] = 4; ORDER_LEN += 1; SECOND }
    unsafe extern "C" fn no_target() -> *mut CallbackTarget { core::ptr::null_mut() }
    unsafe extern "C" fn first_global() -> *mut CallbackTarget { addr_of_mut!(TARGETS[4]) }
    unsafe extern "C" fn second_global() -> *mut CallbackTarget { core::ptr::null_mut() }
    unsafe extern "C" fn final_global() -> *mut CallbackTarget { addr_of_mut!(TARGETS[5]) }
    unsafe extern "C" fn record(target: *mut CallbackTarget, event: u32) {
        let index = target.offset_from(addr_of_mut!(TARGETS[0])) as usize;
        CALLS[index] = event;
    }
    static VTABLE: CallbackTargetVtable = CallbackTargetVtable { unresolved_00_9c: [0; 40], dispatch_event: record };
    static mut TARGETS: [CallbackTarget; 6] = [const { CallbackTarget { vtable: &VTABLE } }; 6];

    fn install(first: u8, second: u8, globals: bool) -> MutexGuard<'static, ()> {
        let guard = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            FIRST = first; SECOND = second; CALLS = [0; 8]; ORDER = [0; 8]; ORDER_LEN = 0;
            CONDITIONAL_CALLBACK_DISPATCH_OPS = ConditionalCallbackDispatchOps {
                initialize_first_context: initialize_first, first_selector, initialize_second_context: initialize_second, second_selector,
                first_global_target: if globals { first_global } else { no_target }, second_global_target: no_target,
                final_global_target: if globals { final_global } else { no_target },
            };
        }
        guard
    }
    fn restore(guard: MutexGuard<'static, ()>) { unsafe { CONDITIONAL_CALLBACK_DISPATCH_OPS = DEFAULT_CONDITIONAL_CALLBACK_DISPATCH_OPS; } drop(guard); }
    fn controller() -> ConditionalCallbackController { unsafe { ConditionalCallbackController { unresolved_00_10: [0; 5], primary_when_enabled: addr_of_mut!(TARGETS[0]), active_target: addr_of_mut!(TARGETS[1]), primary_when_disabled: addr_of_mut!(TARGETS[2]), fallback_target: addr_of_mut!(TARGETS[3]) } } }

    #[test]
    fn selects_each_controller_target_from_the_two_selectors() {
        for (first, second, expected) in [(1, 0, 0), (0, 0, 2), (0, 1, 3)] {
            let guard = install(first, second, false);
            let mut controller = controller();
            unsafe { conditional_callback_dispatch(&mut controller, 0x55); assert_eq!(addr_of!(CALLS).read()[expected], 0x55); assert_eq!(addr_of!(ORDER).read()[..4], [1, 2, 3, 4]); }
            restore(guard);
        }
    }
    #[test]
    fn active_path_dispatches_optional_globals_then_final_target() {
        let guard = install(1, 1, true);
        let mut controller = controller();
        unsafe { conditional_callback_dispatch(&mut controller, 0x77); assert_eq!(addr_of!(CALLS).read()[1], 0x77); assert_eq!(addr_of!(CALLS).read()[4], 0x77); assert_eq!(addr_of!(CALLS).read()[5], 0x77); }
        restore(guard);
    }
}
