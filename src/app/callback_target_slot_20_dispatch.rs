//! `callback_target_slot_20_dispatch` — original: `FUN_08007bd4` @
//! `0x08007bd4` (32 bytes).
//!
//! # Algorithm
//!
//! This wrapper ignores its first incoming argument, obtains the process-wide
//! callback target through the `0x08003910` veneer (literal target
//! `0x0818c740`), and tail-dispatches vtable slot `+0x20`. It preserves and
//! forwards the second incoming argument as the callback argument. The raw ARM
//! saves that argument in `r4` across the getter, reloads it into `r1`, and
//! branches through the virtual slot rather than returning locally.
//!
//! The callback-target getter enters an unliftable framework setup path at
//! `0x0818c740`. Neighboring wrappers at `0x080076d4`, `0x08007788`, and
//! `0x080077a8` use the same getter with distinct virtual slots. The target
//! build therefore retains the retail literal veneer; host tests install a
//! getter seam.
//!
//! Deliberate host deviation: host pointers are wider than the target's
//! 32-bit vtable words, so the host-only vtable representation places the
//! dispatched slot structurally instead of addressing raw bytes at `+0x20`.

/// Fixed instruction word and literal target in the getter veneer at
/// `0x08003910`.
pub const CALLBACK_TARGET_GETTER_VENEER_INSN: u32 = 0xe51f_f004;
pub const CALLBACK_TARGET_GETTER_TARGET: u32 = 0x0818_c740;

/// Object whose callback entry points are supplied by its first-word vtable.
#[repr(C)]
pub struct CallbackTargetSlot20 {
    pub vtable: *const CallbackTargetSlot20Vtable,
}

/// The part of the callback-target vtable recovered by this wrapper.
#[repr(C)]
pub struct CallbackTargetSlot20Vtable {
    /// Slots `+0x00..+0x1c`, dispatched by neighboring wrappers but not here.
    pub unresolved_00_1c: [usize; 8],
    /// Slot `+0x20`: forwards a callback argument to the framework target.
    pub dispatch_callback: unsafe extern "C" fn(this: *mut CallbackTargetSlot20, callback: *mut u8),
}

/// Getter ABI reached through the retail `0x08003910` veneer.
pub type CallbackTargetSlot20Getter = unsafe extern "C" fn() -> *mut CallbackTargetSlot20;

/// Host/target seam for the unliftable framework callback-target getter.
#[derive(Clone, Copy)]
pub struct CallbackTargetSlot20DispatchOps {
    /// Returns the global vtable-bearing callback target.
    pub get_target: CallbackTargetSlot20Getter,
}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_callback_target() -> *mut CallbackTargetSlot20 {
    core::ptr::null_mut()
}

/// Host default before a test installs the framework target.
#[cfg(not(target_arch = "arm"))]
pub const DEFAULT_CALLBACK_TARGET_SLOT_20_DISPATCH_OPS: CallbackTargetSlot20DispatchOps =
    CallbackTargetSlot20DispatchOps { get_target: missing_callback_target };

/// Host-side target seam. Direct host tests replace this with a fixture getter.
#[cfg(not(target_arch = "arm"))]
pub static mut CALLBACK_TARGET_SLOT_20_DISPATCH_OPS: CallbackTargetSlot20DispatchOps =
    DEFAULT_CALLBACK_TARGET_SLOT_20_DISPATCH_OPS;

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
unsafe fn callback_target() -> *mut CallbackTargetSlot20 {
    core::ptr::read_volatile(core::ptr::addr_of!(
        CALLBACK_TARGET_SLOT_20_DISPATCH_OPS.get_target
    ))()
}

/// callback_target_slot_20_dispatch — original: `FUN_08007bd4` @ `0x08007bd4`
/// (32 bytes).
///
/// Obtains the global callback target and invokes its `+0x20` callback slot,
/// forwarding `callback` unchanged. `unused` is ignored, exactly as the raw
/// ARM wrapper ignores incoming `r0` before calling the getter.
///
/// # Safety
///
/// The target getter must return a non-NULL target whose first word is a
/// readable vtable with a valid `+0x20` callback entry. `callback` follows the
/// unvalidated framework callback ABI.
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn callback_target_slot_20_dispatch(
    _unused: *mut u8,
    callback: *mut u8,
) {
    let target = callback_target();
    let vtable = core::ptr::read_volatile(core::ptr::addr_of!((*target).vtable));
    ((*vtable).dispatch_callback)(target, callback);
}

// Keep the original getter veneer and tail virtual dispatch as one ARM
// assembly fragment. A Rust call here would introduce a local return edge.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl callback_target_slot_20_dispatch
    .type callback_target_slot_20_dispatch, %function
callback_target_slot_20_dispatch:
    push    {{r4, lr}}
    mov     r4, r1
    bl      retail_callback_target_getter_slot_20
    ldr     r1, [r0]
    ldr     r2, [r1, #0x20]
    mov     r1, r4
    pop     {{r4, lr}}
    bx      r2
    .size callback_target_slot_20_dispatch, . - callback_target_slot_20_dispatch

retail_callback_target_getter_slot_20:
    ldr     pc, [pc, #-4]
    .word   0x0818c740
    .size retail_callback_target_getter_slot_20, . - retail_callback_target_getter_slot_20
"#
);

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::{Mutex, MutexGuard};

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut GETTER_CALLS: u32 = 0;
    static mut DISPATCH_CALLS: u32 = 0;
    static mut SEEN_TARGET: *mut CallbackTargetSlot20 = core::ptr::null_mut();
    static mut SEEN_CALLBACK: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn record_dispatch(target: *mut CallbackTargetSlot20, callback: *mut u8) {
        DISPATCH_CALLS += 1;
        SEEN_TARGET = target;
        SEEN_CALLBACK = callback;
    }

    static VTABLE: CallbackTargetSlot20Vtable = CallbackTargetSlot20Vtable {
        unresolved_00_1c: [0; 8],
        dispatch_callback: record_dispatch,
    };
    static mut TARGET: CallbackTargetSlot20 = CallbackTargetSlot20 { vtable: &VTABLE };

    unsafe extern "C" fn record_get_target() -> *mut CallbackTargetSlot20 {
        GETTER_CALLS += 1;
        addr_of_mut!(TARGET)
    }

    fn install_recorder() -> MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            addr_of_mut!(GETTER_CALLS).write(0);
            addr_of_mut!(DISPATCH_CALLS).write(0);
            addr_of_mut!(SEEN_TARGET).write(core::ptr::null_mut());
            addr_of_mut!(SEEN_CALLBACK).write(core::ptr::null_mut());
            addr_of_mut!(TARGET).write(CallbackTargetSlot20 { vtable: &VTABLE });
            addr_of_mut!(CALLBACK_TARGET_SLOT_20_DISPATCH_OPS).write(
                CallbackTargetSlot20DispatchOps {
                    get_target: record_get_target,
                },
            );
        }
        guard
    }

    fn restore_default(guard: MutexGuard<'static, ()>) {
        unsafe {
            addr_of_mut!(CALLBACK_TARGET_SLOT_20_DISPATCH_OPS)
                .write(DEFAULT_CALLBACK_TARGET_SLOT_20_DISPATCH_OPS);
        }
        drop(guard);
    }

    #[test]
    fn gets_the_target_once_and_dispatches_slot_20_with_the_second_argument() {
        let guard = install_recorder();
        let mut ignored = [0x11u8; 4];
        let mut callback = [0x22u8; 4];

        unsafe { callback_target_slot_20_dispatch(ignored.as_mut_ptr(), callback.as_mut_ptr()) };

        unsafe {
            assert_eq!(addr_of!(GETTER_CALLS).read(), 1);
            assert_eq!(addr_of!(DISPATCH_CALLS).read(), 1);
            assert_eq!(addr_of!(SEEN_TARGET).read(), addr_of_mut!(TARGET));
            assert_eq!(addr_of!(SEEN_CALLBACK).read(), callback.as_mut_ptr());
        }
        restore_default(guard);
    }

    #[test]
    fn the_first_argument_is_not_forwarded_to_the_virtual_callback_slot() {
        let guard = install_recorder();
        let mut first = [0xaau8; 4];
        let mut second = [0xbbu8; 4];

        unsafe { callback_target_slot_20_dispatch(first.as_mut_ptr(), second.as_mut_ptr()) };

        unsafe {
            assert_ne!(addr_of!(SEEN_CALLBACK).read(), first.as_mut_ptr());
            assert_eq!(addr_of!(SEEN_CALLBACK).read(), second.as_mut_ptr());
        }
        restore_default(guard);
    }

    #[test]
    fn records_the_fixed_getter_veneer_encoding() {
        assert_eq!(CALLBACK_TARGET_GETTER_VENEER_INSN, 0xe51f_f004);
        assert_eq!(CALLBACK_TARGET_GETTER_TARGET, 0x0818_c740);
        assert_eq!(CALLBACK_TARGET_GETTER_TARGET & 3, 0);
    }
}
