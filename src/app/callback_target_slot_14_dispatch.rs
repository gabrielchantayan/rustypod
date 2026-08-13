//! `callback_target_slot_14_dispatch` — original: `FUN_080077a8` @
//! `0x080077a8` (40 bytes).
//!
//! # Algorithm
//!
//! This wrapper ignores its first incoming argument, obtains the process-wide
//! callback target through the `0x08003910` veneer (literal target
//! `0x0818c740`), and tail-dispatches vtable slot `+0x14`. It preserves the
//! second and third incoming arguments across the getter call, then invokes the
//! slot with `r0=target`, `r1=second_argument`, and `r2=third_argument`.
//!
//! The callback-target getter enters an unliftable framework setup path at
//! `0x0818c740`. Neighboring wrappers at `0x080076d4`, `0x08007788`, and
//! `0x08007bd4` use the same getter with distinct virtual slots. The target
//! build therefore retains the retail literal veneer; host tests install a
//! getter seam.
//!
//! Deliberate host deviation: host pointers are wider than the target's
//! 32-bit vtable words, so the host-only vtable representation places the
//! dispatched slot structurally instead of addressing raw bytes at `+0x14`.

/// Fixed instruction word and literal target in the getter veneer at
/// `0x08003910`.
pub const CALLBACK_TARGET_GETTER_VENEER_INSN: u32 = 0xe51f_f004;
pub const CALLBACK_TARGET_GETTER_TARGET: u32 = 0x0818_c740;

/// Object whose callback entry points are supplied by its first-word vtable.
#[repr(C)]
pub struct CallbackTargetSlot14 {
    pub vtable: *const CallbackTargetSlot14Vtable,
}

/// The part of the callback-target vtable recovered by this wrapper.
#[repr(C)]
pub struct CallbackTargetSlot14Vtable {
    /// Slots `+0x00..+0x10`, dispatched by neighboring wrappers but not here.
    pub unresolved_00_10: [usize; 5],
    /// Slot `+0x14`: forwards two callback arguments to the framework target.
    pub dispatch_callback:
        unsafe extern "C" fn(this: *mut CallbackTargetSlot14, arg2: *mut u8, arg3: *mut u8),
}

/// Getter ABI reached through the retail `0x08003910` veneer.
pub type CallbackTargetSlot14Getter = unsafe extern "C" fn() -> *mut CallbackTargetSlot14;

/// Host/target seam for the unliftable framework callback-target getter.
#[derive(Clone, Copy)]
pub struct CallbackTargetSlot14DispatchOps {
    /// Returns the global vtable-bearing callback target.
    pub get_target: CallbackTargetSlot14Getter,
}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_callback_target() -> *mut CallbackTargetSlot14 {
    core::ptr::null_mut()
}

/// Host default before a test installs the framework target.
#[cfg(not(target_arch = "arm"))]
pub const DEFAULT_CALLBACK_TARGET_SLOT_14_DISPATCH_OPS: CallbackTargetSlot14DispatchOps =
    CallbackTargetSlot14DispatchOps {
        get_target: missing_callback_target,
    };

/// Host-side target seam. Direct host tests replace this with a fixture getter.
#[cfg(not(target_arch = "arm"))]
pub static mut CALLBACK_TARGET_SLOT_14_DISPATCH_OPS: CallbackTargetSlot14DispatchOps =
    DEFAULT_CALLBACK_TARGET_SLOT_14_DISPATCH_OPS;

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
unsafe fn callback_target() -> *mut CallbackTargetSlot14 {
    core::ptr::read_volatile(core::ptr::addr_of!(
        CALLBACK_TARGET_SLOT_14_DISPATCH_OPS.get_target
    ))()
}

/// callback_target_slot_14_dispatch — original: `FUN_080077a8` @ `0x080077a8`
/// (40 bytes).
///
/// Obtains the global callback target and invokes its `+0x14` callback slot,
/// forwarding `arg2` and `arg3` unchanged. `unused` is ignored, exactly as the
/// raw ARM wrapper ignores incoming `r0` before calling the getter.
///
/// # Safety
///
/// The target getter must return a non-NULL target whose first word is a
/// readable vtable with a valid `+0x14` callback entry. `arg2` and `arg3`
/// follow the unvalidated framework callback ABI.
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn callback_target_slot_14_dispatch(
    _unused: *mut u8,
    arg2: *mut u8,
    arg3: *mut u8,
) {
    let target = callback_target();
    let vtable = core::ptr::read_volatile(core::ptr::addr_of!((*target).vtable));
    ((*vtable).dispatch_callback)(target, arg2, arg3);
}

// Keep the original getter veneer and tail virtual dispatch as one ARM
// assembly fragment. A Rust call here would introduce a local return edge.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl callback_target_slot_14_dispatch
    .type callback_target_slot_14_dispatch, %function
callback_target_slot_14_dispatch:
    push    {{r4, r5, r6, lr}}
    mov     r5, r2
    mov     r4, r1
    bl      retail_callback_target_getter_slot_14
    ldr     r1, [r0]
    mov     r2, r5
    ldr     r3, [r1, #0x14]
    mov     r1, r4
    pop     {{r4, r5, r6, lr}}
    bx      r3
    .size callback_target_slot_14_dispatch, . - callback_target_slot_14_dispatch

retail_callback_target_getter_slot_14:
    ldr     pc, [pc, #-4]
    .word   0x0818c740
    .size retail_callback_target_getter_slot_14, . - retail_callback_target_getter_slot_14
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
    static mut SEEN_TARGET: *mut CallbackTargetSlot14 = core::ptr::null_mut();
    static mut SEEN_ARG2: *mut u8 = core::ptr::null_mut();
    static mut SEEN_ARG3: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn record_dispatch(
        target: *mut CallbackTargetSlot14,
        arg2: *mut u8,
        arg3: *mut u8,
    ) {
        DISPATCH_CALLS += 1;
        SEEN_TARGET = target;
        SEEN_ARG2 = arg2;
        SEEN_ARG3 = arg3;
    }

    static VTABLE: CallbackTargetSlot14Vtable = CallbackTargetSlot14Vtable {
        unresolved_00_10: [0; 5],
        dispatch_callback: record_dispatch,
    };
    static mut TARGET: CallbackTargetSlot14 = CallbackTargetSlot14 { vtable: &VTABLE };

    unsafe extern "C" fn record_get_target() -> *mut CallbackTargetSlot14 {
        GETTER_CALLS += 1;
        addr_of_mut!(TARGET)
    }

    fn install_recorder() -> MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            addr_of_mut!(GETTER_CALLS).write(0);
            addr_of_mut!(DISPATCH_CALLS).write(0);
            addr_of_mut!(SEEN_TARGET).write(core::ptr::null_mut());
            addr_of_mut!(SEEN_ARG2).write(core::ptr::null_mut());
            addr_of_mut!(SEEN_ARG3).write(core::ptr::null_mut());
            addr_of_mut!(TARGET).write(CallbackTargetSlot14 { vtable: &VTABLE });
            addr_of_mut!(CALLBACK_TARGET_SLOT_14_DISPATCH_OPS).write(
                CallbackTargetSlot14DispatchOps {
                    get_target: record_get_target,
                },
            );
        }
        guard
    }

    fn restore_default(guard: MutexGuard<'static, ()>) {
        unsafe {
            addr_of_mut!(CALLBACK_TARGET_SLOT_14_DISPATCH_OPS)
                .write(DEFAULT_CALLBACK_TARGET_SLOT_14_DISPATCH_OPS);
        }
        drop(guard);
    }

    #[test]
    fn gets_the_target_once_and_dispatches_slot_14_with_the_last_two_arguments() {
        let guard = install_recorder();
        let mut ignored = [0x11u8; 4];
        let mut arg2 = [0x22u8; 4];
        let mut arg3 = [0x33u8; 4];

        unsafe {
            callback_target_slot_14_dispatch(
                ignored.as_mut_ptr(),
                arg2.as_mut_ptr(),
                arg3.as_mut_ptr(),
            )
        };

        unsafe {
            assert_eq!(addr_of!(GETTER_CALLS).read(), 1);
            assert_eq!(addr_of!(DISPATCH_CALLS).read(), 1);
            assert_eq!(addr_of!(SEEN_TARGET).read(), addr_of_mut!(TARGET));
            assert_eq!(addr_of!(SEEN_ARG2).read(), arg2.as_mut_ptr());
            assert_eq!(addr_of!(SEEN_ARG3).read(), arg3.as_mut_ptr());
        }
        restore_default(guard);
    }

    #[test]
    fn the_first_argument_is_not_forwarded_to_the_virtual_callback_slot() {
        let guard = install_recorder();
        let mut first = [0xaau8; 4];
        let mut second = [0xbbu8; 4];
        let mut third = [0xccu8; 4];

        unsafe {
            callback_target_slot_14_dispatch(
                first.as_mut_ptr(),
                second.as_mut_ptr(),
                third.as_mut_ptr(),
            )
        };

        unsafe {
            assert_ne!(addr_of!(SEEN_ARG2).read(), first.as_mut_ptr());
            assert_ne!(addr_of!(SEEN_ARG3).read(), first.as_mut_ptr());
            assert_eq!(addr_of!(SEEN_ARG2).read(), second.as_mut_ptr());
            assert_eq!(addr_of!(SEEN_ARG3).read(), third.as_mut_ptr());
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
