//! Heap-owned object destruction continuation @ 0x08005cf4.
//!
//! The 36-byte wrapper destroys the embedded object at `object + 0x28` via
//! the unported virtual target 0x081b0f0c, adjusts that target's returned
//! subobject pointer back by 0x18, runs the empty base destructor at
//! 0x08005ffc, then hands the base result minus 8 to the stack-sensitive
//! `kernel_indirect_dispatch` veneer (0x08003818).  On ARM the veneer tail
//! target consumes this wrapper's saved frame, so normal control never
//! reaches the apparent final subtraction.  The host seam models Ghidra's
//! inferred normal-return path so the pointer ABI and every adjustment can
//! be tested; it is not used on the device.

/// ABI of the unported embedded-object destructor at 0x081b0f0c.
pub type EmbeddedObjectDestroyFn = unsafe extern "C" fn(*mut u8) -> *mut u8;

/// ABI of the 0x08005ffc base-destructor stub.  Its `bx lr` leaves r0 intact.
pub type EmptyBaseDestroyFn = unsafe extern "C" fn(*mut u8) -> *mut u8;

/// Host representation of 0x08003818's otherwise non-returning tail
/// dispatch.  Its return makes the decompiler's final `-8` observable.
pub type TerminalDispatchFn = unsafe extern "C" fn(*mut u8) -> *mut u8;

/// Host-only boundaries around the two unported helpers and the terminal
/// continuation.  Firmware builds use the literal addresses directly.
#[derive(Clone, Copy)]
pub struct ObjectDestroyDispatchOps {
    pub destroy_embedded: EmbeddedObjectDestroyFn,
    pub destroy_base: EmptyBaseDestroyFn,
    pub terminal_dispatch: TerminalDispatchFn,
}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_embedded_destroy(_object: *mut u8) -> *mut u8 {
    unreachable!("embedded destructor 0x081b0f0c is unavailable on host")
}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_base_destroy(_object: *mut u8) -> *mut u8 {
    unreachable!("base destructor 0x08005ffc is unavailable on host")
}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_terminal_dispatch(_object: *mut u8) -> *mut u8 {
    unreachable!("kernel tail dispatch 0x08003818 is unavailable on host")
}

#[cfg(not(target_arch = "arm"))]
const DEFAULT_OBJECT_DESTROY_DISPATCH_OPS: ObjectDestroyDispatchOps = ObjectDestroyDispatchOps {
    destroy_embedded: missing_embedded_destroy,
    destroy_base: missing_base_destroy,
    terminal_dispatch: missing_terminal_dispatch,
};

/// Active host seam. Target code does not load this table.
#[cfg(not(target_arch = "arm"))]
pub static mut OBJECT_DESTROY_DISPATCH_OPS: ObjectDestroyDispatchOps =
    DEFAULT_OBJECT_DESTROY_DISPATCH_OPS;

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
fn dispatch_ops() -> ObjectDestroyDispatchOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(OBJECT_DESTROY_DISPATCH_OPS)) }
}

/// heap_object_destroy_and_dispatch — original: `FUN_08005cf4` @
/// 0x08005cf4 (36 bytes).
///
/// Destroys the embedded object at `object + 0x28`, rebases its returned
/// pointer by -0x18 for the empty base destructor, then begins the terminal
/// kernel continuation with that result -8.  On ARM this exact continuation
/// does not return to the wrapper; see the module header for the host-only
/// normal-return model.
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn heap_object_destroy_and_dispatch(object: *mut u8) -> *mut u8 {
    let ops = dispatch_ops();
    let embedded_result = (ops.destroy_embedded)(object.add(0x28));
    let base_result = (ops.destroy_base)(embedded_result.sub(0x18));
    let dispatched_result = (ops.terminal_dispatch)(base_result.sub(8));
    dispatched_result.sub(8)
}

// The device body retains the ARM call/return mechanics: 0x081b0f0c is an
// unported in-image virtual destructor, 0x08005ffc is the `bx lr` base stub,
// and `kernel_indirect_dispatch` loads a stack-consuming continuation into
// PC.  In particular, do not turn the last `bl` into a Rust call: it must
// preserve the saved `{r4, lr}` frame for that continuation to pop.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl heap_object_destroy_and_dispatch
    .type heap_object_destroy_and_dispatch, %function
heap_object_destroy_and_dispatch:
    push    {{r4, lr}}
    add     r0, r0, #0x28
    ldr     r12, =0x081b0f0c
    blx     r12
    sub     r0, r0, #0x18
    ldr     r12, =0x08005ffc
    blx     r12
    sub     r0, r0, #8
    bl      kernel_indirect_dispatch
    sub     r0, r0, #8
    pop     {{r4, pc}}
    .size heap_object_destroy_and_dispatch, . - heap_object_destroy_and_dispatch
"#
);

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::hint::spin_loop;
    use core::sync::atomic::{AtomicBool, Ordering};
    use std::vec::Vec;

    static OPS_LOCKED: AtomicBool = AtomicBool::new(false);
    static mut EVENTS: Vec<(u8, usize)> = Vec::new();

    struct OpsLock;

    impl Drop for OpsLock {
        fn drop(&mut self) {
            OPS_LOCKED.store(false, Ordering::Release);
        }
    }

    fn lock_ops() -> OpsLock {
        while OPS_LOCKED
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            spin_loop();
        }
        OpsLock
    }

    unsafe extern "C" fn record_embedded_destroy(object: *mut u8) -> *mut u8 {
        (*core::ptr::addr_of_mut!(EVENTS)).push((1, object as usize));
        object.add(0x18)
    }

    unsafe extern "C" fn record_base_destroy(object: *mut u8) -> *mut u8 {
        (*core::ptr::addr_of_mut!(EVENTS)).push((2, object as usize));
        object.add(8)
    }

    unsafe extern "C" fn record_terminal_dispatch(object: *mut u8) -> *mut u8 {
        (*core::ptr::addr_of_mut!(EVENTS)).push((3, object as usize));
        object.add(0x10)
    }

    struct OpsReset;

    impl Drop for OpsReset {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(OBJECT_DESTROY_DISPATCH_OPS)
                    .write(DEFAULT_OBJECT_DESTROY_DISPATCH_OPS);
            }
        }
    }

    fn install_recorders() -> (OpsLock, OpsReset) {
        let lock = lock_ops();
        unsafe {
            (*core::ptr::addr_of_mut!(EVENTS)).clear();
            core::ptr::addr_of_mut!(OBJECT_DESTROY_DISPATCH_OPS).write(ObjectDestroyDispatchOps {
                destroy_embedded: record_embedded_destroy,
                destroy_base: record_base_destroy,
                terminal_dispatch: record_terminal_dispatch,
            });
        }
        (lock, OpsReset)
    }

    #[test]
    fn destroys_rebased_subobjects_then_returns_the_terminal_result_minus_eight() {
        let (_lock, _reset) = install_recorders();
        let mut storage = [0u8; 0x80];
        let object = storage.as_mut_ptr();

        let result = unsafe { heap_object_destroy_and_dispatch(object) };

        // The mock returns +0x18 from the embedded call, so the following
        // -0x18 exactly recovers `object + 0x28`.  The base mock adds 8;
        // dispatch sees that addition undone, then its +0x10 result receives
        // the decompiler-visible final -8.
        assert_eq!(
            unsafe { (*core::ptr::addr_of!(EVENTS)).clone() },
            std::vec![
                (1, object.wrapping_add(0x28) as usize),
                (2, object.wrapping_add(0x28) as usize),
                (3, object.wrapping_add(0x28) as usize),
            ],
            "the firmware calls every seam in order with its exact rebased pointer"
        );
        assert_eq!(result, object.wrapping_add(0x30));
    }
}
