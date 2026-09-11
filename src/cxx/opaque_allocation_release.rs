//! Opaque allocation release — original: `FUN_08070c04` @ load address
//! `0x08070c04` (12 bytes: two instructions plus its literal-pool word;
//! Ghidra's 8-byte extent drops the pool). The next independently linked
//! function begins at `0x08070c10`.
//!
//! ```text
//! 08070c04  ldr r1, [pc]        @ 0x089063e8
//! 08070c08  b   0x0803b3a4
//! 08070c0c  .word 0x089063e8
//! ```
//!
//! ## Call sites and algorithm
//!
//! Decoding every ARM B/BL word in `osos.dec` (load base `0x08000000`) finds
//! 12 direct references: 11 calls (6 unconditional `bl`, 2 `bleq`, and 3
//! `blne`) plus one `beq` tail transfer. The five predicated calls establish
//! their own gates. This wrapper deliberately has no NULL guard: it loads the
//! fixed opaque descriptor into r1 and tail-branches to `0x0803b3a4`, which
//! creates a temporary `(allocation, descriptor)` frame and calls the
//! unported type-erased release engine at `0x080c85bc` with r2 zero.
//!
//! The descriptor at `0x089063e8` has no recoverable concrete type. The port
//! preserves the raw tail transfer rather than inventing one. On hosts, it
//! enters the ported helper's recording seam for the still-unported engine,
//! still without adding a NULL guard.
//!
//! Deliberate deviation: none on ARM; the global assembly is the three raw
//! words above.

#[cfg(not(target_arch = "arm"))]
use super::typed_allocation_release::typed_allocation_release_helper;

/// Fixed opaque allocation descriptor loaded into r1 by the wrapper.
pub const OPAQUE_ALLOCATION_DESCRIPTOR: usize = 0x0890_63e8;

#[cfg(target_arch = "arm")]
extern "C" {
    /// release_opaque_allocation — original: `FUN_08070c04` @ `0x08070c04`
    /// (12 bytes; 11 `bl` calls and one `beq` tail transfer).
    pub fn release_opaque_allocation(allocation: *mut u8);
}

/// Host representation of the raw tail branch.
///
/// It forwards NULL unchanged; callers choose whether to gate this release.
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn release_opaque_allocation(allocation: *mut u8) {
    typed_allocation_release_helper(
        allocation,
        OPAQUE_ALLOCATION_DESCRIPTOR as *const u8,
    );
}

// Preserve the retail tail transfer: a Rust call would create a local return
// edge, whereas the original helper returns directly to this wrapper's caller.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .section .text.release_opaque_allocation, "ax", %progbits
    .p2align 2
    .globl release_opaque_allocation
    .type release_opaque_allocation, %function
release_opaque_allocation:
    ldr     r1, [pc]
    b       0x0803b3a4
    .word   0x089063e8
    .size release_opaque_allocation, . - release_opaque_allocation
"#
);

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::cxx::typed_allocation_release::{
        AllocationReleaseFrame, TypeErasedReleaseEngine, TYPE_ERASED_RELEASE_ENGINE,
        TYPE_ERASED_RELEASE_ENGINE_TEST_LOCK,
    };
    use core::sync::atomic::{AtomicUsize, Ordering};

    static CALL_COUNT: AtomicUsize = AtomicUsize::new(0);
    static RECORDED_ALLOCATION: AtomicUsize = AtomicUsize::new(usize::MAX);
    static RECORDED_FRAME_DESCRIPTOR: AtomicUsize = AtomicUsize::new(0);
    static RECORDED_DESCRIPTOR: AtomicUsize = AtomicUsize::new(0);
    static RECORDED_STATE: AtomicUsize = AtomicUsize::new(usize::MAX);

    unsafe extern "C" fn record_release(
        frame: *mut AllocationReleaseFrame,
        descriptor: *const u8,
        state: u32,
    ) {
        CALL_COUNT.fetch_add(1, Ordering::SeqCst);
        RECORDED_ALLOCATION.store((*frame).allocation as usize, Ordering::SeqCst);
        RECORDED_FRAME_DESCRIPTOR.store((*frame).descriptor as usize, Ordering::SeqCst);
        RECORDED_DESCRIPTOR.store(descriptor as usize, Ordering::SeqCst);
        RECORDED_STATE.store(state as usize, Ordering::SeqCst);
    }

    struct HostSeamReset(TypeErasedReleaseEngine);

    impl Drop for HostSeamReset {
        fn drop(&mut self) {
            unsafe { TYPE_ERASED_RELEASE_ENGINE = self.0 };
        }
    }

    fn install_recorder() -> HostSeamReset {
        CALL_COUNT.store(0, Ordering::SeqCst);
        RECORDED_ALLOCATION.store(usize::MAX, Ordering::SeqCst);
        RECORDED_FRAME_DESCRIPTOR.store(0, Ordering::SeqCst);
        RECORDED_DESCRIPTOR.store(0, Ordering::SeqCst);
        RECORDED_STATE.store(usize::MAX, Ordering::SeqCst);
        let previous = unsafe {
            core::ptr::read_volatile(core::ptr::addr_of!(TYPE_ERASED_RELEASE_ENGINE))
        };
        unsafe { TYPE_ERASED_RELEASE_ENGINE = record_release };
        HostSeamReset(previous)
    }

    #[test]
    fn null_allocation_is_forwarded_without_a_wrapper_guard() {
        let _guard = TYPE_ERASED_RELEASE_ENGINE_TEST_LOCK.lock();
        let _reset = install_recorder();

        unsafe { release_opaque_allocation(core::ptr::null_mut()) };

        assert_eq!(CALL_COUNT.load(Ordering::SeqCst), 1);
        assert_eq!(RECORDED_ALLOCATION.load(Ordering::SeqCst), 0);
        assert_eq!(
            RECORDED_FRAME_DESCRIPTOR.load(Ordering::SeqCst),
            OPAQUE_ALLOCATION_DESCRIPTOR,
        );
        assert_eq!(RECORDED_DESCRIPTOR.load(Ordering::SeqCst), OPAQUE_ALLOCATION_DESCRIPTOR);
        assert_eq!(RECORDED_STATE.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn nonnull_allocation_and_fixed_descriptor_reach_release_helper() {
        let _guard = TYPE_ERASED_RELEASE_ENGINE_TEST_LOCK.lock();
        let _reset = install_recorder();
        let allocation = 0x2468_a000usize as *mut u8;

        unsafe { release_opaque_allocation(allocation) };

        assert_eq!(CALL_COUNT.load(Ordering::SeqCst), 1);
        assert_eq!(RECORDED_ALLOCATION.load(Ordering::SeqCst), allocation as usize);
        assert_eq!(
            RECORDED_FRAME_DESCRIPTOR.load(Ordering::SeqCst),
            OPAQUE_ALLOCATION_DESCRIPTOR,
        );
        assert_eq!(RECORDED_DESCRIPTOR.load(Ordering::SeqCst), OPAQUE_ALLOCATION_DESCRIPTOR);
        assert_eq!(RECORDED_STATE.load(Ordering::SeqCst), 0);
    }
}
