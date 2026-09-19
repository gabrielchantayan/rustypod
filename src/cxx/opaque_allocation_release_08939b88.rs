//! Fixed-descriptor allocation release — retailOS `FUN_08051080` at load
//! address `0x08051080` (12 bytes: two instructions plus the literal-pool
//! word; Ghidra's 8-byte extent drops the pool). The next independently
//! linked function starts at `0x0805108c`.
//!
//! ```text
//! 08051080  ldr r1, [pc]        @ 0x08939b88
//! 08051084  b   0x0803b3a4
//! 08051088  .word 0x08939b88
//! ```
//!
//! ## Call sites and algorithm
//!
//! Decoding every ARM B/BL word in `osos.dec` (load base `0x08000000`) finds
//! four direct calls: four unconditional `bl` and no predicated `bl`. This
//! wrapper deliberately has no NULL guard: it loads its fixed descriptor into
//! r1 and tail-branches to `0x0803b3a4`, which creates a temporary
//! `(allocation, descriptor)` frame and calls the unported type-erased release
//! engine at `0x080c85bc` with r2 zero.
//!
//! The descriptor at `0x08939b88` has no recoverable concrete type. The port
//! preserves the raw tail transfer rather than inventing one. On hosts, it
//! enters the ported helper's recording seam for the still-unported engine,
//! still without adding a NULL guard.
//!
//! Deliberate deviation: none on ARM; the global assembly is the three raw
//! words above.

#[cfg(not(target_arch = "arm"))]
use super::typed_allocation_release::typed_allocation_release_helper;

/// Fixed opaque allocation descriptor loaded into r1 by the wrapper.
pub const OPAQUE_ALLOCATION_DESCRIPTOR_08939B88: usize = 0x0893_9b88;

#[cfg(target_arch = "arm")]
extern "C" {
    /// release_opaque_allocation_08939b88 — original: `FUN_08051080` @
    /// `0x08051080` (12 bytes; four unconditional `bl` calls).
    pub fn release_opaque_allocation_08939b88(allocation: *mut u8);
}

/// Host representation of the raw tail branch.
///
/// It forwards NULL unchanged; callers choose whether to gate this release.
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn release_opaque_allocation_08939b88(allocation: *mut u8) {
    typed_allocation_release_helper(
        allocation,
        OPAQUE_ALLOCATION_DESCRIPTOR_08939B88 as *const u8,
    );
}

// Preserve the retail tail transfer: a Rust call would create a local return
// edge, whereas the original helper returns directly to this wrapper's caller.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .section .text.release_opaque_allocation_08939b88, "ax", %progbits
    .p2align 2
    .globl release_opaque_allocation_08939b88
    .type release_opaque_allocation_08939b88, %function
release_opaque_allocation_08939b88:
    ldr     r1, [pc]
    b       0x0803b3a4
    .word   0x08939b88
    .size release_opaque_allocation_08939b88, . - release_opaque_allocation_08939b88
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

        unsafe { release_opaque_allocation_08939b88(core::ptr::null_mut()) };

        assert_eq!(CALL_COUNT.load(Ordering::SeqCst), 1);
        assert_eq!(RECORDED_ALLOCATION.load(Ordering::SeqCst), 0);
        assert_eq!(
            RECORDED_FRAME_DESCRIPTOR.load(Ordering::SeqCst),
            OPAQUE_ALLOCATION_DESCRIPTOR_08939B88,
        );
        assert_eq!(
            RECORDED_DESCRIPTOR.load(Ordering::SeqCst),
            OPAQUE_ALLOCATION_DESCRIPTOR_08939B88,
        );
        assert_eq!(RECORDED_STATE.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn nonnull_allocation_and_fixed_descriptor_reach_release_helper() {
        let _guard = TYPE_ERASED_RELEASE_ENGINE_TEST_LOCK.lock();
        let _reset = install_recorder();
        let allocation = 0x2468_a000usize as *mut u8;

        unsafe { release_opaque_allocation_08939b88(allocation) };

        assert_eq!(CALL_COUNT.load(Ordering::SeqCst), 1);
        assert_eq!(RECORDED_ALLOCATION.load(Ordering::SeqCst), allocation as usize);
        assert_eq!(
            RECORDED_FRAME_DESCRIPTOR.load(Ordering::SeqCst),
            OPAQUE_ALLOCATION_DESCRIPTOR_08939B88,
        );
        assert_eq!(
            RECORDED_DESCRIPTOR.load(Ordering::SeqCst),
            OPAQUE_ALLOCATION_DESCRIPTOR_08939B88,
        );
        assert_eq!(RECORDED_STATE.load(Ordering::SeqCst), 0);
    }
}
