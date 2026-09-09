//! Typed allocation release — original: `FUN_08060460` @ load address
//! `0x08060460` (12 bytes: two instructions plus its literal-pool word;
//! Ghidra's 8-byte extent drops the pool). The next independently linked
//! function begins at `0x0806046c`.
//!
//! ```text
//! 08060460  ldr r1, [pc]        @ 0x0890b608
//! 08060464  b   0x0803b3a4
//! 08060468  .word 0x0890b608
//! ```
//!
//! ## Call sites and algorithm
//!
//! Decoding every ARM B/BL word in `osos.dec` (load base `0x08000000`) finds
//! 16 direct calls: 6 unconditional `bl` and 10 `blne`; no direct `b` sites.
//! The predicated callers establish their own non-NULL guards. This wrapper
//! deliberately has none: it loads the fixed allocation descriptor into r1
//! and tail-branches to `0x0803b3a4`, which puts `(allocation, descriptor)` in
//! a temporary two-word frame before calling the unported type-erased release
//! engine at `0x080c85bc` with its third argument zero.
//!
//! The descriptor at `0x0890b608` is opaque: the adjacent allocator wrapper
//! `FUN_080604ac` supplies the same value to `0x0803b468`; no type name is
//! recoverable from the decrypted bytes. The target implementation therefore
//! keeps the raw tail transfer rather than inventing an allocation type.
//!
//! Deliberate deviation: none on ARM; the global assembly is the three raw
//! words above. Hosts cannot call mapped retailOS code, so they invoke a
//! recording-replaceable seam with the exact branch arguments. That seam does
//! not add a NULL guard, which proves the caller-gated `blne` contract.

/// Fixed opaque allocation descriptor loaded into r1 by the wrapper.
pub const TYPED_ALLOCATION_DESCRIPTOR: usize = 0x0890_b608;

/// Stock helper reached by the wrapper's unconditional tail branch.
pub const TYPED_ALLOCATION_RELEASE_HELPER: usize = 0x0803_b3a4;

/// ABI of the branch arguments reaching [`TYPED_ALLOCATION_RELEASE_HELPER`].
pub type TypedAllocationRelease = unsafe extern "C" fn(*mut u8, usize);

#[cfg(target_arch = "arm")]
extern "C" {
    /// release_typed_allocation — original: `FUN_08060460` @ `0x08060460`
    /// (12 bytes; 16 direct calls: 6 `bl`, 10 `blne`).
    pub fn release_typed_allocation(allocation: *mut u8);
}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_typed_allocation_release(_allocation: *mut u8, _descriptor: usize) {}

/// Host boundary for the still-unported type-erased release engine.
///
/// Target builds use the verbatim tail branch below. Host tests replace this
/// slot to observe the otherwise unmapped retailOS call.
#[cfg(not(target_arch = "arm"))]
pub static mut TYPED_ALLOCATION_RELEASE: TypedAllocationRelease = missing_typed_allocation_release;

/// Host representation of the raw tail branch.
///
/// It forwards even NULL unchanged; retail callers choose whether to guard the
/// allocation with `blne` before entering this wrapper.
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn release_typed_allocation(allocation: *mut u8) {
    let release = core::ptr::read_volatile(core::ptr::addr_of!(TYPED_ALLOCATION_RELEASE));
    release(allocation, TYPED_ALLOCATION_DESCRIPTOR);
}

// Preserve the retail tail transfer: a Rust call would create a local return
// edge, whereas the original helper returns directly to this wrapper's caller.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .section .text.release_typed_allocation, "ax", %progbits
    .p2align 2
    .globl release_typed_allocation
    .type release_typed_allocation, %function
release_typed_allocation:
    ldr     r1, [pc]
    b       0x0803b3a4
    .word   0x0890b608
    .size release_typed_allocation, . - release_typed_allocation
"#
);

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static CALL_COUNT: AtomicUsize = AtomicUsize::new(0);
    static RECORDED_ALLOCATION: AtomicUsize = AtomicUsize::new(usize::MAX);
    static RECORDED_DESCRIPTOR: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn record_release(allocation: *mut u8, descriptor: usize) {
        CALL_COUNT.fetch_add(1, Ordering::SeqCst);
        RECORDED_ALLOCATION.store(allocation as usize, Ordering::SeqCst);
        RECORDED_DESCRIPTOR.store(descriptor, Ordering::SeqCst);
    }

    struct HostSeamReset;

    impl Drop for HostSeamReset {
        fn drop(&mut self) {
            unsafe { TYPED_ALLOCATION_RELEASE = missing_typed_allocation_release };
        }
    }

    fn install_recorder() -> HostSeamReset {
        CALL_COUNT.store(0, Ordering::SeqCst);
        RECORDED_ALLOCATION.store(usize::MAX, Ordering::SeqCst);
        RECORDED_DESCRIPTOR.store(0, Ordering::SeqCst);
        unsafe { TYPED_ALLOCATION_RELEASE = record_release };
        HostSeamReset
    }

    #[test]
    fn null_allocation_is_forwarded_without_a_wrapper_guard() {
        let _guard = TEST_LOCK.lock();
        let _reset = install_recorder();

        unsafe { release_typed_allocation(core::ptr::null_mut()) };

        assert_eq!(CALL_COUNT.load(Ordering::SeqCst), 1);
        assert_eq!(RECORDED_ALLOCATION.load(Ordering::SeqCst), 0);
        assert_eq!(RECORDED_DESCRIPTOR.load(Ordering::SeqCst), TYPED_ALLOCATION_DESCRIPTOR);
    }

    #[test]
    fn nonnull_allocation_and_fixed_descriptor_reach_release_helper() {
        let _guard = TEST_LOCK.lock();
        let _reset = install_recorder();
        let allocation = 0x1234_5000usize as *mut u8;

        unsafe { release_typed_allocation(allocation) };

        assert_eq!(CALL_COUNT.load(Ordering::SeqCst), 1);
        assert_eq!(RECORDED_ALLOCATION.load(Ordering::SeqCst), allocation as usize);
        assert_eq!(RECORDED_DESCRIPTOR.load(Ordering::SeqCst), TYPED_ALLOCATION_DESCRIPTOR);
    }
}
