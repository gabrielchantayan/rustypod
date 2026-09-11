//! Typed allocation release helper — retailOS `FUN_0803b3a4` at load address
//! `0x0803b3a4` (20 bytes, `0x0803b3a4..0x0803b3b7`). Raw `osos.dec` confirms
//! the extent: the next separately linked function starts at `0x0803b3b8`.
//!
//! ```text
//! 0803b3a4  push {r0,r1,r4,lr}
//! 0803b3a8  mov  r0,sp
//! 0803b3ac  mov  r2,#0
//! 0803b3b0  bl   0x080c85bc
//! 0803b3b4  pop  {r2,r3,r4,pc}
//! ```
//!
//! ## Call sites and algorithm
//!
//! Decoding every ARM B/BL word in `osos.dec` (load base `0x08000000`) finds
//! 27 direct references: 9 unconditional `bl` calls and 18 unconditional `b`
//! tail transfers; there are no predicated references. The helper preserves
//! its `allocation` and opaque `descriptor` arguments as a two-word stack
//! frame, then calls the unported type-erased release engine at `0x080c85bc`
//! with that frame, the descriptor, and a zero third argument. It has no NULL
//! guard; the nine direct callers all invoke it unconditionally.
//!
//! Deliberate deviation: target builds call the fixed retail engine address.
//! Host builds use a volatile replaceable seam because that address is unmapped;
//! tests prove the complete frame and all forwarded arguments.

/// Fixed opaque allocation descriptor loaded into r1 by the wrapper.
pub const TYPED_ALLOCATION_DESCRIPTOR: usize = 0x0890_b608;

/// Target address of the still-unported type-erased release engine.
const RETAIL_TYPE_ERASED_RELEASE_ENGINE: usize = 0x080c_85bc;

/// The two saved argument words passed to the type-erased release engine.
///
/// `repr(C)` retains the retail stack layout: on the 32-bit target,
/// `allocation` is at +0 and `descriptor` at +4.
#[repr(C)]
pub struct AllocationReleaseFrame {
    pub allocation: *mut u8,
    pub descriptor: *const u8,
}

/// ABI of retailOS's still-unported type-erased release engine.
pub type TypeErasedReleaseEngine =
    unsafe extern "C" fn(*mut AllocationReleaseFrame, *const u8, u32);

#[cfg(target_arch = "arm")]
extern "C" {
    /// release_typed_allocation — original: `FUN_08060460` @ `0x08060460`
    /// (12 bytes; 16 direct calls: 6 `bl`, 10 `blne`).
    pub fn release_typed_allocation(allocation: *mut u8);
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn retail_type_erased_release(
    frame: *mut AllocationReleaseFrame,
    descriptor: *const u8,
) {
    let release: TypeErasedReleaseEngine =
        core::mem::transmute(RETAIL_TYPE_ERASED_RELEASE_ENGINE);
    release(frame, descriptor, 0);
}

/// Host boundary for the still-unported type-erased release engine.
///
/// Host tests replace this slot to observe the otherwise unmapped retailOS
/// call. Target builds call `0x080c85bc` directly.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_type_erased_release(
    _frame: *mut AllocationReleaseFrame,
    _descriptor: *const u8,
    _state: u32,
) {}

#[cfg(not(target_os = "none"))]
pub static mut TYPE_ERASED_RELEASE_ENGINE: TypeErasedReleaseEngine =
    missing_type_erased_release;

/// Serializes host tests that replace the shared release-engine seam.
#[cfg(test)]
pub(crate) static TYPE_ERASED_RELEASE_ENGINE_TEST_LOCK: parking_lot::Mutex<()> =
    parking_lot::Mutex::new(());

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn host_type_erased_release(
    frame: *mut AllocationReleaseFrame,
    descriptor: *const u8,
) {
    let release = core::ptr::read_volatile(
        core::ptr::addr_of!(TYPE_ERASED_RELEASE_ENGINE),
    );
    release(frame, descriptor, 0);
}

/// Releases an allocation through an opaque type descriptor.
///
/// `allocation` and `descriptor` are forwarded without validation. The
/// type-erased engine owns all deeper requirements.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn typed_allocation_release_helper(
    allocation: *mut u8,
    descriptor: *const u8,
) {
    let mut frame = AllocationReleaseFrame { allocation, descriptor };
    #[cfg(target_os = "none")]
    retail_type_erased_release(&mut frame, descriptor);
    #[cfg(not(target_os = "none"))]
    host_type_erased_release(&mut frame, descriptor);
}

/// Typed allocation release — retailOS `FUN_08060460` at load address
/// `0x08060460` (12 bytes). This host representation forwards the fixed
/// descriptor through [`typed_allocation_release_helper`] and deliberately
/// preserves NULL; retail callers choose whether to guard with `blne`.
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn release_typed_allocation(allocation: *mut u8) {
    typed_allocation_release_helper(
        allocation,
        TYPED_ALLOCATION_DESCRIPTOR as *const u8,
    );
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

    static CALL_COUNT: AtomicUsize = AtomicUsize::new(0);
    static RECORDED_ALLOCATION: AtomicUsize = AtomicUsize::new(usize::MAX);
    static RECORDED_FRAME_DESCRIPTOR: AtomicUsize = AtomicUsize::new(0);
    static RECORDED_DESCRIPTOR_ARGUMENT: AtomicUsize = AtomicUsize::new(0);
    static RECORDED_STATE: AtomicUsize = AtomicUsize::new(usize::MAX);

    unsafe extern "C" fn record_release(
        frame: *mut AllocationReleaseFrame,
        descriptor: *const u8,
        state: u32,
    ) {
        CALL_COUNT.fetch_add(1, Ordering::SeqCst);
        RECORDED_ALLOCATION.store((*frame).allocation as usize, Ordering::SeqCst);
        RECORDED_FRAME_DESCRIPTOR.store((*frame).descriptor as usize, Ordering::SeqCst);
        RECORDED_DESCRIPTOR_ARGUMENT.store(descriptor as usize, Ordering::SeqCst);
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
        RECORDED_DESCRIPTOR_ARGUMENT.store(0, Ordering::SeqCst);
        RECORDED_STATE.store(usize::MAX, Ordering::SeqCst);
        let previous = unsafe {
            core::ptr::read_volatile(core::ptr::addr_of!(TYPE_ERASED_RELEASE_ENGINE))
        };
        unsafe { TYPE_ERASED_RELEASE_ENGINE = record_release };
        HostSeamReset(previous)
    }

    #[test]
    fn helper_saves_both_arguments_and_clears_engine_state() {
        let _guard = TYPE_ERASED_RELEASE_ENGINE_TEST_LOCK.lock();
        let _reset = install_recorder();
        let allocation = 0x1234_5000usize as *mut u8;
        let descriptor = 0x0890_b608usize as *const u8;

        unsafe { typed_allocation_release_helper(allocation, descriptor) };

        assert_eq!(CALL_COUNT.load(Ordering::SeqCst), 1);
        assert_eq!(RECORDED_ALLOCATION.load(Ordering::SeqCst), allocation as usize);
        assert_eq!(RECORDED_FRAME_DESCRIPTOR.load(Ordering::SeqCst), descriptor as usize);
        assert_eq!(RECORDED_DESCRIPTOR_ARGUMENT.load(Ordering::SeqCst), descriptor as usize);
        assert_eq!(RECORDED_STATE.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn helper_forwards_null_allocation_without_a_guard() {
        let _guard = TYPE_ERASED_RELEASE_ENGINE_TEST_LOCK.lock();
        let _reset = install_recorder();
        let descriptor = 0x0890_63e8usize as *const u8;

        unsafe { typed_allocation_release_helper(core::ptr::null_mut(), descriptor) };

        assert_eq!(CALL_COUNT.load(Ordering::SeqCst), 1);
        assert_eq!(RECORDED_ALLOCATION.load(Ordering::SeqCst), 0);
        assert_eq!(RECORDED_FRAME_DESCRIPTOR.load(Ordering::SeqCst), descriptor as usize);
        assert_eq!(RECORDED_DESCRIPTOR_ARGUMENT.load(Ordering::SeqCst), descriptor as usize);
        assert_eq!(RECORDED_STATE.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn typed_wrapper_reaches_the_helper_with_its_fixed_descriptor() {
        let _guard = TYPE_ERASED_RELEASE_ENGINE_TEST_LOCK.lock();
        let _reset = install_recorder();
        let allocation = 0x2468_a000usize as *mut u8;

        unsafe { release_typed_allocation(allocation) };

        assert_eq!(CALL_COUNT.load(Ordering::SeqCst), 1);
        assert_eq!(RECORDED_ALLOCATION.load(Ordering::SeqCst), allocation as usize);
        assert_eq!(
            RECORDED_DESCRIPTOR_ARGUMENT.load(Ordering::SeqCst),
            TYPED_ALLOCATION_DESCRIPTOR,
        );
    }
}
