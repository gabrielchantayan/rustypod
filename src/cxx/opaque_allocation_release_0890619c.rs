//! Opaque allocation release — retailOS `FUN_0803a240` at `0x0803a240`.
//! True extent: 12 bytes (`0x0803a240..0x0803a24c`), including the descriptor
//! literal at +8; the next real function starts at `0x0803a24c` with its own
//! literal load and tail branch. Raw words: e59f1000 ea000456 0890619c.
//! Whole-image ARM decoding finds two plain inbound BLs (0x0805fae8 and
//! 0x080ec2c0), zero predicated BLs, and no outbound BLs.
//!
//! Load opaque descriptor 0x0890619c into r1 and tail-branch to the existing
//! typed allocation release helper at 0x0803b3a4. That helper packages the
//! allocation and descriptor and calls the unresolved type-erased release
//! engine with mode zero. No NULL guard is added; the callers use this for
//! cleanup. The descriptor's concrete type is not established.
//!
//! Deliberate deviation: ARM uses an absolute literal-loaded PC tail transfer
//! instead of a placement-dependent B (16 emitted bytes versus 12 original).
//! Hosts use the existing helper/engine seam.

#[cfg(not(target_arch = "arm"))]
use super::typed_allocation_release::typed_allocation_release_helper;

pub const OPAQUE_ALLOCATION_DESCRIPTOR_0890619C: usize = 0x0890_619c;

#[cfg(target_arch = "arm")]
extern "C" {
    /// Releases through the fixed opaque descriptor without a NULL guard.
    /// The allocation must satisfy the retail release engine's requirements.
    pub fn release_opaque_allocation_0890619c(allocation: *mut u8);
}

/// Releases through the fixed opaque descriptor without a NULL guard.
///
/// # Safety
/// The allocation must satisfy the installed release engine's requirements.
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn release_opaque_allocation_0890619c(allocation: *mut u8) {
    typed_allocation_release_helper(
        allocation,
        OPAQUE_ALLOCATION_DESCRIPTOR_0890619C as *const u8,
    );
}

#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .section .text.release_opaque_allocation_0890619c, "ax", %progbits
    .p2align 2
    .globl release_opaque_allocation_0890619c
    .type release_opaque_allocation_0890619c, %function
release_opaque_allocation_0890619c:
    ldr     r1, [pc]
    ldr     pc, [pc]
    .word   0x0890619c
    .word   0x0803b3a4
    .size release_opaque_allocation_0890619c, . - release_opaque_allocation_0890619c
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
    use std::boxed::Box;

    static DROPS: AtomicUsize = AtomicUsize::new(0);
    static NULL_RELEASES: AtomicUsize = AtomicUsize::new(0);

    struct OwnedValue(u32);
    impl Drop for OwnedValue {
        fn drop(&mut self) {
            assert_eq!(self.0, 0xfedc_ba98);
            DROPS.fetch_add(1, Ordering::SeqCst);
        }
    }

    unsafe extern "C" fn release_owned(
        frame: *mut AllocationReleaseFrame, descriptor: *const u8, mode: u32,
    ) {
        assert_eq!(descriptor as usize, OPAQUE_ALLOCATION_DESCRIPTOR_0890619C);
        assert_eq!((*frame).descriptor, descriptor);
        assert_eq!(mode, 0);
        if (*frame).allocation.is_null() {
            NULL_RELEASES.fetch_add(1, Ordering::SeqCst);
        } else {
            drop(Box::from_raw((*frame).allocation.cast::<OwnedValue>()));
        }
    }

    struct Reset(TypeErasedReleaseEngine);
    impl Drop for Reset {
        fn drop(&mut self) {
            unsafe { TYPE_ERASED_RELEASE_ENGINE = self.0 };
        }
    }

    #[test]
    fn cleanup_releases_owned_value_and_delegates_null() {
        let _guard = TYPE_ERASED_RELEASE_ENGINE_TEST_LOCK.lock();
        let _reset = Reset(unsafe { TYPE_ERASED_RELEASE_ENGINE });
        unsafe { TYPE_ERASED_RELEASE_ENGINE = release_owned };
        DROPS.store(0, Ordering::SeqCst);
        NULL_RELEASES.store(0, Ordering::SeqCst);
        let value = Box::into_raw(Box::new(OwnedValue(0xfedc_ba98)));
        unsafe { release_opaque_allocation_0890619c(value.cast()) };
        assert_eq!(DROPS.load(Ordering::SeqCst), 1);
        unsafe { release_opaque_allocation_0890619c(core::ptr::null_mut()) };
        assert_eq!(NULL_RELEASES.load(Ordering::SeqCst), 1);
        assert_eq!(DROPS.load(Ordering::SeqCst), 1);
    }
}
