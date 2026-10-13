//! Opaque allocation release — retailOS FUN_08039a64 at 0x08039a64.
//! True size: 12 bytes, [0x08039a64,0x08039a70), including the +8 literal.
//! Raw words e59f1000 ea00064d 08906180; the successor starts with mov r2,r1,asr #31.
//! Whole-image ARM decoding finds two plain inbound BLs at 0x080ce378 and
//! 0x080ce4b4, zero predicated BLs, zero outbound BLs, and one tail B.
//!
//! Load opaque descriptor 0x08906180 and tail-transfer the unchanged allocation
//! to typed_allocation_release_helper at 0x0803b3a4. Callers release temporary
//! query results after reading their payloads. No NULL guard or concrete
//! descriptor identity is invented. The helper invokes the existing retail
//! type-erased release engine with mode zero.
//!
//! Deliberate deviations: ARM uses placement-independent LDR PC instead of B
//! (16 emitted bytes); hosts use the existing helper/engine seam.

#[cfg(not(target_arch = "arm"))]
use super::typed_allocation_release::typed_allocation_release_helper;

pub const OPAQUE_ALLOCATION_DESCRIPTOR_08906180: usize = 0x0890_6180;

#[cfg(target_arch = "arm")]
extern "C" {
    /// Releases the allocation through its fixed opaque descriptor.
    /// The allocation must satisfy the retail release engine's requirements.
    pub fn release_opaque_allocation_08906180(allocation: *mut u8);
}

/// Releases an allocation, including NULL, through the fixed descriptor.
///
/// # Safety
/// The allocation must satisfy the installed release engine's requirements.
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn release_opaque_allocation_08906180(allocation: *mut u8) {
    typed_allocation_release_helper(
        allocation,
        OPAQUE_ALLOCATION_DESCRIPTOR_08906180 as *const u8,
    );
}

#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .section .text.release_opaque_allocation_08906180, "ax", %progbits
    .p2align 2
    .globl release_opaque_allocation_08906180
    .type release_opaque_allocation_08906180, %function
release_opaque_allocation_08906180:
    ldr     r1, [pc]
    ldr     pc, [pc]
    .word   0x08906180
    .word   0x0803b3a4
    .size release_opaque_allocation_08906180, . - release_opaque_allocation_08906180
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

    struct OwnedValue([u32; 3]);
    impl Drop for OwnedValue {
        fn drop(&mut self) {
            assert_eq!(self.0, [2, 0, 0xfedc_ba98]);
            DROPS.fetch_add(1, Ordering::SeqCst);
        }
    }

    unsafe extern "C" fn release_owned(
        frame: *mut AllocationReleaseFrame, descriptor: *const u8, mode: u32,
    ) {
        assert_eq!(descriptor as usize, OPAQUE_ALLOCATION_DESCRIPTOR_08906180);
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
    fn cleanup_releases_owned_payload_once_and_delegates_null() {
        let _guard = TYPE_ERASED_RELEASE_ENGINE_TEST_LOCK.lock();
        let _reset = Reset(unsafe { TYPE_ERASED_RELEASE_ENGINE });
        unsafe { TYPE_ERASED_RELEASE_ENGINE = release_owned };
        DROPS.store(0, Ordering::SeqCst);
        NULL_RELEASES.store(0, Ordering::SeqCst);
        let value = Box::into_raw(Box::new(OwnedValue([2, 0, 0xfedc_ba98])));
        unsafe { release_opaque_allocation_08906180(value.cast()) };
        assert_eq!(DROPS.load(Ordering::SeqCst), 1);
        unsafe { release_opaque_allocation_08906180(core::ptr::null_mut()) };
        assert_eq!(NULL_RELEASES.load(Ordering::SeqCst), 1);
        assert_eq!(DROPS.load(Ordering::SeqCst), 1);
    }
}
