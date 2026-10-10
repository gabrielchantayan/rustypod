//! Tagged allocation release — retailOS `FUN_0806fb54` at load address
//! `0x0806fb54` (32 bytes, `0x0806fb54..0x0806fb73`). The next independently
//! linked function starts at `0x0806fb74`.
//!
//! ```text
//! 0806fb54  ldr   r1,[r0]
//! 0806fb58  cmp   r1,#1
//! 0806fb5c  ldreq r0,[r0,#4]
//! 0806fb60  beq   0x08070c04
//! 0806fb64  cmp   r1,#2
//! 0806fb68  ldreq r0,[r0,#4]
//! 0806fb6c  beq   0x0806f174
//! 0806fb70  bx    lr
//! ```
//!
//! ## Call sites and algorithm
//!
//! Decoding every ARM B/BL word in `osos.dec` (load base `0x08000000`) finds
//! five direct references: five unconditional `bl` calls and no predicated
//! `bl` calls. A two-word tagged allocation record has tag at +0 and allocation
//! at +4. Tag 1 tail-dispatches to `release_opaque_allocation`; tag 2
//! tail-dispatches through `0x0806f174` to the typed allocation helper with
//! descriptor `0x0891f788`; every other tag returns without accessing +4.
//!
//! Deliberate deviation: none on ARM; global assembly preserves all eight raw
//! words and both tail transfers. Host builds use the existing release seams.

#[cfg(not(target_arch = "arm"))]
use super::{
    opaque_allocation_release::release_opaque_allocation,
    typed_allocation_release::typed_allocation_release_helper,
};

/// Descriptor loaded by the `0x0806f174` tag-2 tail wrapper.
pub const TAG_TWO_ALLOCATION_DESCRIPTOR: usize = 0x0891_f788;

/// Fixed-descriptor release — `FUN_0806f174` @ `0x0806f174`, 12 bytes
/// including the literal at `0x0806f17c`; the next function is `0x0806f180`.
/// Raw words: `e59f1000 eaff3089 0891f788`. Independent raw decoding finds
/// two inbound BL calls (one plain BL, one BLEQ) and one BEQ tail transfer.
///
/// Loads descriptor `0x0891f788` and tail-transfers the untouched allocation
/// to `typed_allocation_release_helper` at `0x0803b3a4`. No NULL guard.
/// The descriptor's concrete type is unknown. Deliberate deviations: hosts
/// use the existing helper seam; ARM preserves the exact tail transfer.
///
/// # Safety
/// The allocation must satisfy the retail type-erased release engine's
/// requirements for this descriptor; NULL is forwarded, not rejected.
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn release_tag_two_allocation(allocation: *mut u8) {
    typed_allocation_release_helper(
        allocation,
        TAG_TWO_ALLOCATION_DESCRIPTOR as *const u8,
    );
}

#[cfg(target_arch = "arm")]
extern "C" {
    pub fn release_tag_two_allocation(allocation: *mut u8);
}

#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .section .text.release_tag_two_allocation, "ax", %progbits
    .p2align 2
    .globl release_tag_two_allocation
    .type release_tag_two_allocation, %function
release_tag_two_allocation:
    ldr     r1, [pc]
    b       0x0803b3a4
    .word   0x0891f788
    .size release_tag_two_allocation, . - release_tag_two_allocation
"#
);

/// Releases the allocation selected by a two-word tag record.
///
/// The input must point to at least one readable word. A tag of one or two
/// additionally requires the allocation word at +4; retailOS has no NULL
/// guard.
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn release_tagged_allocation(record: *const u32) {
    match record.read() {
        1 => release_opaque_allocation(record.add(1).read() as *mut u8),
        2 => release_tag_two_allocation(record.add(1).read() as *mut u8),
        _ => {}
    }
}

#[cfg(target_arch = "arm")]
extern "C" {
    pub fn release_tagged_allocation(record: *const u32);
}

#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .section .text.release_tagged_allocation, "ax", %progbits
    .p2align 2
    .globl release_tagged_allocation
    .type release_tagged_allocation, %function
release_tagged_allocation:
    ldr     r1, [r0, #0]
    cmp     r1, #1
    ldreq   r0, [r0, #4]
    beq     0x08070c04
    cmp     r1, #2
    ldreq   r0, [r0, #4]
    beq     release_tag_two_allocation
    bx      lr
    .size release_tagged_allocation, . - release_tagged_allocation
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
    static ALLOCATION: AtomicUsize = AtomicUsize::new(0);
    static DESCRIPTOR: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn record_release(
        frame: *mut AllocationReleaseFrame,
        descriptor: *const u8,
        _state: u32,
    ) {
        CALL_COUNT.fetch_add(1, Ordering::SeqCst);
        ALLOCATION.store((*frame).allocation as usize, Ordering::SeqCst);
        DESCRIPTOR.store(descriptor as usize, Ordering::SeqCst);
    }

    struct ReleaseEngineReset(TypeErasedReleaseEngine);

    impl Drop for ReleaseEngineReset {
        fn drop(&mut self) {
            unsafe { TYPE_ERASED_RELEASE_ENGINE = self.0 };
        }
    }

    fn install_recorder() -> ReleaseEngineReset {
        CALL_COUNT.store(0, Ordering::SeqCst);
        ALLOCATION.store(0, Ordering::SeqCst);
        DESCRIPTOR.store(0, Ordering::SeqCst);
        unsafe {
            let previous = TYPE_ERASED_RELEASE_ENGINE;
            TYPE_ERASED_RELEASE_ENGINE = record_release;
            ReleaseEngineReset(previous)
        }
    }

    #[test]
    fn tag_one_and_two_select_their_exact_release_descriptors() {
        let _lock = TYPE_ERASED_RELEASE_ENGINE_TEST_LOCK.lock();
        let _reset = install_recorder();
        let one = [1, 0x1234_5678];
        unsafe { release_tagged_allocation(one.as_ptr()) };
        assert_eq!(CALL_COUNT.load(Ordering::SeqCst), 1);
        assert_eq!(ALLOCATION.load(Ordering::SeqCst), 0x1234_5678);
        assert_eq!(DESCRIPTOR.load(Ordering::SeqCst), 0x0890_63e8);

        let two = [2, 0x8765_4321];
        unsafe { release_tagged_allocation(two.as_ptr()) };
        assert_eq!(CALL_COUNT.load(Ordering::SeqCst), 2);
        assert_eq!(ALLOCATION.load(Ordering::SeqCst), 0x8765_4321);
        assert_eq!(DESCRIPTOR.load(Ordering::SeqCst), TAG_TWO_ALLOCATION_DESCRIPTOR);
    }

    #[test]
    fn unrecognized_tag_does_not_read_or_release_allocation() {
        let _lock = TYPE_ERASED_RELEASE_ENGINE_TEST_LOCK.lock();
        let _reset = install_recorder();
        let unrecognized = [3];
        unsafe { release_tagged_allocation(unrecognized.as_ptr()) };
        assert_eq!(CALL_COUNT.load(Ordering::SeqCst), 0);
    }

    unsafe extern "C" fn release_owned_byte(
        frame: *mut AllocationReleaseFrame,
        descriptor: *const u8,
        state: u32,
    ) {
        assert_eq!(descriptor as usize, TAG_TWO_ALLOCATION_DESCRIPTOR);
        assert_eq!((*frame).descriptor, descriptor);
        assert_eq!(state, 0);
        if (*frame).allocation.is_null() {
            CALL_COUNT.fetch_add(1, Ordering::SeqCst);
        } else {
            let allocation = std::boxed::Box::from_raw((*frame).allocation);
            ALLOCATION.store(*allocation as usize, Ordering::SeqCst);
            drop(allocation);
        }
    }

    #[test]
    fn fixed_descriptor_release_handles_null_and_owned_allocation() {
        let _lock = TYPE_ERASED_RELEASE_ENGINE_TEST_LOCK.lock();
        let _reset = install_recorder();
        unsafe { TYPE_ERASED_RELEASE_ENGINE = release_owned_byte };
        unsafe { release_tag_two_allocation(core::ptr::null_mut()) };
        assert_eq!(CALL_COUNT.load(Ordering::SeqCst), 1);
        let allocation = std::boxed::Box::into_raw(std::boxed::Box::new(0xa5u8));
        unsafe { release_tag_two_allocation(allocation) };
        assert_eq!(ALLOCATION.load(Ordering::SeqCst), 0xa5);
    }
}
