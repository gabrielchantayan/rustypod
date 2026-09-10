//! Opaque descriptor lookup — original: `FUN_082c5814` @ load address
//! `0x082c5814` (12 bytes: two instructions plus its literal-pool word;
//! Ghidra reports only 8 bytes). The next independently linked function
//! begins at `0x082c5820`.
//!
//! ```text
//! 082c5814  ldr r3, [pc]        @ 0x0890b608
//! 082c5818  b   0x0803a7f0
//! 082c581c  .word 0x0890b608
//! ```
//!
//! ## Call sites and algorithm
//!
//! Decoding every ARM B/BL word in `osos.dec` (load base `0x08000000`) finds
//! 10 direct call sites, all unconditional `bl`; there are no predicated calls
//! or direct `b` transfers. The wrapper preserves r0-r2, loads the fixed
//! opaque descriptor into r3, then tail-branches to the generic lookup helper
//! at `0x0803a7f0`. That helper returns its resolved object pointer, or NULL
//! when its deeper lookup reports no result.
//!
//! The descriptor's concrete identity is not recoverable from the decrypted
//! bytes. It is also used by allocation wrappers, but this port deliberately
//! does not infer that it denotes an allocation type.
//!
//! Deliberate deviation: none on ARM; the global assembly is the three raw
//! words above. Hosts replace the otherwise unmapped lookup helper with a
//! recording seam, proving all three incoming arguments, the fixed descriptor,
//! and the return value are forwarded unchanged.

/// Fixed opaque descriptor loaded into r3 by the wrapper.
pub const OPAQUE_LOOKUP_DESCRIPTOR: usize = 0x0890_b608;

/// Stock helper reached by the wrapper's unconditional tail branch.
pub const OPAQUE_DESCRIPTOR_LOOKUP_HELPER: usize = 0x0803_a7f0;

/// ABI of the branch arguments reaching [`OPAQUE_DESCRIPTOR_LOOKUP_HELPER`].
pub type OpaqueDescriptorLookup = unsafe extern "C" fn(*mut *mut u8, *mut u8, usize, usize) -> *mut u8;

#[cfg(target_arch = "arm")]
extern "C" {
    /// lookup_opaque_descriptor — original: `FUN_082c5814` @ `0x082c5814`
    /// (12 bytes; 10 unconditional `bl` call sites).
    pub fn lookup_opaque_descriptor(output: *mut *mut u8, lookup_context: *mut u8, lookup_key: usize) -> *mut u8;
}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_opaque_descriptor_lookup(
    _output: *mut *mut u8,
    _lookup_context: *mut u8,
    _lookup_key: usize,
    _descriptor: usize,
) -> *mut u8 {
    core::ptr::null_mut()
}

/// Host boundary for the still-unported generic lookup helper.
///
/// Target builds use the verbatim tail branch below. Host tests replace this
/// slot to observe the otherwise unmapped retailOS call.
#[cfg(not(target_arch = "arm"))]
pub static mut OPAQUE_DESCRIPTOR_LOOKUP: OpaqueDescriptorLookup = missing_opaque_descriptor_lookup;

/// Serializes host tests that replace the shared lookup-helper seam.
#[cfg(test)]
pub(crate) static OPAQUE_DESCRIPTOR_LOOKUP_TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

/// Host representation of the raw tail branch.
///
/// It forwards a NULL output pointer unchanged; the retail wrapper has no
/// local guard before entering the generic helper.
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn lookup_opaque_descriptor(
    output: *mut *mut u8,
    lookup_context: *mut u8,
    lookup_key: usize,
) -> *mut u8 {
    let lookup = core::ptr::read_volatile(core::ptr::addr_of!(OPAQUE_DESCRIPTOR_LOOKUP));
    lookup(output, lookup_context, lookup_key, OPAQUE_LOOKUP_DESCRIPTOR)
}

// Preserve the retail tail transfer: a Rust call would create a local return
// edge, whereas the original helper returns directly to this wrapper's caller.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .section .text.lookup_opaque_descriptor, "ax", %progbits
    .p2align 2
    .globl lookup_opaque_descriptor
    .type lookup_opaque_descriptor, %function
lookup_opaque_descriptor:
    ldr     r3, [pc]
    b       0x0803a7f0
    .word   0x0890b608
    .size lookup_opaque_descriptor, . - lookup_opaque_descriptor
"#
);

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};

    static CALL_COUNT: AtomicUsize = AtomicUsize::new(0);
    static RECORDED_OUTPUT: AtomicUsize = AtomicUsize::new(usize::MAX);
    static RECORDED_CONTEXT: AtomicUsize = AtomicUsize::new(usize::MAX);
    static RECORDED_KEY: AtomicUsize = AtomicUsize::new(usize::MAX);
    static RECORDED_DESCRIPTOR: AtomicUsize = AtomicUsize::new(0);
    static RETURN_VALUE: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn record_lookup(
        output: *mut *mut u8,
        lookup_context: *mut u8,
        lookup_key: usize,
        descriptor: usize,
    ) -> *mut u8 {
        CALL_COUNT.fetch_add(1, Ordering::SeqCst);
        RECORDED_OUTPUT.store(output as usize, Ordering::SeqCst);
        RECORDED_CONTEXT.store(lookup_context as usize, Ordering::SeqCst);
        RECORDED_KEY.store(lookup_key, Ordering::SeqCst);
        RECORDED_DESCRIPTOR.store(descriptor, Ordering::SeqCst);
        RETURN_VALUE.load(Ordering::SeqCst) as *mut u8
    }

    struct HostSeamReset;

    impl Drop for HostSeamReset {
        fn drop(&mut self) {
            unsafe { OPAQUE_DESCRIPTOR_LOOKUP = missing_opaque_descriptor_lookup };
        }
    }

    fn install_recorder(return_value: *mut u8) -> HostSeamReset {
        CALL_COUNT.store(0, Ordering::SeqCst);
        RECORDED_OUTPUT.store(usize::MAX, Ordering::SeqCst);
        RECORDED_CONTEXT.store(usize::MAX, Ordering::SeqCst);
        RECORDED_KEY.store(usize::MAX, Ordering::SeqCst);
        RECORDED_DESCRIPTOR.store(0, Ordering::SeqCst);
        RETURN_VALUE.store(return_value as usize, Ordering::SeqCst);
        unsafe { OPAQUE_DESCRIPTOR_LOOKUP = record_lookup };
        HostSeamReset
    }

    #[test]
    fn null_output_pointer_reaches_generic_lookup_unchanged() {
        let _guard = OPAQUE_DESCRIPTOR_LOOKUP_TEST_LOCK.lock();
        let returned = 0x1234_5000usize as *mut u8;
        let _reset = install_recorder(returned);
        let context = 0x2345_6000usize as *mut u8;

        let result = unsafe { lookup_opaque_descriptor(core::ptr::null_mut(), context, usize::MAX) };

        assert_eq!(result, returned);
        assert_eq!(CALL_COUNT.load(Ordering::SeqCst), 1);
        assert_eq!(RECORDED_OUTPUT.load(Ordering::SeqCst), 0);
        assert_eq!(RECORDED_CONTEXT.load(Ordering::SeqCst), context as usize);
        assert_eq!(RECORDED_KEY.load(Ordering::SeqCst), usize::MAX);
        assert_eq!(RECORDED_DESCRIPTOR.load(Ordering::SeqCst), OPAQUE_LOOKUP_DESCRIPTOR);
    }

    #[test]
    fn arguments_descriptor_and_null_result_are_forwarded_unchanged() {
        let _guard = OPAQUE_DESCRIPTOR_LOOKUP_TEST_LOCK.lock();
        let _reset = install_recorder(core::ptr::null_mut());
        let mut output = 0x3456_7000usize as *mut u8;
        let context = 0x4567_8000usize as *mut u8;

        let result = unsafe { lookup_opaque_descriptor(&mut output, context, 0x89ab_cdef) };

        assert!(result.is_null());
        assert_eq!(CALL_COUNT.load(Ordering::SeqCst), 1);
        assert_eq!(RECORDED_OUTPUT.load(Ordering::SeqCst), core::ptr::addr_of_mut!(output) as usize);
        assert_eq!(RECORDED_CONTEXT.load(Ordering::SeqCst), context as usize);
        assert_eq!(RECORDED_KEY.load(Ordering::SeqCst), 0x89ab_cdef);
        assert_eq!(RECORDED_DESCRIPTOR.load(Ordering::SeqCst), OPAQUE_LOOKUP_DESCRIPTOR);
    }
}
