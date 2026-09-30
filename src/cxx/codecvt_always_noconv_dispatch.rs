//! Codecvt predicate for bypassing byte-stream conversion.
//!
//! Original: `FUN_082a759c`, load address **0x082a759c**, true size
//! **24 bytes**, ending at the separate constant-true method at **0x082a75b4**.
//! Whole-image aligned A32 decoding verifies two inbound plain BLs
//! (`0x083d9410`, `0x083d9618`), zero predicated BLs, and zero outbound BLs.
//! One indirect call uses synthetic LR and `mov pc,r1`.
//!
//! Loads the receiver's vtable word seven (+0x1c), invokes that method with
//! the receiver, and preserves its returned r0. Both byte-stream callers
//! bypass conversion when the result is nonzero. The concrete target remains
//! unresolved; Ghidra's void return and low-bit masking are not in the raw code.
//!
//! Deliberate deviations: a typed Rust call replaces the return trampoline;
//! host vtable cells are pointer-width, target cells remain four bytes. The
//! return is a full u32 rather than Rust bool so no normalization loses bits.
//! No pointer checks or low-bit masking are added (ARM-state method ABI).

/// ABI of the virtual predicate, not a recovered concrete callee.
pub type AlwaysNoConversion = unsafe extern "C" fn(*const u8) -> u32;

/// # Safety
/// The receiver must contain a valid vtable pointer with an ARM-state predicate
/// in word seven, and must satisfy that method's unchecked object contract.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn codecvt_always_noconv_dispatch(receiver: *const u8) -> u32 {
    let vtable = unsafe { receiver.cast::<*const usize>().read() };
    let entry = unsafe { vtable.add(7).read() };
    let predicate: AlwaysNoConversion = unsafe { core::mem::transmute(entry) };
    unsafe { predicate(receiver) }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Exact semantics of e3a00001/e1a0f00e at 0x082a75b4..0x082a75bc.
    // This fixture does not identify the target of every receiver's slot.
    unsafe extern "C" fn constant_true_reference(_receiver: *const u8) -> u32 {
        1
    }

    #[test]
    fn raw_constant_true_method_accepts_minimal_receiver_without_mutation() {
        // Only the selected slot is callable; the receiver has no extra fields.
        let vtable = [0usize, 0, 0, 0, 0, 0, 0,
                      constant_true_reference as *const () as usize];
        let receiver = vtable.as_ptr();
        let before = vtable;
        let result = unsafe {
            codecvt_always_noconv_dispatch((&receiver as *const *const usize).cast())
        };
        assert_eq!(result, 1);
        assert_eq!(receiver, vtable.as_ptr());
        assert_eq!(vtable, before);
    }
}
