//! Opaque word/handle record assignment — `FUN_082a7d8c` @ `0x082a7d8c`.
//!
//! Raw A32 extent: 32 bytes through pop {r4,pc} at 0x082a7da8; the next
//! independently entered function begins at 0x082a7dac. Whole-image decoding
//! verifies two inbound plain BLs (0x082a7120, 0x082a7150), one outbound plain
//! BL (0x082a7da0 to opaque_refcounted_assign @ 0x082a8c04), and zero
//! predicated BLs in either direction.
//!
//! Copy the leading word before assigning the following reference-counted
//! handle, then return the original destination. Callers traverse eight-byte
//! records. Deliberate deviation: repr(C) uses native-width host pointers
//! (and their alignment), while the target handle stays at +4. No class
//! identity is inferred; retain/release behavior reuses the existing port.

use super::opaque_refcounted_assign::{opaque_refcounted_assign, OpaqueRefcountedObject};

#[repr(C)]
pub struct OpaqueRefcountedRecord {
    pub word: u32,
    pub handle: *mut OpaqueRefcountedObject,
}

/// # Safety
/// Both records must be readable, and dst writable. Their handle slots must
/// satisfy opaque_refcounted_assign's object and final-release contracts.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn opaque_refcounted_record_assign(
    dst: *mut OpaqueRefcountedRecord,
    src: *const OpaqueRefcountedRecord,
) -> *mut OpaqueRefcountedRecord {
    core::ptr::addr_of_mut!((*dst).word).write(core::ptr::addr_of!((*src).word).read());
    opaque_refcounted_assign(
        core::ptr::addr_of_mut!((*dst).handle),
        core::ptr::addr_of!((*src).handle),
    );
    dst
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object(references: u32) -> OpaqueRefcountedObject {
        OpaqueRefcountedObject { unresolved_00_18: [0xdeadbeef; 7], references }
    }

    #[test]
    fn copies_word_even_when_handles_are_equal_or_null() {
        unsafe {
            let mut shared = object(7);
            let mut dst = OpaqueRefcountedRecord { word: 0, handle: &mut shared };
            let src = OpaqueRefcountedRecord { word: u32::MAX, handle: dst.handle };
            let ptr = &mut dst as *mut _;
            assert_eq!(opaque_refcounted_record_assign(ptr, &src), ptr);
            assert_eq!(dst.word, u32::MAX);
            assert_eq!(dst.handle, src.handle);
            assert_eq!(shared.references, 7);
            opaque_refcounted_record_assign(ptr, ptr);
            assert_eq!(dst.word, u32::MAX);
            assert_eq!(shared.references, 7);
            dst.handle = core::ptr::null_mut();
            let null_src = OpaqueRefcountedRecord { word: 0x12345678, handle: core::ptr::null_mut() };
            opaque_refcounted_record_assign(ptr, &null_src);
            assert_eq!(dst.word, 0x12345678);
            assert!(dst.handle.is_null());
        }
    }

    #[test]
    fn unequal_handles_wrap_counts_and_preserve_source_and_object_prefixes() {
        unsafe {
            let mut old = object(0);
            let mut replacement = object(u32::MAX);
            let mut dst = OpaqueRefcountedRecord { word: u32::MAX, handle: &mut old };
            let src = OpaqueRefcountedRecord { word: 0, handle: &mut replacement };
            let ptr = &mut dst as *mut _;
            assert_eq!(opaque_refcounted_record_assign(ptr, &src), ptr);
            assert_eq!(dst.word, 0);
            assert_eq!(dst.handle, src.handle);
            assert_eq!(old.references, u32::MAX);
            assert_eq!(replacement.references, 0);
            assert_eq!(src.word, 0);
            assert_eq!(src.handle, &mut replacement as *mut _);
            assert_eq!(old.unresolved_00_18, [0xdeadbeef; 7]);
            assert_eq!(replacement.unresolved_00_18, [0xdeadbeef; 7]);
        }
    }
}
