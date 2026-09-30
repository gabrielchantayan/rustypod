//! Opaque reference copy assignment — `FUN_082a8c04` @ `0x082a8c04`.
//!
//! Raw A32 extent is 96 bytes, ending at pop {r4,r5,r6,pc} at 0x082a8c60;
//! the separately entered constructor at 0x082a8c64 is the next boundary.
//! Two outbound plain BLs (0x082a8c4c to 0x0826709c, 0x082a8c50 to
//! operator_delete @ 0x082aad24), zero predicated BLs. Whole-image decoding
//! finds two inbound plain BLs (0x082a71a4, 0x082a7da0), zero predicated BLs.
//!
//! Equal pointees are a no-op. Otherwise wrapping-increment the replacement's
//! count at +0x1c before wrapping-decrementing the old object's count. On zero,
//! destroy the non-NULL old object and delete the destructor's returned pointer.
//! Reload the source slot after callbacks, store it into destination, return dst.
//!
//! Deliberate deviations: no inferred class identity. The unported destructor
//! at 0x0826709c is an address-backed boundary, replaceable on host. Native-width
//! host slots hold pointers; the object prefix remains eight 32-bit words.

use crate::heap::veneers::operator_delete;

#[repr(C)]
pub struct OpaqueRefcountedObject {
    pub unresolved_00_18: [u32; 7],
    pub references: u32,
}

pub type OpaqueRefcountedDestruct = unsafe extern "C" fn(*mut OpaqueRefcountedObject) -> *mut u8;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_destruct(object: *mut OpaqueRefcountedObject) -> *mut u8 {
    let destruct: OpaqueRefcountedDestruct = core::mem::transmute(0x0826_709cusize);
    destruct(object)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_destruct(_: *mut OpaqueRefcountedObject) -> *mut u8 {
    panic!("opaque_refcounted_assign requires unresolved FUN_0826709c")
}

#[cfg(not(target_os = "none"))]
pub static mut OPAQUE_REFCOUNTED_DESTRUCT: OpaqueRefcountedDestruct = missing_destruct;
#[cfg(not(target_os = "none"))]
pub static mut OPAQUE_REFCOUNTED_DELETE: unsafe extern "C" fn(*mut u8) = operator_delete;

/// # Safety
/// Both slots must be readable, and dst writable. Unequal pointees must both
/// address writable objects (there is no early NULL guard). A final-release
/// object must satisfy the retail destructor and delete contracts. Callbacks
/// must leave src readable and dst writable.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn opaque_refcounted_assign(
    dst: *mut *mut OpaqueRefcountedObject,
    src: *const *mut OpaqueRefcountedObject,
) -> *mut *mut OpaqueRefcountedObject {
    let replacement = src.read();
    if dst.read() != replacement {
        (*replacement).references = (*replacement).references.wrapping_add(1);
        let old = dst.read();
        (*old).references = (*old).references.wrapping_sub(1);
        if (*old).references == 0 {
            let old = dst.read();
            if !old.is_null() {
                #[cfg(target_os = "none")]
                { operator_delete(firmware_destruct(old)); }
                #[cfg(not(target_os = "none"))]
                {
                    let destruct = core::ptr::addr_of!(OPAQUE_REFCOUNTED_DESTRUCT).read_volatile();
                    let allocation = destruct(old);
                    let delete = core::ptr::addr_of!(OPAQUE_REFCOUNTED_DELETE).read_volatile();
                    delete(allocation);
                }
            }
        }
        dst.write(src.read());
    }
    dst
}

#[cfg(test)]
mod tests {
    use super::*;
    static LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    static mut SOURCE: *mut *mut OpaqueRefcountedObject = core::ptr::null_mut();
    static mut NEXT: *mut OpaqueRefcountedObject = core::ptr::null_mut();
    static mut RETAINED: *mut OpaqueRefcountedObject = core::ptr::null_mut();
    static mut DELETED: *mut u8 = core::ptr::null_mut();
    static mut STAGE: u32 = 0;

    unsafe extern "C" fn destruct(old: *mut OpaqueRefcountedObject) -> *mut u8 {
        assert_eq!((*old).references, 0);
        assert_eq!((*RETAINED).references, 8);
        assert_eq!(STAGE, 0);
        STAGE = 1;
        SOURCE.write(NEXT);
        // Deliberately return a different allocation; r0 flows directly to delete.
        old.cast::<u8>().add(4)
    }
    unsafe extern "C" fn delete(allocation: *mut u8) {
        assert_eq!(STAGE, 1);
        STAGE = 2;
        DELETED = allocation;
    }
    fn object(count: u32) -> OpaqueRefcountedObject {
        OpaqueRefcountedObject { unresolved_00_18: [0xfeedbeef; 7], references: count }
    }

    #[test]
    fn assignment_alias_wrap_and_final_release() {
        let _lock = LOCK.lock();
        unsafe {
            let mut old = object(5);
            let mut replacement = object(u32::MAX);
            let mut dst = &mut old as *mut _;
            let src = &mut replacement as *mut _;
            let dst_slot = &mut dst as *mut _;
            assert_eq!(opaque_refcounted_assign(dst_slot, &src), dst_slot);
            assert_eq!(dst, src);
            assert_eq!(old.references, 4);
            assert_eq!(replacement.references, 0);
            opaque_refcounted_assign(dst_slot, dst_slot);
            assert_eq!(replacement.references, 0);
            let alias = dst;
            opaque_refcounted_assign(dst_slot, &alias);
            assert_eq!(replacement.references, 0);
            let mut null = core::ptr::null_mut();
            let null_src = null;
            opaque_refcounted_assign(&mut null, &null_src);
            assert!(null.is_null());
            old.references = 0;
            replacement.references = 2;
            dst = &mut old;
            opaque_refcounted_assign(&mut dst, &src);
            assert_eq!(old.references, u32::MAX);
            assert_eq!(replacement.references, 3);

            let saved_destruct = OPAQUE_REFCOUNTED_DESTRUCT;
            let saved_delete = OPAQUE_REFCOUNTED_DELETE;
            OPAQUE_REFCOUNTED_DESTRUCT = destruct;
            OPAQUE_REFCOUNTED_DELETE = delete;
            old.references = 1;
            replacement.references = 7;
            let mut next = object(99);
            let mut mutable_src = &mut replacement as *mut _;
            SOURCE = &mut mutable_src;
            NEXT = &mut next;
            RETAINED = &mut replacement;
            STAGE = 0;
            dst = &mut old;
            opaque_refcounted_assign(&mut dst, SOURCE);
            assert_eq!(dst, &mut next as *mut _);
            assert_eq!(next.references, 99);
            assert_eq!(DELETED, (&mut old as *mut OpaqueRefcountedObject).cast::<u8>().add(4));
            assert_eq!(STAGE, 2);
            assert_eq!(old.unresolved_00_18, [0xfeedbeef; 7]);
            assert_eq!(replacement.unresolved_00_18, [0xfeedbeef; 7]);
            OPAQUE_REFCOUNTED_DESTRUCT = saved_destruct;
            OPAQUE_REFCOUNTED_DELETE = saved_delete;
        }
    }
}
