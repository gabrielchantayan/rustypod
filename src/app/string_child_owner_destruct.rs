//! String-and-child owner destructor, `FUN_0818cb08` @ 0x0818cb08.
//!
//! True size: 60 bytes (52 code, 8 literal pool), ending at the next
//! prologue at 0x0818cb44. Two inbound plain BLs (0x0818bc94,
//! 0x0818cafc), zero predicated BLs; two outbound plain BLs, zero
//! predicated BLs, and a tail B to 0x081d63c4. Ghidra's 116-byte body
//! incorrectly includes the base destructor reached by that tail branch.
//! Install 0x08989a40, reset the derived state through 0x0818bf34,
//! install the embedded string vtable 0x089a6044, release its payload,
//! and tail into the base destructor, returning its result.
//!
//! Deliberate deviations: repr(C) pointer fields widen on hosts. The
//! concrete class is unknown; the name describes ownership, not an inferred
//! class identity. The base destructor retains a verified firmware-address
//! seam, with an explicitly installed host operation; reset uses the port.
//! The string release uses the existing port directly. Vtable stores are
//! volatile to preserve the transitions observed by destruction callbacks.

use crate::cxx::string_object::{StringObject, StringObjectVtable, string_object_release_payload};
use super::buffer_pool_owner_destruct::ReleaseObject;

#[repr(C)]
pub struct StringChildOwner {
    pub vtable: u32,
    pub reserved: [u32; 4],
    pub base_first: *mut ReleaseObject,
    pub base_second: *mut ReleaseObject,
    pub string: StringObject,
    pub unknown_24: u32,
    pub state: u32,
    pub flag: u8,
    pub padding: [u8; 3],
    pub derived_first: *mut ReleaseObject,
    pub derived_second: *mut ReleaseObject,
    pub trailing_state: u32,
}

type BaseDestruct = unsafe extern "C" fn(*mut StringChildOwner) -> *mut StringChildOwner;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_base(_: *mut StringChildOwner) -> *mut StringChildOwner {
    panic!("install string-child owner host base destructor (0x081d63c4)")
}
#[cfg(not(target_os = "none"))]
pub static mut STRING_CHILD_OWNER_BASE_DESTRUCT: BaseDestruct = missing_base;

/// Destroy a live owner without freeing its enclosing allocation.
///
/// # Safety
/// `owner` must have valid owned members and virtual dispatch tables.
/// Hosts must install the base-destructor operation.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn string_child_owner_destruct(owner: *mut StringChildOwner) -> *mut StringChildOwner {
    core::ptr::addr_of_mut!((*owner).vtable).write_volatile(0x0898_9a40);
    super::string_child_owner_reset::string_child_owner_reset(owner);
    core::ptr::addr_of_mut!((*owner).string.vtable)
        .write_volatile(0x089a_6044usize as *const StringObjectVtable);
    string_object_release_payload(core::ptr::addr_of_mut!((*owner).string));
    #[cfg(target_os = "none")]
    let base: BaseDestruct = core::mem::transmute(0x081d_63c4usize);
    #[cfg(not(target_os = "none"))]
    let base = core::ptr::addr_of!(STRING_CHILD_OWNER_BASE_DESTRUCT).read();
    base(owner)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Empty assignment may retain storage; teardown releases it afterward.
    unsafe extern "C" fn clear(_: *mut StringObject) {}
    unsafe extern "C" fn base(owner: *mut StringChildOwner) -> *mut StringChildOwner {
        assert_eq!((*owner).string.vtable as usize, 0x089a_6044);
        assert!((*owner).string.payload.is_null(), "release precedes base teardown");
        assert_eq!((*owner).state, 0);
        assert_eq!((*owner).flag, 0);
        assert_eq!((*owner).trailing_state, 0);
        (*owner).vtable = 0x0898_e004;
        owner
    }

    #[test]
    fn null_and_allocated_payloads_release_once_and_preserve_unowned_words() {
        let _heap = crate::heap::veneers::tests::mock_heap();
        unsafe {
            let old_base = STRING_CHILD_OWNER_BASE_DESTRUCT;
            STRING_CHILD_OWNER_BASE_DESTRUCT = base;
            let mut storage = [0u8; 16];
            let vtable = StringObjectVtable { slots: [0, 0, 0, clear as *const () as usize, 0, 0] };
            let mut expected_frees = 0;
            for allocated in [false, true] {
                let payload = if allocated { storage.as_mut_ptr() } else { core::ptr::null_mut() };
                let mut owner = StringChildOwner {
                    vtable: 0, reserved: [0xfeed; 4],
                    base_first: core::ptr::null_mut(), base_second: core::ptr::null_mut(),
                    string: StringObject { vtable: &vtable, payload },
                    unknown_24: 0x1234, state: 7, flag: 1, padding: [0xab; 3],
                    derived_first: core::ptr::null_mut(), derived_second: core::ptr::null_mut(),
                    trailing_state: 9,
                };
                for _ in 0..2 {
                    owner.string.vtable = &vtable;
                    assert_eq!(string_child_owner_destruct(&mut owner), &mut owner as *mut _);
                    assert_eq!(owner.vtable, 0x0898_e004);
                    assert_eq!(owner.reserved, [0xfeed; 4]);
                    assert_eq!(owner.unknown_24, 0x1234);
                    assert_eq!(owner.padding, [0xab; 3]);
                }
                expected_frees += usize::from(allocated);
                let (calls, freed, tag) = crate::heap::veneers::tests::free_log();
                assert_eq!(calls, expected_frees, "no double free on repeated teardown");
                if allocated {
                    assert_eq!(freed, payload);
                    assert_eq!(tag, 0x34);
                }
            }
            STRING_CHILD_OWNER_BASE_DESTRUCT = old_base;
        }
    }
}
