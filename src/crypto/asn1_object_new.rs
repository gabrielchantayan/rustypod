//! ASN1_OBJECT_new @ 0x0803a1dc, 96 bytes through 0x0803a23c.
//! Raw ARM words verify two plain outbound BLs and no predicated BLs;
//! the next entry is an independent branch veneer. Allocate a 24-byte
//! ASN1_OBJECT with zero tags, report (13, 0x7b, 0x41, 0, 0) on failure,
//! otherwise clear length, data, nid, sn and ln, then set dynamic flag 1.
//! No target behavioral deviations. Host allocation uses the native repr(C)
//! size because its pointer fields are wider; target allocation remains 24.
//! Existing allocator and diagnostic seams are reused without modification.

use crate::crypto::obj_dat::Asn1Object;
use crate::drivers::ata_cmd::traced_alloc;
use crate::kernel::diag_ring_record::diag_ring_record;

/// Allocate an empty, dynamically owned ASN.1 object identifier.
///
/// # Safety
/// The allocator must return storage aligned and large enough for Asn1Object.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn asn1_object_new() -> *mut Asn1Object {
    let object = traced_alloc(core::mem::size_of::<Asn1Object>() as i32, 0, 0).cast::<Asn1Object>();
    if object.is_null() {
        diag_ring_record(13, 0x7b, 0x41, 0, 0);
        return core::ptr::null_mut();
    }
    core::ptr::addr_of_mut!((*object).length).write_volatile(0);
    core::ptr::addr_of_mut!((*object).data).write_volatile(core::ptr::null());
    core::ptr::addr_of_mut!((*object).nid).write_volatile(0);
    core::ptr::addr_of_mut!((*object).sn).write_volatile(core::ptr::null());
    core::ptr::addr_of_mut!((*object).ln).write_volatile(core::ptr::null());
    core::ptr::addr_of_mut!((*object).flags).write_volatile(1);
    object
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drivers::ata_cmd::{TracedAllocHooks, TRACED_ALLOC_HOOKS};
    use crate::kernel::diag_ring_record::{BlockGetter, DiagEventRing, DIAG_RING_BLOCK_GETTER};
    use crate::testing::{DIAG_RING_TEST_LOCK, TRACED_ALLOC_TEST_LOCK};

    static mut OBJECT: Asn1Object = Asn1Object {
        sn: core::ptr::null(), ln: core::ptr::null(), nid: 0,
        length: 0, data: core::ptr::null(), flags: 0,
    };
    static mut RING: DiagEventRing = DiagEventRing {
        owner: 0, tags: [0; 16], pointers: [0; 16], flags: [0; 16],
        data0: [0; 16], data1: [0; 16], head: 0, tail: 0,
    };
    unsafe extern "C" fn allocate(_: i32, _: u32, _: u32) -> *mut u8 {
        core::ptr::addr_of_mut!(OBJECT).cast()
    }
    unsafe extern "C" fn fail(_: i32, _: u32, _: u32) -> *mut u8 {
        core::ptr::null_mut()
    }
    unsafe extern "C" fn ring() -> *mut DiagEventRing {
        core::ptr::addr_of_mut!(RING)
    }
    struct Restore(TracedAllocHooks, Option<BlockGetter>);
    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe {
                TRACED_ALLOC_HOOKS = self.0;
                DIAG_RING_BLOCK_GETTER = self.1;
            }
        }
    }

    #[test]
    fn dirty_allocation_is_empty_owned_object_and_failure_records_malloc_error() {
        let _alloc_lock = TRACED_ALLOC_TEST_LOCK.lock();
        let _diag_lock = DIAG_RING_TEST_LOCK.lock();
        unsafe {
            let _restore = Restore(TRACED_ALLOC_HOOKS, DIAG_RING_BLOCK_GETTER);
            OBJECT = Asn1Object {
                sn: 1usize as *const u8, ln: 2usize as *const u8, nid: -1,
                length: -1, data: 3usize as *const u8, flags: -1,
            };
            RING = DiagEventRing {
                owner: 0, tags: [0; 16], pointers: [0; 16], flags: [0; 16],
                data0: [u32::MAX; 16], data1: [u32::MAX; 16], head: 0, tail: 0,
            };
            TRACED_ALLOC_HOOKS = TracedAllocHooks { alloc: allocate, trace: None };
            DIAG_RING_BLOCK_GETTER = Some(ring);
            let object = asn1_object_new();
            assert_eq!(object, core::ptr::addr_of_mut!(OBJECT));
            assert!((*object).sn.is_null());
            assert!((*object).ln.is_null());
            assert!((*object).data.is_null());
            assert_eq!(((*object).length, (*object).nid, (*object).flags), (0, 0, 1));
            assert_eq!((*ring()).head, 0);
            (*object).nid = 123;
            TRACED_ALLOC_HOOKS = TracedAllocHooks { alloc: fail, trace: None };
            assert!(asn1_object_new().is_null());
            assert_eq!((*object).nid, 123);
            assert_eq!((*ring()).head, 1);
            assert_eq!((*ring()).tags[1], 0x0d07b041);
            assert_eq!(((*ring()).data0[1], (*ring()).data1[1]), (0, 0));
        }
    }
}
