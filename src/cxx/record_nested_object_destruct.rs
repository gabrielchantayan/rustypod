//! Optional nested-object destruction @ 0x080fe744 (FUN_080fe744).
//!
//! True size: 36 bytes [0x080fe744, 0x080fe768); the next function starts
//! with push {r4,r5,r6,r7,r8,lr}. Independent whole-image A32 decoding finds
//! two plain inbound BLs (0x083cfb38, 0x083cfb88), zero predicated inbound
//! BLs, zero outgoing direct BLs, and one BLXNE at 0x080fe75c.
//!
//! Load the record's optional object at word 1. If non-NULL, invoke its
//! vtable slot 1 with that object as receiver. Ignore the virtual result,
//! preserve callback mutations, and return the original record. Do not
//! clear the nested pointer or free the record. Concrete virtual method
//! identity is unresolved; no fixed-address callee seam is introduced.
//!
//! Deliberate deviation: repr(C) native-width pointer fields and vtable
//! words widen on hosts, preserving target word indices. No ARM algorithm
//! deviation; the first record word is never read or written.
//! ARM match: LLVM uses an early NULL return and a larger frame (13 versus
//! 9 instructions), retaining both word-1 loads, one indirect call and the
//! original-record return across dispatch.

/// Record prefix; on ARM the optional object is at byte offset +4.
#[repr(C)]
pub struct NestedObjectRecord {
    pub header: usize,
    pub object: *mut u8,
}

/// # Safety
/// `record` must be aligned and readable through its object field. A non-NULL
/// object must begin with a valid vtable pointer whose second word is callable
/// as `unsafe extern "C" fn(*mut u8)`. The callback may mutate or destroy the
/// record and object: neither is dereferenced again after the call.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn record_nested_object_destruct(
    record: *mut NestedObjectRecord,
) -> *mut NestedObjectRecord {
    let object = unsafe { core::ptr::addr_of!((*record).object).read() };
    if !object.is_null() {
        let vtable = unsafe { object.cast::<*const usize>().read() };
        let destruct: unsafe extern "C" fn(*mut u8) = unsafe {
            core::mem::transmute(vtable.add(1).read())
        };
        unsafe { destruct(object) };
    }
    record
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;

    #[repr(C)]
    struct Object {
        vtable: *const usize,
        record: *mut NestedObjectRecord,
        calls: usize,
        mutate: bool,
    }

    unsafe extern "C" fn destruct(receiver: *mut u8) {
        let object = unsafe { &mut *receiver.cast::<Object>() };
        assert_eq!(unsafe { (*object.record).object }, receiver);
        object.calls += 1;
        if object.mutate {
            unsafe {
                (*object.record).header = 19;
                (*object.record).object = ptr::null_mut();
            }
        }
    }

    #[test]
    fn null_nested_object_preserves_record_and_surrounding_words() {
        #[repr(C)]
        struct Fixture { before: usize, record: NestedObjectRecord, after: usize }
        let mut fixture = Fixture {
            before: 31,
            record: NestedObjectRecord { header: usize::MAX, object: ptr::null_mut() },
            after: 47,
        };
        let record = &mut fixture.record as *mut _;
        assert_eq!(unsafe { record_nested_object_destruct(record) }, record);
        assert_eq!(fixture.record.header, usize::MAX);
        assert!(fixture.record.object.is_null());
        assert_eq!((fixture.before, fixture.after), (31, 47));
    }

    #[test]
    fn repeated_dispatch_retains_pointer_unless_callback_changes_it() {
        for mutate in [false, true] {
            let vtable = [0usize, destruct as *const () as usize];
            let mut record = NestedObjectRecord { header: 7, object: ptr::null_mut() };
            let record_ptr = &mut record as *mut _;
            let mut object = Object { vtable: vtable.as_ptr(), record: record_ptr, calls: 0, mutate };
            let receiver = (&mut object as *mut Object).cast::<u8>();
            record.object = receiver;
            assert_eq!(unsafe { record_nested_object_destruct(record_ptr) }, record_ptr);
            assert_eq!(object.calls, 1);
            assert_eq!(record.header, if mutate { 19 } else { 7 });
            assert_eq!(record.object, if mutate { ptr::null_mut() } else { receiver });
            assert_eq!(unsafe { record_nested_object_destruct(record_ptr) }, record_ptr);
            assert_eq!(object.calls, if mutate { 1 } else { 2 });
        }
    }
}
