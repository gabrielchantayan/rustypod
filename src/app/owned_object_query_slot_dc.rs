//! Owned-object virtual word query.
//!
//! Original: `FUN_081133f8` @ `0x081133f8`, 16 bytes, ending at the
//! next real function at `0x08113408`. Raw words: e5900430 e5901000
//! e59110dc e12fff11. Whole-image decoding finds two inbound plain BLs
//! (0x081cb06c, 0x081cb260), zero predicated BLs. The body has no BL;
//! its final BX dispatches the object's virtual method at slot +0xdc.
//!
//! Load the owned object at owner +0x430, load its vtable, and return the
//! method's word result with the owned object as receiver. Both callers use
//! that result. No NULL checks or method identity are inferred. Deliberate
//! deviation: host pointer fields and vtable entries use native width;
//! fixed owner padding and vtable word index preserve the target layout.

/// Owner prefix through the object pointer at target offset +0x430.
#[repr(C)]
pub struct QuerySlotDcOwner {
    pub opaque_prefix: [u32; 0x430 / 4],
    pub object: *mut QuerySlotDcObject,
}

/// Object prefix used by the unresolved virtual query.
#[repr(C)]
pub struct QuerySlotDcObject {
    pub vtable: *const usize,
}

type QueryWord = unsafe extern "C" fn(*mut QuerySlotDcObject) -> u32;
const QUERY_SLOT_WORD: usize = 0xdc / 4;

/// Return the owned object's unresolved slot +0xdc word query.
///
/// # Safety
/// `owner` and its object must be valid aligned readable prefixes. The
/// object's vtable must contain a callable `QueryWord` at word index 55.
/// Any additional method-specific receiver requirements must also hold.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn owned_object_query_slot_dc(owner: *const QuerySlotDcOwner) -> u32 {
    let object = (*owner).object;
    let vtable = (*object).vtable;
    let query: QueryWord = core::mem::transmute(vtable.add(QUERY_SLOT_WORD).read());
    query(object)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    struct Receiver {
        prefix: QuerySlotDcObject,
        result: u32,
        calls: u32,
    }

    unsafe extern "C" fn query(object: *mut QuerySlotDcObject) -> u32 {
        let receiver = &mut *object.cast::<Receiver>();
        receiver.calls += 1;
        receiver.result
    }

    unsafe extern "C" fn wrong_slot(_: *mut QuerySlotDcObject) -> u32 {
        panic!("dispatched an adjacent virtual slot")
    }

    #[test]
    fn selects_owned_receiver_and_preserves_word_results() {
        let mut table = [wrong_slot as *const () as usize; QUERY_SLOT_WORD + 2];
        table[QUERY_SLOT_WORD] = query as *const () as usize;
        let mut first = Receiver {
            prefix: QuerySlotDcObject { vtable: table.as_ptr() }, result: 0, calls: 0,
        };
        let mut second = Receiver {
            prefix: QuerySlotDcObject { vtable: table.as_ptr() }, result: 0x8000_0001, calls: 0,
        };
        let mut owner = QuerySlotDcOwner { opaque_prefix: [0xdead_beef; 0x430 / 4], object: &mut first.prefix };
        assert_eq!(core::mem::offset_of!(QuerySlotDcOwner, object), 0x430);
        assert_eq!(unsafe { owned_object_query_slot_dc(&owner) }, 0);
        assert_eq!((first.calls, second.calls), (1, 0));
        owner.object = &mut second.prefix;
        assert_eq!(unsafe { owned_object_query_slot_dc(&owner) }, 0x8000_0001);
        assert_eq!((first.calls, second.calls), (1, 1));
        second.result = u32::MAX;
        assert_eq!(unsafe { owned_object_query_slot_dc(&owner) }, u32::MAX);
        assert_eq!((first.calls, second.calls), (1, 2));
    }
}
