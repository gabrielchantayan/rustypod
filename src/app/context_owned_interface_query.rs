//! Query the interface owned by an application context.
//!
//! Original `FUN_08115324` at `0x08115324`, true size 16 bytes, ending at
//! `0x08115334` (the next function's push). Raw words: e5900430 e5901000
//! e59110bc e12fff11. Verified inbound calls: two plain BLs (0x0819e260,
//! 0x082a1abc), zero predicated BLs; outbound: zero BL/BLX, one BX tail call.
//! Load the interface at context +0x430, load its vtable slot +0xbc, and
//! dispatch with the interface as receiver. Return the entire result, not a
//! normalized boolean: both callers compare it with zero. The concrete
//! virtual method's identity and a more specific result meaning are unknown.
//!
//! Deliberate deviations: repr(C) host pointers widen, preserving field and
//! vtable word indices. Rust expresses the tail dispatch as a final call;
//! no fixed-address callee seam or null checks are introduced.

#[repr(C)]
pub struct OwnedQueryVtable {
    pub reserved: [usize; 0xbc / 4],
    pub query: unsafe extern "C" fn(*mut OwnedQueryInterface) -> u32,
}

#[repr(C)]
pub struct OwnedQueryInterface {
    pub vtable: *const OwnedQueryVtable,
}

#[repr(C)]
pub struct OwnedInterfaceQueryContext {
    pub reserved: [u32; 0x430 / 4],
    pub interface: *mut OwnedQueryInterface,
}

/// The context, its owned interface, and the interface's query slot must be
/// valid. The method may mutate its receiver; its full word result is returned.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn context_owned_interface_query(context: *mut OwnedInterfaceQueryContext) -> u32 {
    let interface = (*context).interface;
    ((*(*interface).vtable).query)(interface)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    struct Fixture {
        interface: OwnedQueryInterface,
        result: u32,
        calls: u32,
    }

    unsafe extern "C" fn query(interface: *mut OwnedQueryInterface) -> u32 {
        let fixture = &mut *interface.cast::<Fixture>();
        fixture.calls += 1;
        fixture.result
    }

    #[test]
    fn preserves_full_results_and_reloads_the_owned_receiver() {
        let vtable = OwnedQueryVtable { reserved: [0; 0xbc / 4], query };
        let mut first = Fixture {
            interface: OwnedQueryInterface { vtable: &vtable }, result: 0, calls: 0,
        };
        let mut second = Fixture {
            interface: OwnedQueryInterface { vtable: &vtable }, result: 0x80000000, calls: 0,
        };
        let mut context = OwnedInterfaceQueryContext {
            reserved: [0x12345678; 0x430 / 4], interface: &mut first.interface,
        };
        for result in [0, 1, 0x80000000, u32::MAX] {
            first.result = result;
            assert_eq!(unsafe { context_owned_interface_query(&mut context) }, result);
        }
        context.interface = &mut second.interface;
        assert_eq!(unsafe { context_owned_interface_query(&mut context) }, 0x80000000);
        assert_eq!((first.calls, second.calls), (4, 1));
        assert_eq!(context.reserved, [0x12345678; 0x430 / 4]);
        assert_eq!(context.interface, &mut second.interface as *mut _);
    }
}
