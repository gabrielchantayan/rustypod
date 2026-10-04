//! Position-dependent resource refresh at load address 0x081f9a3c.
//! True extent: 196 bytes through 0x081f9aff (164 executable bytes and
//! 32 literal bytes); next real function starts at 0x081f9b00. Raw A32
//! decoding finds two inbound plain BLs (0x081f98c8, 0x081f9f08), zero
//! predicated inbound BLs, zero outbound direct BLs, and six plain BLX calls.
//!
//! Dispatch six ordered resource updates through receiver vtable slot +0x58:
//! five "Str " resources and one "Cntl" resource. Reload the receiver's
//! vtable before every call, ignore each result, and return one. The callers
//! include a position accumulator update and an event handler; the concrete
//! class and virtual method identity remain unresolved.
//!
//! Deliberate deviation: repr(C) widens the receiver's vtable pointer and
//! reserved vtable slots on hosts; on ARM the dispatch field stays at +0x58.
//! Volatile reads preserve dispatch changes made by earlier callbacks.

use core::ptr;

type ResourceDispatch = unsafe extern "C" fn(*mut PositionResourceReceiver, u32, u32) -> u32;

#[repr(C)]
pub struct PositionResourceVtable {
    pub unresolved: [usize; 22],
    pub dispatch_resource: ResourceDispatch,
}

#[repr(C)]
pub struct PositionResourceReceiver {
    pub vtable: *const PositionResourceVtable,
}

#[inline(always)]
unsafe fn dispatch(receiver: *mut PositionResourceReceiver, kind: u32, resource: u32) {
    let vtable = ptr::read_volatile(ptr::addr_of!((*receiver).vtable));
    let method = ptr::read_volatile(ptr::addr_of!((*vtable).dispatch_resource));
    method(receiver, kind, resource);
}

/// # Safety
/// `receiver` must have a valid vtable and callable +0x58 entry before each
/// dispatch. Each callback must accept the receiver and resource arguments.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn position_resource_refresh(receiver: *mut PositionResourceReceiver) -> u32 {
    dispatch(receiver, 0x5374_7220, 0x7f0a);
    dispatch(receiver, 0x5374_7220, 0x7f0b);
    dispatch(receiver, 0x436e_746c, 0x7f0f);
    dispatch(receiver, 0x5374_7220, 0x7f03);
    dispatch(receiver, 0x5374_7220, 0x7f04);
    dispatch(receiver, 0x5374_7220, 0x7f09);
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    struct Fixture {
        receiver: PositionResourceReceiver,
        calls: [(u32, u32, u32); 6],
        count: usize,
        replacement: *const PositionResourceVtable,
    }

    unsafe fn record(receiver: *mut PositionResourceReceiver, kind: u32, resource: u32, method: u32) -> u32 {
        let fixture = &mut *receiver.cast::<Fixture>();
        fixture.calls[fixture.count] = (kind, resource, method);
        fixture.count += 1;
        fixture.receiver.vtable = fixture.replacement;
        // Alternating failure/success values must not terminate the sequence
        // or affect the unconditional return value.
        if fixture.count % 2 == 0 { u32::MAX } else { 0 }
    }

    unsafe extern "C" fn first(receiver: *mut PositionResourceReceiver, kind: u32, resource: u32) -> u32 {
        record(receiver, kind, resource, 1)
    }

    unsafe extern "C" fn replacement(receiver: *mut PositionResourceReceiver, kind: u32, resource: u32) -> u32 {
        record(receiver, kind, resource, 2)
    }

    #[test]
    fn ordered_refresh_ignores_results_and_observes_vtable_replacement() {
        let initial = PositionResourceVtable { unresolved: [0; 22], dispatch_resource: first };
        let changed = PositionResourceVtable { unresolved: [0; 22], dispatch_resource: replacement };
        for change_dispatch in [false, true] {
            let mut fixture = Fixture {
                receiver: PositionResourceReceiver { vtable: &initial },
                calls: [(0, 0, 0); 6], count: 0,
                replacement: if change_dispatch { &changed } else { &initial },
            };
            assert_eq!(unsafe { position_resource_refresh(&mut fixture.receiver) }, 1);
            let later = if change_dispatch { 2 } else { 1 };
            assert_eq!(fixture.calls, [
                (0x5374_7220, 0x7f0a, 1),
                (0x5374_7220, 0x7f0b, later),
                (0x436e_746c, 0x7f0f, later),
                (0x5374_7220, 0x7f03, later),
                (0x5374_7220, 0x7f04, later),
                (0x5374_7220, 0x7f09, later),
            ]);
        }
    }
}
