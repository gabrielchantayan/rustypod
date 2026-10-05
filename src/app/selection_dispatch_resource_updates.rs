//! Selection resource-update dispatch sequence.
//!
//! Original: `FUN_081b63c4` @ `0x081b63c4`, 172 bytes to the next real
//! function at `0x081b6470`: 140 code bytes and eight literal words.
//! Whole-image raw A32 decoding finds two inbound plain BLs (0x081b65ac,
//! 0x081b6618), no predicated BLs, and one tail B (0x081b55d8). Outgoing:
//! zero plain/predicated BLs, four plain BLXs, and a final indirect BX.
//!
//! After a selection change, dispatch five ordered category/resource pairs
//! through receiver vtable slot +0x58, reloading the vtable after every call.
//! Categories and resources remain opaque; no virtual callee identity is
//! assumed. The final dispatch's r0 result passes through to the caller.
//!
//! Deliberate deviations: repr(C) pointers widen on hosts, retaining slot
//! indices rather than host byte offsets. Rust calls and returns the final
//! result instead of requiring an indirect tail branch. Ghidra's void return
//! is corrected to preserve the raw final r0 word.

pub type SelectionResourceDispatch = unsafe extern "C" fn(*mut SelectionResourceObject, u32, u32) -> u32;

#[repr(C)]
pub struct SelectionResourceVtable {
    pub preceding_slots: [usize; 0x58 / 4],
    pub dispatch: SelectionResourceDispatch,
}

#[repr(C)]
pub struct SelectionResourceObject {
    pub vtable: *const SelectionResourceVtable,
}

/// Dispatch selection resource updates, preserving the final virtual result.
///
/// # Safety
/// `receiver` must point to a live object with a callable vtable slot +0x58.
/// Each callback may replace its vtable, but must keep the object and the
/// next dispatch slot valid. RetailOS performs no NULL checks.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn selection_dispatch_resource_updates(receiver: *mut SelectionResourceObject) -> u32 {
    let mut result = 0;
    for (category, resource) in [
        (0x5374_7220, 0x9402),
        (0x5374_7220, 0x9403),
        (0x4472_6177, 0x9405),
        (0x4472_6177, 0x9404),
        (0x436e_746c, 0x9406),
    ] {
        let dispatch = unsafe { (*(*receiver).vtable).dispatch };
        result = unsafe { dispatch(receiver, category, resource) };
    }
    result
}

#[cfg(target_os = "none")]
const _: () = assert!(core::mem::offset_of!(SelectionResourceVtable, dispatch) == 0x58);

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    struct Fixture {
        object: SelectionResourceObject,
        replacement: *const SelectionResourceVtable,
        state: u32,
    }

    unsafe extern "C" fn initial(object: *mut SelectionResourceObject, category: u32, resource: u32) -> u32 {
        unsafe {
            let fixture = object.cast::<Fixture>();
            (*fixture).state = (*fixture).state.rotate_left(7) ^ category ^ resource;
            (*object).vtable = (*fixture).replacement;
            0xdead_beef
        }
    }

    unsafe extern "C" fn changed(object: *mut SelectionResourceObject, category: u32, resource: u32) -> u32 {
        unsafe {
            let fixture = object.cast::<Fixture>();
            (*fixture).state = (*fixture).state.wrapping_mul(33) ^ category ^ resource;
            (*fixture).state
        }
    }

    #[test]
    fn reloads_changed_vtable_preserves_order_and_final_result() {
        let first = SelectionResourceVtable { preceding_slots: [0; 22], dispatch: initial };
        let second = SelectionResourceVtable { preceding_slots: [0; 22], dispatch: changed };
        for seed in [0u32, 1, 0x8000_0000, u32::MAX] {
            let mut fixture = Fixture {
                object: SelectionResourceObject { vtable: &first },
                replacement: &second,
                state: seed,
            };
            let mut expected = seed.rotate_left(7) ^ 0x5374_7220 ^ 0x9402;
            expected = expected.wrapping_mul(33) ^ 0x5374_7220 ^ 0x9403;
            expected = expected.wrapping_mul(33) ^ 0x4472_6177 ^ 0x9405;
            expected = expected.wrapping_mul(33) ^ 0x4472_6177 ^ 0x9404;
            expected = expected.wrapping_mul(33) ^ 0x436e_746c ^ 0x9406;
            assert_eq!(unsafe { selection_dispatch_resource_updates(&mut fixture.object) }, expected);
            assert_eq!(fixture.state, expected);
            assert_eq!(fixture.object.vtable, &second as *const _);
        }
    }
}
