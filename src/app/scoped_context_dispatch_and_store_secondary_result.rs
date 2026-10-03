//! Dispatch and store the receiver's secondary context result.
//!
//! Original `FUN_08231744` @ `0x08231744`, 96 bytes through the return
//! at `0x082317a0`; the next real prologue begins at `0x082317a4`.
//! Raw A32 decoding: three unconditional plain BLs, zero predicated BLs,
//! one indirect BLX at receiver vtable +0x170. Whole-image decoding finds
//! zero plain inbound BLs and two BLNEs (0x0817dd00, 0x0817e068).
//! Constructs a zero-mode ScopedContext, dispatches (receiver, argument,
//! context), conditionally resolves its payload word into object+0x30,
//! stores value at +0x34 regardless of availability, then destroys context.
//! Deliberate deviations: repr(C) pointer fields widen on hosts; a host-only
//! adapter bridges ScopedContext's u32 payload word to the existing query's
//! native pointer without changing virtual predicate identity or reload order.
//! The unused stack spill of the query's return value is omitted.

use core::{mem::MaybeUninit, ptr};
use crate::app::scoped_context::{scoped_context_construct, scoped_context_destroy, ScopedContext};
use crate::cxx::vtable_slot_08_optional_payload_word::vtable_slot_08_optional_payload_word;
#[cfg(not(target_pointer_width = "32"))]
use crate::cxx::vtable_slot_08_optional_payload_word::{OptionalPayload, OptionalPayloadHandle, OptionalPayloadVtable};

pub type ContextDispatch = unsafe extern "C" fn(*mut ContextReceiver, u32, *mut ScopedContext);

#[repr(C)]
pub struct ContextReceiverVtable {
    pub preceding_slots: [usize; 0x170 / 4],
    pub dispatch: ContextDispatch,
}

#[repr(C)]
pub struct ContextReceiver {
    pub vtable: *const ContextReceiverVtable,
}

#[repr(C)]
pub struct SecondaryContextResultObject {
    pub preceding_word: u32,
    pub receiver: *mut ContextReceiver,
    pub preceding_results: [u32; 10],
    pub result: u32,
    pub value: u32,
}

#[cfg(target_pointer_width = "32")]
const _: [(); 0x30] = [(); core::mem::offset_of!(SecondaryContextResultObject, result)];
#[cfg(target_pointer_width = "32")]
const _: [(); 0x34] = [(); core::mem::offset_of!(SecondaryContextResultObject, value)];

#[cfg(not(target_pointer_width = "32"))]
#[repr(C)]
struct HostQuery {
    handle: OptionalPayloadHandle,
    context: *mut ScopedContext,
}

#[cfg(not(target_pointer_width = "32"))]
unsafe extern "C" fn host_predicate(handle: *mut OptionalPayloadHandle) -> bool {
    let query = handle.cast::<HostQuery>();
    let context = (*query).context;
    let predicate: unsafe extern "C" fn(*mut ScopedContext) -> u32 =
        core::mem::transmute((*(*context).vtable).slots[2]);
    let accepted = predicate(context) != 0;
    if accepted {
        (*handle).payload = (*context).owner_valid as usize as *mut OptionalPayload;
    }
    accepted
}

#[inline(always)]
unsafe fn resolve(context: *mut ScopedContext, output: *mut u32) {
    #[cfg(target_pointer_width = "32")]
    { vtable_slot_08_optional_payload_word(context.cast(), output); }
    #[cfg(not(target_pointer_width = "32"))]
    {
        let vtable = OptionalPayloadVtable { slots_before: [None; 2], predicate: host_predicate };
        let mut query = HostQuery {
            handle: OptionalPayloadHandle { vtable: &vtable, payload: ptr::null_mut() },
            context,
        };
        vtable_slot_08_optional_payload_word(&mut query.handle, output);
    }
}

/// # Safety
/// Object and receiver must be valid, and receiver slot +0x170 must accept
/// a ScopedContext output. Its resulting vtable slot +8 must accept that
/// context; a successful nonzero payload word must address five u32 words.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn scoped_context_dispatch_and_store_secondary_result(
    object: *mut SecondaryContextResultObject,
    argument: u32,
    value: u32,
) {
    let mut context = MaybeUninit::<ScopedContext>::uninit();
    scoped_context_construct(context.as_mut_ptr(), ptr::null_mut(), 0);
    let receiver = ptr::addr_of!((*object).receiver).read();
    ((*(*receiver).vtable).dispatch)(receiver, argument, context.as_mut_ptr());
    resolve(context.as_mut_ptr(), ptr::addr_of_mut!((*object).result));
    ptr::addr_of_mut!((*object).value).write(value);
    scoped_context_destroy(context.as_mut_ptr());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::scoped_context::ScopedContextVtable;
    use crate::testing::{hints, try_map_u32_slab};

    #[repr(C)]
    struct ReceiverFixture {
        receiver: ContextReceiver,
        object: *mut SecondaryContextResultObject,
        payload: u32,
        mode: u32,
        query_vtable: *const ScopedContextVtable,
    }

    unsafe extern "C" fn predicate(context: *mut ScopedContext) -> u32 {
        let fixture = (*context).owner.cast::<ReceiverFixture>();
        // Resolution must precede publishing the third argument.
        assert_eq!((*(*fixture).object).value, 0x1122_3344);
        (*context).owner_valid = if (*fixture).mode == 1 { 0 } else { (*fixture).payload };
        if (*fixture).mode == 0 { 0 } else { 0x8000_0000 }
    }

    unsafe extern "C" fn dispatch(receiver: *mut ContextReceiver, argument: u32, context: *mut ScopedContext) {
        let fixture = receiver.cast::<ReceiverFixture>();
        assert_eq!((*context).mode, 0);
        assert_eq!((*context).owner_valid, 0);
        (*fixture).mode = argument;
        (*context).owner = fixture.cast();
        (*context).vtable = (*fixture).query_vtable;
        // Predicate replaces this invalid value; resolver must reload after it.
        (*context).owner_valid = 1;
    }


    #[test]
    fn availability_reload_zero_payload_and_unconditional_value_store() {
        let Some(slab) = try_map_u32_slab(hints::SECONDARY_CONTEXT_RESULT, 4096) else { return; };
        let mut query_vtable = ScopedContextVtable { slots: [0; 15] };
        query_vtable.slots[2] = predicate as *const () as usize;
        let receiver_vtable = ContextReceiverVtable { preceding_slots: [0; 0x170 / 4], dispatch };
        let mut fixture = ReceiverFixture {
            receiver: ContextReceiver { vtable: &receiver_vtable },
            object: ptr::null_mut(), payload: slab as usize as u32, mode: 0,
            query_vtable: &query_vtable,
        };
        let mut object = SecondaryContextResultObject {
            preceding_word: 0xabc, receiver: &mut fixture.receiver,
            preceding_results: [0xa5a5_a5a5; 10], result: 0, value: 0,
        };
        fixture.object = &mut object;
        unsafe {
            for mode in 0..3 {
                for payload_word in [0, u32::MAX] {
                    slab.cast::<u32>().add(4).write(payload_word);
                    object.result = 0xdead_beef;
                    object.value = 0x1122_3344;
                    scoped_context_dispatch_and_store_secondary_result(&mut object, mode, u32::MAX);
                    assert_eq!(object.result, if mode == 2 { payload_word } else { 0xdead_beef });
                    assert_eq!(object.value, u32::MAX);
                    assert_eq!(object.preceding_results, [0xa5a5_a5a5; 10]);
                    assert_eq!(object.preceding_word, 0xabc);
                }
            }
        }
    }
}
