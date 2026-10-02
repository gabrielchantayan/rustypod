//! Owner/component/feedback permission gate.
//!
//! `FUN_082897c0` @ **0x082897c0**, **144 bytes**, next real function
//! `0x08289850`. Raw ARM has eight outgoing plain BLs, zero predicated
//! BLs, one virtual BLX, and a conditional tail B to `0x08294ba0`.
//! Independently decoded incoming calls: two plain BLs (`0x082896b0`,
//! `0x08289728`), zero predicated BLs. Reject owner byte +0x4d3 or
//! class-0x6600 byte +0x100; require singleton virtual slot +0x10;
//! accept the component predicate !slot_ac || slot_b4 || slot_b8, then
//! return 1 for absent feedback controller or its permission result otherwise.
//!
//! Deviations: inline the verified byte getter and component tail wrappers
//! at 0x08116410, 0x08116904 and 0x08116914; reuse the existing +0xb4
//! wrapper and singleton/getter ports. The unported feedback permission
//! function remains a typed firmware-address call, not an invented identity.
//! Host fixtures widen vtable entries and pointer fields with repr(C);
//! firmware layouts are checked below. No NULL guards are added.

use crate::cxx::component_vtable_slot_180_tail_dispatch::{
    ComponentVtableSlot180Owner, component_vtable_slot_180_tail_dispatch,
};

type Get = unsafe extern "C" fn() -> *mut u8;
type Dispatch = unsafe extern "C" fn(*mut u8) -> u32;

/// Firmware prefix: the owner pointer is word ten, at target +0x28.
#[repr(C)]
pub struct FeedbackGateContext {
    pub opaque: [u32; 10],
    pub owner: *mut ComponentVtableSlot180Owner,
}

#[cfg(target_pointer_width = "32")]
const _: [(); 0x28] = [(); core::mem::offset_of!(FeedbackGateContext, owner)];

#[derive(Clone, Copy)]
struct GateOps {
    class_get: Get,
    singleton_get: Get,
    feedback_get: Get,
    feedback_permission: Dispatch,
}

unsafe extern "C" fn feedback_permission(controller: *mut u8) -> u32 {
    #[cfg(target_os = "none")]
    { core::mem::transmute::<usize, Dispatch>(0x0829_4ba0)(controller) }
    #[cfg(not(target_os = "none"))]
    { let _ = controller; panic!("retailOS feedback permission requires a host fixture") }
}
#[cfg(target_os = "none")]
extern "C" {
    fn input_feedback_controller_get() -> *mut u8;
}
#[cfg(not(target_os = "none"))]
use crate::app::input_feedback_controller::input_feedback_controller_get;


const FIRMWARE_OPS: GateOps = GateOps {
    class_get: crate::app::registry::instance_of_class_6600,
    singleton_get: crate::app::singletons::lazy_singleton_0x40,
    feedback_get: input_feedback_controller_get,
    feedback_permission,
};

unsafe fn virtual_result(object: *mut u8, word: usize) -> u32 {
    let vtable = object.cast::<*const Dispatch>().read();
    (vtable.add(word).read())(object)
}

unsafe fn gate(context: *mut FeedbackGateContext, ops: GateOps) -> u32 {
    let owner = (*context).owner;
    if owner.cast::<u8>().add(0x4d3).read() != 0 { return 0; }
    let class = (ops.class_get)();
    if crate::app::class_6600_byte_at_100::class_6600_byte_at_100(class) != 0 {
        return 0;
    }
    if virtual_result((ops.singleton_get)(), 0x10 / 4) == 0 { return 0; }
    let component = (*(*context).owner).component.cast::<u8>();
    if virtual_result(component, 0xac / 4) != 0
        && component_vtable_slot_180_tail_dispatch((*context).owner) == 0
        && virtual_result((*(*context).owner).component.cast::<u8>(), 0xb8 / 4) == 0
    {
        return 0;
    }
    let feedback = (ops.feedback_get)();
    if feedback.is_null() { 1 } else { (ops.feedback_permission)(feedback) }
}

/// Returns the retail gate result, including the unmodified feedback tail result.
///
/// # Safety
/// Context and owner must be readable with the retail prefix and owner byte
/// +0x4d3. All reached singleton/component vtables must contain callable slots;
/// the firmware getters and feedback controller must satisfy retail contracts.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn owner_component_feedback_gate(context: *mut FeedbackGateContext) -> u32 {
    gate(context, FIRMWARE_OPS)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::ptr;
    use std::cell::RefCell;
    use std::vec::Vec;
    use crate::cxx::component_vtable_slot_180_tail_dispatch::{
        ComponentVtableSlot180, ComponentVtableSlot180Vtable,
    };

    struct State {
        class: *mut u8, singleton: *mut u8, feedback: *mut u8,
        values: [u32; 5], calls: Vec<u8>,
    }
    std::thread_local! {
        static STATE: RefCell<State> = RefCell::new(State {
            class: ptr::null_mut(), singleton: ptr::null_mut(), feedback: ptr::null_mut(),
            values: [0; 5], calls: Vec::new(),
        });
    }
    unsafe extern "C" fn class_get() -> *mut u8 {
        STATE.with(|s| { let mut s = s.borrow_mut(); s.calls.push(0); s.class })
    }
    unsafe extern "C" fn singleton_get() -> *mut u8 {
        STATE.with(|s| { let mut s = s.borrow_mut(); s.calls.push(1); s.singleton })
    }
    unsafe extern "C" fn feedback_get() -> *mut u8 {
        STATE.with(|s| { let mut s = s.borrow_mut(); s.calls.push(6); s.feedback })
    }
    unsafe extern "C" fn result<const INDEX: usize>(_: *mut u8) -> u32 {
        STATE.with(|s| {
            let mut s = s.borrow_mut(); s.calls.push(INDEX as u8 + 2); s.values[INDEX]
        })
    }
    unsafe extern "C" fn permission(p: *mut u8) -> u32 {
        STATE.with(|s| {
            let mut s = s.borrow_mut(); assert_eq!(p, s.feedback);
            s.calls.push(7); s.values[4]
        })
    }

    #[test]
    fn exhaustive_short_circuit_and_full_width_results() {
        // Storage covers the real owner byte; native pointer fields stay aligned.
        #[repr(C)]
        struct OwnerStorage { owner: ComponentVtableSlot180Owner, tail: [u8; 0x100] }
        let mut table: [Dispatch; 47] = [result::<0>; 47];
        table[43] = result::<1>; table[45] = result::<2>; table[46] = result::<3>;
        let mut component = ComponentVtableSlot180 {
            vtable: table.as_ptr().cast::<ComponentVtableSlot180Vtable>(),
        };
        let mut owner = OwnerStorage {
            owner: ComponentVtableSlot180Owner { opaque_00_42c: [0; 268], component: &mut component },
            tail: [0; 0x100],
        };
        let mut context = FeedbackGateContext { opaque: [0; 10], owner: &mut owner.owner };
        let singleton_table: [Dispatch; 5] = [result::<0>; 5];
        let mut singleton = singleton_table.as_ptr();
        let mut class = [0u8; 0x101];
        let mut feedback = 0u32;
        let ops = GateOps { class_get, singleton_get, feedback_get, feedback_permission: permission };
        for mask in 0..128 {
            for nonzero in [1, 0x80, u32::MAX] {
                let flag = |bit| mask & (1 << bit) != 0;
                unsafe { context.owner.cast::<u8>().add(0x4d3).write(if flag(0) { 0x80 } else { 0 }); }
                class[0x100] = if flag(1) { 0xff } else { 0 };
                STATE.with(|s| *s.borrow_mut() = State {
                    class: class.as_mut_ptr(), singleton: (&mut singleton as *mut *const Dispatch).cast(),
                    feedback: if flag(6) { (&mut feedback as *mut u32).cast() } else { ptr::null_mut() },
                    values: [2, 3, 4, 5, 7].map(|bit| if flag(bit) { nonzero } else { 0 }),
                    calls: Vec::new(),
                });
                let mut expected_calls = Vec::new();
                let mut allowed = false;
                if !flag(0) {
                    expected_calls.push(0);
                    if !flag(1) {
                        expected_calls.extend_from_slice(&[1, 2]);
                        if flag(2) {
                            expected_calls.push(3);
                            allowed = !flag(3);
                            if !allowed {
                                expected_calls.push(4); allowed = flag(4);
                                if !allowed { expected_calls.push(5); allowed = flag(5); }
                            }
                        }
                    }
                }
                if allowed {
                    expected_calls.push(6);
                    if flag(6) { expected_calls.push(7); }
                }
                let expected = if !allowed { 0 } else if flag(6) { 0 } else { 1 };
                assert_eq!(unsafe { gate(&mut context, ops) }, expected, "mask {mask}");
                STATE.with(|s| assert_eq!(s.borrow().calls, expected_calls, "mask {mask}"));
                if allowed && flag(6) {
                    STATE.with(|s| s.borrow_mut().values[4] = nonzero);
                    assert_eq!(unsafe { gate(&mut context, ops) }, nonzero);
                }
            }
        }
    }
}
