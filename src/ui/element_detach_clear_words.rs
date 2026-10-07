//! `ui_element_detach_clear_words` — FUN_08157670 at 0x08157670.
//! True size: 76 bytes, next prologue at 0x081576bc. Incoming calls:
//! one plain BL (0x08187bbc), one BLNE (0x0826f168). Body: four plain BL,
//! zero predicated BL, one indirect BLX.
//!
//! Dispatch embedded object +0xa8 through vtable +0x28, passing the address
//! of a local item pointer. Test the possibly replaced item's +0x94 byte;
//! when nonzero, resolve the element's render context, and if non-null,
//! resolve it again and clear that second result's word vector. Callers
//! detach an item from its prior owner; the virtual method identity is unknown.
//!
//! Deviations: native-width vtable slots on hosts; incidental r3 and stacked
//! saved r0 are not modeled as virtual arguments. Preserve r2's method address
//! explicitly. No caching of the two potentially side-effecting resolutions.

use super::coordinate_owner_clear_words::{coordinate_owner_clear_words, CoordinateWordOwner};
use super::render_context::ui_element_resolve_render_context;
use crate::app::object_byte_at_94::object_byte_at_94;

pub type DetachMethod = unsafe extern "C" fn(*mut DetachInterface, *mut *mut u8, usize);

#[repr(C)]
pub struct DetachVtable {
    pub preceding_slots: [usize; 10],
    pub detach: DetachMethod,
}

#[repr(C)]
pub struct DetachInterface {
    pub vtable: *const DetachVtable,
}

/// # Safety
/// `element` contains the live interface at +0xa8 and satisfies the render
/// resolver contract. The virtual method must leave a readable item pointer;
/// any second resolved context must satisfy the word-owner clear contract.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ui_element_detach_clear_words(element: *mut u8, item: *mut u8) {
    let interface = element.add(0xa8).cast::<DetachInterface>();
    let method = (*(*interface).vtable).detach;
    let mut detached_item = item;
    method(interface, &mut detached_item, method as usize);
    if object_byte_at_94(detached_item) != 0 {
        if !ui_element_resolve_render_context(element).is_null() {
            let owner = ui_element_resolve_render_context(element);
            coordinate_owner_clear_words(owner.cast::<CoordinateWordOwner>());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;
    use super::super::coordinate_owner_clear_words::OwnerWordVector;

    struct State {
        replacement: *mut u8,
        detach_calls: usize,
        lookup_calls: usize,
        first: *mut u8,
        second: *mut u8,
        render_owner: [usize; 40],
    }

    unsafe fn state(element: *mut u8) -> &'static mut State {
        &mut *element.add(0xe0).cast::<*mut State>().read()
    }

    unsafe extern "C" fn detach(interface: *mut DetachInterface, item: *mut *mut u8, method: usize) {
        assert_eq!(method, detach as usize);
        let s = state(interface.cast::<u8>().sub(0xa8));
        s.detach_calls += 1;
        *item = s.replacement;
    }

    unsafe extern "C" fn resolve(element: *mut u8) -> *mut u8 {
        let s = state(element);
        let context = if s.lookup_calls == 0 { s.first } else { s.second };
        s.lookup_calls += 1;
        let owner = s.render_owner.as_mut_ptr().cast::<u8>();
        owner.add(0x104).cast::<*mut u8>().write_unaligned(context);
        owner
    }

    #[test]
    fn replaced_item_gate_and_two_distinct_resolutions() {
        for gate in [0u8, 1, 0x80, 0xff] {
            for first_present in [false, true] {
                let mut data = [11u32, 22, 33];
                let begin = data.as_mut_ptr();
                let mut owner = CoordinateWordOwner {
                    prefix: [0; 5],
                    words: OwnerWordVector { begin, end: unsafe { begin.add(2) }, capacity_end: unsafe { begin.add(3) } },
                    intervening_words: [0; 22], context: ptr::null_mut(),
                };
                let mut original = [0u8; 0x98];
                original[0x94] = if gate == 0 { 1 } else { 0 };
                let mut replacement = [0u8; 0x98];
                replacement[0x94] = gate;
                let mut s = State {
                    replacement: replacement.as_mut_ptr(), detach_calls: 0, lookup_calls: 0,
                    // First result is intentionally not a word owner: only its nullness matters.
                    first: if first_present { original.as_mut_ptr() } else { ptr::null_mut() },
                    second: (&mut owner as *mut CoordinateWordOwner).cast(), render_owner: [0; 40],
                };
                let detach_vtable = DetachVtable { preceding_slots: [0; 10], detach };
                let mut root_vtable = [0usize; 16];
                let mut element = [0usize; 64];
                unsafe {
                    let base = element.as_mut_ptr().cast::<u8>();
                    root_vtable.as_mut_ptr().cast::<u8>().add(0x5c).cast::<usize>().write_unaligned(resolve as usize);
                    base.cast::<*const usize>().write(root_vtable.as_ptr());
                    base.add(0xa8).cast::<DetachInterface>().write(DetachInterface { vtable: &detach_vtable });
                    base.add(0xe0).cast::<*mut State>().write(&mut s);
                    ui_element_detach_clear_words(base, original.as_mut_ptr());
                }
                assert_eq!(s.detach_calls, 1);
                assert_eq!(s.lookup_calls, if gate == 0 { 0 } else if first_present { 2 } else { 1 });
                assert_eq!(owner.words.end, if gate != 0 && first_present { begin } else { unsafe { begin.add(2) } });
                assert_eq!(owner.words.capacity_end, unsafe { begin.add(3) });
                assert_eq!(data, [11, 22, 33]);
            }
        }
    }
}
