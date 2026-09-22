//! `photo_browse_slideshow_construct` — retailOS `FUN_0822ba68` @
//! `0x0822ba68` (**120 bytes, `0x0822ba68..0x0822bae0`**): 116 instruction
//! bytes followed by the vtable literal `0x089a0910` at `0x0822badc`. The next
//! separately linked function begins at `0x0822bae0`.
//!
//! Raw ARM decoding finds three incoming plain `bl` calls and no predicated
//! form (`0x081b7d68`, `0x081cd624`, `0x08220540`). The body has six outgoing
//! plain `bl` calls and no predicated form: `0x08214568`, `0x08214eb0`,
//! `0x08208614`,
//! [`super::image_format_descriptor_slots_initialize::image_format_descriptor_slots_initialize`],
//! [`crate::shared_cell_construct_secondary`], and
//! [`crate::shared_cell_construct`]. It initializes the slideshow object's base
//! fields and vtable, builds nested descriptor slots, clears two shared-cell
//! handles, marks the nested state active, and clears word `+0x898`.
//!
//! Deliberate deviation: the three unported callees remain fixed-address calls
//! on ARM and are replaceable host seams; their identities have not been
//! established beyond their observed constructor roles.

use crate::cxx::shared_cell::{shared_cell_construct, shared_cell_construct_secondary, SharedCell};
use super::image_format_descriptor_slots_initialize::image_format_descriptor_slots_initialize;

const VTABLE: u32 = 0x089a_0910;
const BASE_WORD_11: usize = 11;
const BASE_WORD_12: usize = 12;
const BASE_WORD_13: usize = 13;
const NESTED_CONSTRUCT_OFFSET: usize = 0x38;
const NESTED_STATE_OFFSET: usize = 0x2c8;
const DESCRIPTOR_OFFSET: usize = 0x2cc;
const FIRST_CELL_OFFSET: usize = 0x560;
const SECOND_CELL_OFFSET: usize = 0x564;
const FINAL_CLEAR_OFFSET: usize = 0x898;
const BASE_CONSTRUCT_TARGET: usize = 0x0821_4568;
const NESTED_CONSTRUCT_TARGET: usize = 0x0821_4eb0;
const NESTED_STATE_TARGET: usize = 0x0820_8614;

type BaseConstruct = unsafe extern "C" fn(*mut u8, *const u8) -> *mut u8;
type NestedConstruct = unsafe extern "C" fn(*mut u8) -> *mut u8;
type NestedState = unsafe extern "C" fn(*mut u8) -> *mut u8;

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_base_construct(_context: *mut u8, _descriptor: *const u8) -> *mut u8 { panic!("install photo-browse slideshow constructor seams") }
#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_nested_construct(_object: *mut u8) -> *mut u8 { panic!("install photo-browse slideshow constructor seams") }
#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_nested_state(_object: *mut u8) -> *mut u8 { panic!("install photo-browse slideshow constructor seams") }

#[cfg(not(target_arch = "arm"))]
pub static mut PHOTO_BROWSE_SLIDESHOW_BASE_CONSTRUCT: BaseConstruct = missing_base_construct;
#[cfg(not(target_arch = "arm"))]
pub static mut PHOTO_BROWSE_SLIDESHOW_NESTED_CONSTRUCT: NestedConstruct = missing_nested_construct;
#[cfg(not(target_arch = "arm"))]
pub static mut PHOTO_BROWSE_SLIDESHOW_NESTED_STATE: NestedState = missing_nested_state;

#[inline(always)]
unsafe fn base_construct() -> BaseConstruct {
    #[cfg(target_arch = "arm")]
    { core::mem::transmute(BASE_CONSTRUCT_TARGET) }
    #[cfg(not(target_arch = "arm"))]
    { core::ptr::read_volatile(core::ptr::addr_of!(PHOTO_BROWSE_SLIDESHOW_BASE_CONSTRUCT)) }
}
#[inline(always)]
unsafe fn nested_construct() -> NestedConstruct {
    #[cfg(target_arch = "arm")]
    { core::mem::transmute(NESTED_CONSTRUCT_TARGET) }
    #[cfg(not(target_arch = "arm"))]
    { core::ptr::read_volatile(core::ptr::addr_of!(PHOTO_BROWSE_SLIDESHOW_NESTED_CONSTRUCT)) }
}
#[inline(always)]
unsafe fn nested_state() -> NestedState {
    #[cfg(target_arch = "arm")]
    { core::mem::transmute(NESTED_STATE_TARGET) }
    #[cfg(not(target_arch = "arm"))]
    { core::ptr::read_volatile(core::ptr::addr_of!(PHOTO_BROWSE_SLIDESHOW_NESTED_STATE)) }
}

/// Constructs and returns the photo-browse slideshow object.
///
/// # Safety
///
/// The three retail constructor targets and their returned object layouts must
/// satisfy the raw ARM accesses through `+0x898`; allocation failure is not
/// checked by the original.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn photo_browse_slideshow_construct(context: *mut u8, descriptor: *const u8) -> *mut u8 {
    let object = base_construct()(context, descriptor);
    object.cast::<u32>().write(VTABLE);
    object.cast::<u32>().add(BASE_WORD_11).write(0);
    object.cast::<u32>().add(BASE_WORD_12).write(0);
    object.cast::<u32>().add(BASE_WORD_13).write(u32::MAX);
    let nested = nested_construct()(object.add(NESTED_CONSTRUCT_OFFSET));
    let state = nested_state()(nested.add(0x2f8));
    state.add(NESTED_STATE_OFFSET).write(1);
    image_format_descriptor_slots_initialize(state.add(DESCRIPTOR_OFFSET).cast());
    shared_cell_construct_secondary(state.add(FIRST_CELL_OFFSET).cast::<*mut SharedCell>(), core::ptr::null_mut());
    shared_cell_construct(state.add(SECOND_CELL_OFFSET).cast::<*mut SharedCell>(), core::ptr::null_mut());
    state.add(FINAL_CLEAR_OFFSET).cast::<u32>().write(0);
    object
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut BASE: *mut u8 = core::ptr::null_mut();
    static mut NESTED: *mut u8 = core::ptr::null_mut();
    static mut STATE: *mut u8 = core::ptr::null_mut();
    static mut BASE_ARGS: (*mut u8, *const u8) = (core::ptr::null_mut(), core::ptr::null());

    unsafe extern "C" fn base_construct(context: *mut u8, descriptor: *const u8) -> *mut u8 { BASE_ARGS = (context, descriptor); BASE }
    unsafe extern "C" fn nested_construct(object: *mut u8) -> *mut u8 { assert_eq!(object, BASE.add(NESTED_CONSTRUCT_OFFSET)); NESTED }
    unsafe extern "C" fn nested_state(object: *mut u8) -> *mut u8 { assert_eq!(object, NESTED.add(0x2f8)); STATE }

    #[test]
    fn initializes_base_nested_slots_and_returns_base_object() {
        let _lock = LOCK.lock();
        let mut base = [0xa5u8; 0x80];
        let mut nested = [0xa5u8; 0x400];
        let mut state = [0xa5u8; FINAL_CLEAR_OFFSET + 4];
        let descriptor = [0u8; 1];
        unsafe {
            BASE = base.as_mut_ptr(); NESTED = nested.as_mut_ptr(); STATE = state.as_mut_ptr();
            PHOTO_BROWSE_SLIDESHOW_BASE_CONSTRUCT = base_construct;
            PHOTO_BROWSE_SLIDESHOW_NESTED_CONSTRUCT = nested_construct;
            PHOTO_BROWSE_SLIDESHOW_NESTED_STATE = nested_state;
            let result = photo_browse_slideshow_construct(base.as_mut_ptr().wrapping_add(3), descriptor.as_ptr());
            assert_eq!(result, base.as_mut_ptr());
            assert_eq!(BASE_ARGS, (base.as_mut_ptr().wrapping_add(3), descriptor.as_ptr()));
            assert_eq!(base.as_ptr().cast::<u32>().read(), VTABLE);
            assert_eq!(base.as_ptr().cast::<u32>().add(BASE_WORD_11).read(), 0);
            assert_eq!(base.as_ptr().cast::<u32>().add(BASE_WORD_12).read(), 0);
            assert_eq!(base.as_ptr().cast::<u32>().add(BASE_WORD_13).read(), u32::MAX);
            assert_eq!(state[NESTED_STATE_OFFSET], 1);
            assert_eq!(state.as_ptr().add(FINAL_CLEAR_OFFSET).cast::<u32>().read(), 0);
            assert_eq!(state.as_ptr().add(FIRST_CELL_OFFSET).cast::<usize>().read(), 0);
            assert_eq!(state.as_ptr().add(SECOND_CELL_OFFSET).cast::<usize>().read(), 0);
            PHOTO_BROWSE_SLIDESHOW_BASE_CONSTRUCT = missing_base_construct;
            PHOTO_BROWSE_SLIDESHOW_NESTED_CONSTRUCT = missing_nested_construct;
            PHOTO_BROWSE_SLIDESHOW_NESTED_STATE = missing_nested_state;
        }
    }
}
