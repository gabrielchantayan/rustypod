//! Reads the resource value selected by the media-player interface.
//!
//! `media_player_resource_value` — original: `FUN_081f796c` @ `0x081f796c`
//! (**84 bytes**, exactly 21 ARM instructions ending at `0x081f79bc`; the
//! distinct next function begins at `0x081f79c0`). Decoding every ARM branch
//! word in `osos.dec` finds **four plain unconditional `bl`** call sites
//! (0x081f7978, 0x081f797c, 0x081f799c, and 0x081f79b0), **zero predicated
//! `bl`** call sites, and one dynamic `blx` through media-player-interface
//! vtable slot +0xe4.
//!
//! The function default-constructs a [`TaggedValue`], asks the media-player
//! interface's unresolved virtual slot +0xe4 to fill it, constructs a
//! [`ScopedContext`] from that value with mode zero, then returns the scoped
//! context's resource-reference value before destroying the stack token.
//! Deliberate deviation: host tests replace the singleton getter and final
//! resource lookup with native callbacks; target builds call the existing
//! retailOS ports. The slot's concrete callee identity is not recovered, so
//! its verified receiver-and-tagged-value ABI remains virtual.

use crate::app::resource_reference_value::resource_reference_value;
use crate::app::scoped_context::{scoped_context_construct_from_source, scoped_context_destroy, ScopedContext};
use crate::app::singletons::media_player_interface_get;
use crate::cxx::tagged_value::{tagged_value_default_construct, TaggedValue};

/// Media-player interface vtable prefix through the observed +0xe4 slot.
#[repr(C)]
pub struct MediaPlayerInterfaceVtable {
    _slots_before_selected_value: [usize; 0xe4 / 4],
    pub selected_value: unsafe extern "C" fn(*mut u8, *mut TaggedValue),
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0xe8] = [0; core::mem::size_of::<MediaPlayerInterfaceVtable>()];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0xe4] = [0; core::mem::offset_of!(MediaPlayerInterfaceVtable, selected_value)];

type MediaPlayerInterfaceGet = unsafe extern "C" fn() -> *mut u8;
type ResourceReferenceValue = unsafe extern "C" fn(*mut ScopedContext) -> u32;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn get_interface() -> *mut u8 {
    media_player_interface_get()
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn selected_resource_value(context: *mut ScopedContext) -> u32 {
    resource_reference_value(context.cast())
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_interface() -> *mut u8 {
    core::ptr::null_mut()
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_resource_value(_context: *mut ScopedContext) -> u32 {
    0
}

#[cfg(not(target_os = "none"))]
static mut HOST_OPS: (MediaPlayerInterfaceGet, ResourceReferenceValue) =
    (unavailable_interface, unavailable_resource_value);

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn get_interface() -> *mut u8 {
    core::ptr::read_volatile(core::ptr::addr_of!(HOST_OPS)).0()
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn selected_resource_value(context: *mut ScopedContext) -> u32 {
    core::ptr::read_volatile(core::ptr::addr_of!(HOST_OPS)).1(context)
}

/// # Safety
/// The media-player interface getter must return a valid interface. Its vtable
/// slot +0xe4 must accept the interface and writable [`TaggedValue`]; all
/// callee-owned pointers must satisfy the existing scoped-context and
/// resource-reference contracts.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.media_player_resource_value")]
#[inline(never)]
pub unsafe extern "C" fn media_player_resource_value() -> u32 {
    let mut value = core::mem::MaybeUninit::<TaggedValue>::uninit();
    tagged_value_default_construct(value.as_mut_ptr());

    let interface = get_interface();
    let vtable = (interface as *const *const MediaPlayerInterfaceVtable).read();
    ((*vtable).selected_value)(interface, value.as_mut_ptr());

    let mut context = core::mem::MaybeUninit::<ScopedContext>::uninit();
    scoped_context_construct_from_source(context.as_mut_ptr(), value.as_ptr().cast(), 0);
    let result = selected_resource_value(context.as_mut_ptr());
    scoped_context_destroy(context.as_mut_ptr());
    result
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::ptr::addr_of_mut;
    use std::sync::{Mutex, MutexGuard};
    #[repr(C)]
    struct Interface {
        vtable: *const MediaPlayerInterfaceVtable,
    }
    static LOCK: Mutex<()> = Mutex::new(());
    static mut INTERFACE: *mut u8 = core::ptr::null_mut();
    static mut SEEN_RECEIVER: *mut u8 = core::ptr::null_mut();
    static mut SEEN_TAGGED_VALUE: TaggedValue = TaggedValue { vtable: 0, kind: 0, padding: [0; 3], payload: 0, auxiliary: 0 };
    static mut RESOURCE_CALLS: u32 = 0;

    unsafe extern "C" fn test_interface() -> *mut u8 { INTERFACE }
    unsafe extern "C" fn fill_selected_value(receiver: *mut u8, value: *mut TaggedValue) {
        SEEN_RECEIVER = receiver;
        SEEN_TAGGED_VALUE = value.read();
    }
    unsafe extern "C" fn test_resource_value(context: *mut ScopedContext) -> u32 {
        RESOURCE_CALLS += 1;
        assert_eq!((*context).mode, 0);
        0x6a09_e667
    }

    fn install() -> MutexGuard<'static, ()> {
        let guard = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            addr_of_mut!(RESOURCE_CALLS).write(0);
            addr_of_mut!(HOST_OPS).write((test_interface, test_resource_value));
        }
        guard
    }

    #[test]
    fn dispatches_default_tagged_value_and_returns_resource_value() {
        let guard = install();
        let vtable = MediaPlayerInterfaceVtable { _slots_before_selected_value: [0; 0xe4 / 4], selected_value: fill_selected_value };
        let mut interface = Interface { vtable: &vtable };
        let interface = (&mut interface as *mut Interface).cast::<u8>();
        unsafe {
            addr_of_mut!(INTERFACE).write(interface);
            assert_eq!(media_player_resource_value(), 0x6a09_e667);
            assert_eq!(SEEN_RECEIVER, interface);
            assert_eq!(SEEN_TAGGED_VALUE.vtable, crate::cxx::tagged_value::TAGGED_VALUE_VTABLE);
            assert_eq!(SEEN_TAGGED_VALUE.kind, 0);
            assert_eq!(RESOURCE_CALLS, 1);
            addr_of_mut!(HOST_OPS).write((unavailable_interface, unavailable_resource_value));
        }
        drop(guard);
    }
}
