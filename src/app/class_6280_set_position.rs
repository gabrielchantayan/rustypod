//! Class-0x6280 position selector.
//!
//! `class_6280_set_position` — `FUN_0811c188` @ 0x0811c188. The true extent
//! is 148 bytes (0x0811c188..0x0811c21c): 144 instruction bytes followed by
//! its 4-byte null-string literal; the next function starts at 0x0811c234.
//! Raw ARM decoding finds one plain direct `bl` (string assignment), zero
//! predicated direct `bl`, and four indirect `blx` dispatches. It conditionally
//! replaces the selected position, clears the embedded status string, notifies
//! the position provider, submits three opaque resource updates through vtable
//! slot +0x58, then tail-branches to the shared UI refresh at 0x0811b9dc.
//!
//! Deliberate deviations: the four virtual callees are not identified, so the
//! target build retains physical vtable dispatch rather than inventing seams.
//! The host adapter widens those vtable pointers for tests; its shared-refresh
//! path is target-only because it invokes further unidentified virtual slots.

use core::ptr;

use crate::cxx::string_object::{string_object_assign_cstr, StringObject};

const POSITION_OFFSET: usize = 0x20;
const MODE_OFFSET: usize = 0x2d;
const POSITION_PROVIDER_OFFSET: usize = 0x88;
const STATUS_OFFSET: usize = 0x8c;
const UI_ELEMENT_OFFSET: usize = 0x94;
const RESOURCE_FIRST: u32 = 0x6280;
const RESOURCE_SECOND: u32 = 0x6282;
const RESOURCE_THIRD: u32 = 0x6283;
const OPAQUE_FIRST_VALUE: u32 = 0x2a2a_2a2a;
const OPAQUE_SHARED_VALUE: u32 = 0x5374_7220;

#[cfg(target_os = "none")]
unsafe fn dispatch_provider(provider: *mut u8, position: i32) {
    let vtable = ptr::read_volatile(provider.cast::<u32>()) as usize as *const u32;
    let address = ptr::read_volatile(vtable.add(0x40 / 4));
    let dispatch: unsafe extern "C" fn(*mut u8, i32) = core::mem::transmute(address as usize);
    dispatch(provider, position);
}

#[cfg(target_os = "none")]
unsafe fn dispatch_resource(view: *mut u8, value: u32, resource: u32) {
    let vtable = ptr::read_volatile(view.cast::<u32>()) as usize as *const u32;
    let address = ptr::read_volatile(vtable.add(0x58 / 4));
    let dispatch: unsafe extern "C" fn(*mut u8, u32, u32) = core::mem::transmute(address as usize);
    dispatch(view, value, resource);
}

#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostClass6280Vtable {
    _before_resource: [usize; 0x58 / core::mem::size_of::<usize>()],
    pub resource: unsafe extern "C" fn(*mut u8, u32, u32),
}

#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostPositionProviderVtable {
    _before_position: [usize; 0x40 / core::mem::size_of::<usize>()],
    pub position: unsafe extern "C" fn(*mut u8, i32),
}

#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostClass6280 {
    pub vtable: *const HostClass6280Vtable,
    _before_position: [u8; POSITION_OFFSET - core::mem::size_of::<*const HostClass6280Vtable>()],
    pub position: i32,
    _before_mode: [u8; MODE_OFFSET - POSITION_OFFSET - core::mem::size_of::<i32>()],
    pub mode: u8,
    _before_provider: [u8; POSITION_PROVIDER_OFFSET - MODE_OFFSET - 1],
    pub provider: *mut u8,
    pub status: StringObject,
    pub ui_element: *mut u8,
}

#[cfg(not(target_os = "none"))]
unsafe fn dispatch_provider(provider: *mut u8, position: i32) {
    let vtable = ptr::read_volatile(provider.cast::<*const HostPositionProviderVtable>());
    ((*vtable).position)(provider, position);
}

#[cfg(not(target_os = "none"))]
unsafe fn dispatch_resource(view: *mut u8, value: u32, resource: u32) {
    let vtable = ptr::read_volatile(view.cast::<*const HostClass6280Vtable>());
    ((*vtable).resource)(view, value, resource);
}

#[cfg(target_os = "none")]
unsafe fn refresh_ui(view: *mut u8) {
    use crate::runtime::rt_div::__rt_sdiv;
    use crate::ui::invalidate::ui_element_invalidate_region;

    let position = ptr::read_volatile(view.add(POSITION_OFFSET).cast::<i32>());
    let mode = ptr::read_volatile(view.add(MODE_OFFSET));
    let marker = if mode == 3 {
        __rt_sdiv(position.wrapping_sub(76_000).wrapping_mul(20), 1_000).wrapping_add(18)
    } else {
        __rt_sdiv(position.wrapping_sub(88_000).wrapping_mul(14), 1_000).wrapping_add(20)
    };
    let element = ptr::read_volatile(view.add(UI_ELEMENT_OFFSET).cast::<u32>()) as usize as *mut u8;
    if element.is_null() { return; }
    let first_pair = (ptr::read_volatile(element.add(0x54).cast::<u32>()) & !0x20) == 0x8000_0002
        && (ptr::read_volatile(element.add(0x60).cast::<u32>()) & !0x20) == 0x8000_0002;
    if first_pair {
        ptr::write_volatile(element.add(0x64).cast::<i32>(), marker);
        ptr::write_volatile(
            element.add(0x58).cast::<u32>(),
            ptr::read_volatile(element.add(0x80).cast::<u32>()),
        );
    } else {
        let second_pair = (ptr::read_volatile(element.add(0x6c).cast::<u32>()) & !0x20) == 0x8000_0002
            && (ptr::read_volatile(element.add(0x78).cast::<u32>()) & !0x20) == 0x8000_0002;
        if second_pair {
            ptr::write_volatile(element.add(0x7c).cast::<i32>(), marker);
            ptr::write_volatile(
                element.add(0x70).cast::<u32>(),
                ptr::read_volatile(element.add(0x80).cast::<u32>()),
            );
        }
    }
    ptr::write_volatile(
        element.add(0x48).cast::<u32>(),
        ptr::read_volatile(element.add(0x48).cast::<u32>()) | 0x20,
    );
    ui_element_invalidate_region(element, element.add(0x80).cast());
    let parent = ptr::read_volatile(element.add(0x34).cast::<u32>()) as usize as *mut u8;
    if !parent.is_null() && ptr::read_volatile(element.add(0xa0)) == 0 {
        let vtable = ptr::read_volatile(parent.cast::<u32>()) as usize as *const u32;
        let callback: unsafe extern "C" fn(*mut u8) = core::mem::transmute(ptr::read_volatile(vtable.add(0x128 / 4)) as usize);
        callback(parent);
    }
    let vtable = ptr::read_volatile(element.cast::<u32>()) as usize as *const u32;
    let resolve: unsafe extern "C" fn(*mut u8) -> *mut u8 = core::mem::transmute(ptr::read_volatile(vtable.add(0x5c / 4)) as usize);
    let resolved = resolve(element);
    ptr::write_volatile(
        resolved.add(0x48).cast::<u32>(),
        ptr::read_volatile(resolved.add(0x48).cast::<u32>()) | 0x40,
    );
}

#[cfg(not(target_os = "none"))]
unsafe fn refresh_ui(_: *mut u8) {}

/// Selects a class-0x6280 position and refreshes its displayed state.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn class_6280_set_position(view: *mut u8, position: i32, force: u32) {
    let previous = ptr::read_volatile(view.add(POSITION_OFFSET).cast::<i32>());
    if force != 0 || previous != position {
        ptr::write_volatile(view.add(POSITION_OFFSET).cast::<i32>(), position);
        string_object_assign_cstr(view.add(STATUS_OFFSET).cast::<StringObject>(), ptr::null());
        #[cfg(target_os = "none")]
        let provider = ptr::read_volatile(view.add(POSITION_PROVIDER_OFFSET).cast::<u32>()) as usize as *mut u8;
        #[cfg(not(target_os = "none"))]
        let provider = ptr::read_volatile(ptr::addr_of!((*view.cast::<HostClass6280>()).provider));
        dispatch_provider(provider, position);
    }
    dispatch_resource(view, OPAQUE_FIRST_VALUE, RESOURCE_FIRST);
    dispatch_resource(view, OPAQUE_SHARED_VALUE, RESOURCE_SECOND);
    dispatch_resource(view, OPAQUE_SHARED_VALUE, RESOURCE_THIRD);
    refresh_ui(view);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::ptr::{addr_of, addr_of_mut};
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut PROVIDER_CALL: Option<i32> = None;
    static mut RESOURCES: [u32; 3] = [0; 3];
    static mut RESOURCE_COUNT: usize = 0;
    unsafe extern "C" fn provider(_: *mut u8, position: i32) { PROVIDER_CALL = Some(position); }
    unsafe extern "C" fn resource(_: *mut u8, _: u32, id: u32) { RESOURCES[RESOURCE_COUNT] = id; RESOURCE_COUNT += 1; }
    static PROVIDER_VTABLE: HostPositionProviderVtable = HostPositionProviderVtable { _before_position: [0; 8], position: provider };
    static VIEW_VTABLE: HostClass6280Vtable = HostClass6280Vtable { _before_resource: [0; 11], resource };

    fn view(position: i32, provider_ptr: *mut u8) -> HostClass6280 {
        HostClass6280 { vtable: addr_of!(VIEW_VTABLE), _before_position: [0; 24], position, _before_mode: [0; 9], mode: 0, _before_provider: [0; 90], provider: provider_ptr, status: unsafe { core::mem::zeroed() }, ui_element: ptr::null_mut() }
    }
    #[test]
    fn unchanged_position_skips_provider_but_still_updates_resources() {
        let _guard = LOCK.lock();
        unsafe { PROVIDER_CALL = None; RESOURCES = [0; 3]; RESOURCE_COUNT = 0; }
        let mut provider_storage = [addr_of!(PROVIDER_VTABLE) as usize];
        let mut subject = view(42, provider_storage.as_mut_ptr().cast());
        unsafe { class_6280_set_position(addr_of_mut!(subject).cast(), 42, 0); }
        unsafe { assert_eq!(PROVIDER_CALL, None); assert_eq!(RESOURCES, [RESOURCE_FIRST, RESOURCE_SECOND, RESOURCE_THIRD]); }
    }
    #[test]
    fn forced_position_notifies_provider_even_when_unchanged() {
        let _guard = LOCK.lock();
        unsafe { PROVIDER_CALL = None; RESOURCES = [0; 3]; RESOURCE_COUNT = 0; }
        let mut provider_storage = [addr_of!(PROVIDER_VTABLE) as usize];
        let mut subject = view(-88_000, provider_storage.as_mut_ptr().cast());
        unsafe { class_6280_set_position(addr_of_mut!(subject).cast(), -88_000, 1); }
        unsafe { assert_eq!(PROVIDER_CALL, Some(-88_000)); assert_eq!(RESOURCE_COUNT, 3); }
    }
}
