//! Controller resource-list replacement — `FUN_0819f330` @ 0x0819f330.
//! True extent: 212 bytes through 0x0819f404 (204 code, eight literal bytes).
//! Raw whole-image scan: two incoming plain BLs, zero predicated BLs;
//! body: five plain BLs, zero predicated BLs, one BLX and one BLXNE.
//!
//! Fetch the application provider even on the unchanged path. If the current
//! list's resource-data word equals the request, return zero. Otherwise notify
//! the optional view with (0, 1), destroy and clear the reloaded current list,
//! allocate and construct a 36-byte list, publish it, then run the resident
//! update body with (controller, view, 1). A zero request uses controller+44
//! and tag MEIS (0x5349454d); nonzero requests use METI (0x4954454d).
//! Deliberate deviations: native pointer fields widen on hosts; target offsets
//! are asserted. The unrecovered update body remains an address-based target
//! seam, not a guessed identity; host execution requires explicit injection.

use crate::app::application_resource_provider::application_resource_provider;
use crate::heap::veneers::operator_new;
use crate::util::resource_list::{load_resource_list, ResourceList};

#[repr(C)]
pub struct ResourceListController {
    pub opaque_prefix: [u32; 6],
    pub current_list: *mut ResourceList,
    pub opaque_middle: [u32; 4],
    pub default_resource: u32,
}

#[cfg(target_os = "none")]
const _: () = {
    assert!(core::mem::offset_of!(ResourceListController, current_list) == 24);
    assert!(core::mem::offset_of!(ResourceListController, default_resource) == 44);
};

type Update = unsafe extern "C" fn(*mut ResourceListController, *mut u8, u32);
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_update(_: *mut ResourceListController, _: *mut u8, _: u32) {
    panic!("controller_resource_list_replace requires resident update 0x0819ed10")
}
#[cfg(not(target_os = "none"))]
pub static mut CONTROLLER_RESOURCE_LIST_UPDATE: Update = missing_update;

#[inline(always)]
unsafe fn replace_with(
    controller: *mut ResourceListController,
    resource: u32,
    view: *mut u8,
    provider: impl FnOnce() -> u32,
    notify: impl FnOnce(*mut u8, u32, u32),
    destroy: impl FnOnce(*mut ResourceList),
    allocate: impl FnOnce() -> *mut ResourceList,
    create: impl FnOnce(*mut ResourceList, u32, u32, u32) -> *mut ResourceList,
    update: impl FnOnce(*mut ResourceListController, *mut u8, u32),
) -> u32 {
    let provider = provider();
    let current = (*controller).current_list;
    if !current.is_null() && (*current).resource_data == resource { return 0; }
    if !view.is_null() { notify(view, 0, 1); }
    let current = (*controller).current_list;
    if !current.is_null() {
        destroy(current);
        (*controller).current_list = core::ptr::null_mut();
    }
    let allocation = allocate();
    let (data, tag) = if resource == 0 {
        ((*controller).default_resource, 0x5349_454d)
    } else {
        (resource, 0x4954_454d)
    };
    (*controller).current_list = create(allocation, provider, data, tag);
    update(controller, view, 1);
    1
}

/// Replace a controller's resource list if its resource-data word differs.
///
/// # Safety
/// Controller, current list, optional view and their target-word vtables must
/// be valid. The allocation and resident update contracts must be satisfied;
/// stock does not guard a failed allocation.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn controller_resource_list_replace(
    controller: *mut ResourceListController, resource: u32, view: *mut u8,
) -> u32 {
    replace_with(controller, resource, view,
        || application_resource_provider() as usize as u32,
        |view, zero, one| {
            let table = *(view.cast::<u32>()) as usize as *const u32;
            let call: unsafe extern "C" fn(*mut u8, u32, u32) =
                core::mem::transmute(*table.add(100) as usize);
            call(view, zero, one);
        },
        |list| {
            let table = (*list).vtable as usize as *const u32;
            let call: unsafe extern "C" fn(*mut ResourceList) =
                core::mem::transmute(*table.add(1) as usize);
            call(list);
        },
        || operator_new(36).cast(),
        |allocation, provider, data, tag| {
            load_resource_list(allocation, provider, data, tag, 0)
        },
        |controller, view, one| {
            #[cfg(target_os = "none")]
            let update: Update = core::mem::transmute(0x0819_ed10usize);
            #[cfg(not(target_os = "none"))]
            let update = CONTROLLER_RESOURCE_LIST_UPDATE;
            update(controller, view, one);
        })
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::cell::RefCell;
    use std::vec::Vec;

    fn list(data: u32) -> ResourceList {
        ResourceList { vtable: 0, provider: 0, parser: 0, resource_data: data,
            state: 0, vector_words: [0; 3], loading: 0, first_flag: 0,
            second_flag: 0, unused_23: 0 }
    }

    #[test]
    fn unchanged_including_zero_still_fetches_provider() {
        for data in [0, 7, u32::MAX] {
            let mut old = list(data);
            let mut owner = ResourceListController { opaque_prefix: [0; 6],
                current_list: &mut old, opaque_middle: [0; 4], default_resource: 99 };
            let fetched = std::cell::Cell::new(false);
            let result = unsafe { replace_with(&mut owner, data, core::ptr::null_mut(),
                || { fetched.set(true); 42 }, |_, _, _| panic!("notify"), |_| panic!("destroy"),
                || panic!("allocate"), |_, _, _, _| panic!("construct"), |_, _, _| panic!("update")) };
            assert_eq!(result, 0);
            assert!(fetched.get());
            assert_eq!(owner.current_list, &mut old as *mut _);
        }
    }

    #[test]
    fn replacement_order_defaults_and_callback_mutation() {
        for request in [0, 7, u32::MAX] {
            for has_view in [false, true] {
                for has_old in [false, true] {
                    let mut old = list(3);
                    let mut substituted = list(4);
                    let mut new = list(0);
                    let new_ptr = &mut new as *mut _;
                    let substituted_ptr = &mut substituted as *mut _;
                    let mut owner = ResourceListController { opaque_prefix: [0; 6],
                        current_list: if has_old { &mut old } else { core::ptr::null_mut() },
                        opaque_middle: [0; 4], default_resource: 99 };
                    let owner_ptr = &mut owner as *mut ResourceListController;
                    let mut view_word = 0u32;
                    let view = if has_view { (&mut view_word as *mut u32).cast() }
                        else { core::ptr::null_mut() };
                    let events = RefCell::new(Vec::new());
                    let result = unsafe { replace_with(owner_ptr, request, view,
                        || { events.borrow_mut().push(0); 42 },
                        |v, z, o| {
                            assert_eq!((v, z, o), (view, 0, 1));
                            events.borrow_mut().push(1);
                            (*owner_ptr).current_list = substituted_ptr;
                        },
                        |p| {
                            assert_eq!(p, if has_view { substituted_ptr } else { &mut old });
                            events.borrow_mut().push(2);
                        },
                        || {
                            assert!((*owner_ptr).current_list.is_null());
                            (*owner_ptr).default_resource = 101;
                            new_ptr
                        },
                        |allocation, p, d, t| {
                            assert_eq!(allocation, new_ptr);
                            assert!((*owner_ptr).current_list.is_null());
                            assert_eq!((p, d, t), (42, if request == 0 { 101 } else { request },
                                if request == 0 { 0x5349_454d } else { 0x4954_454d }));
                            events.borrow_mut().push(3); new_ptr
                        },
                        |c, v, o| {
                            assert_eq!((c, v, o), (owner_ptr, view, 1));
                            assert_eq!((*c).current_list, new_ptr);
                            events.borrow_mut().push(4);
                        }) };
                    assert_eq!(result, 1);
                    let mut expected = std::vec![0];
                    if has_view { expected.push(1); }
                    if has_view || has_old { expected.push(2); }
                    expected.extend([3, 4]);
                    assert_eq!(*events.borrow(), expected);
                }
            }
        }
    }
}
