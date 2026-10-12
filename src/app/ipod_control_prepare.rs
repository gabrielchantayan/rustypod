//! Prepare the control directory and consume the first-time marker request.
//!
//! `FUN_08047454` @ **0x08047454**: true extent **296 bytes** through
//! 0x0804757c (216 code bytes and 80 string/literal bytes). Raw aligned ARM
//! decoding finds **2 incoming plain BLs, 0 predicated**, and **9 outgoing
//! plain BLs, 1 predicated**. Callers are 0x080588e0 and 0x0806e4c8.
//!
//! Query `iPod_Control`; statuses 0 and 13 trigger facade slot 0x80 with
//! value 1. Preserve that result unless the byte at 0x089cb190 is nonzero.
//! In that case query `iPod_Control\\iTunes\\`, conditionally apply the same
//! operation to the ROOT (not the queried subdirectory), construct/open the
//! firsttime marker, clear the request before cleanup, and return zero even
//! when either directory operation failed.
//!
//! Deliberate deviations: typed StringObject storage widens on hosts; the
//! base-vtable literal uses STRING_OBJECT_VTABLE. The addon remains an aligned
//! 84-byte target object. Its existing Rust constructor/destructor have inert
//! helper defaults, so their verified resident addresses are retained here;
//! this function does not replace those incomplete ports or guess helpers.

use core::mem::MaybeUninit;
use crate::app::path_component_query::path_component_query;
use crate::app::path_object_construct::path_object_construct_from_string_object;
use crate::app::path_probe::path_facade_slot_80_from_cstr;
use crate::app::string_owner_init::string_owner_embedded_init;
use crate::cxx::string_object::{
    string_object_destroy_veneer, string_object_release_payload, StringObject,
    STRING_OBJECT_VTABLE,
};

const CONTROL: &[u8] = b"iPod_Control\0";
const ITUNES: &[u8] = b"iPod_Control\\iTunes\\\0";
const FIRSTTIME: &[u8] = b"iPod_Control\\iTunes\\firsttime\0";

// The flag is sampled only after the root query/create, and cleared between
// marker construction and destruction. Separate phases preserve that ordering.
unsafe fn prepare_with(
    request: *mut u8,
    mut query: impl FnMut(*const u8) -> u32,
    mut create: impl FnMut(*const u8) -> u32,
    initialize_marker: impl FnOnce(),
    finish_marker: impl FnOnce(),
) -> u32 {
    let mut status = query(CONTROL.as_ptr());
    if status == 0 || status == 13 {
        status = create(CONTROL.as_ptr());
    }
    if request.read_volatile() != 0 {
        let nested_status = query(ITUNES.as_ptr());
        if nested_status == 0 || nested_status == 13 {
            create(CONTROL.as_ptr());
        }
        initialize_marker();
        request.write_volatile(0);
        finish_marker();
        status = 0;
    }
    status
}

/// Prepare iPod_Control and optionally create the firsttime marker.
///
/// # Safety
/// Requires the retailOS resident routines and global state at their original
/// load addresses. The caller must provide the firmware's normal execution
/// context; this zero-argument firmware entry is not callable on a host.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ipod_control_prepare() -> u32 {
    let mut temporary = MaybeUninit::<StringObject>::uninit();
    let mut path = MaybeUninit::<StringObject>::uninit();
    let temporary = temporary.as_mut_ptr();
    let path = path.as_mut_ptr();
    let mut addon = MaybeUninit::<[u32; 21]>::uninit();
    let addon = addon.as_mut_ptr().cast::<u8>();
    let construct: unsafe extern "C" fn(*mut u8, *const u8, u32, u32, u32, u32, u32) -> *mut u8 =
        core::mem::transmute(0x0827_8e8cusize);
    let destroy: unsafe extern "C" fn(*mut u8) -> *mut u8 =
        core::mem::transmute(0x0827_8f60usize);
    prepare_with(
        0x089c_b190 as *mut u8,
        |path| path_component_query(path, 0),
        |path| path_facade_slot_80_from_cstr(path, 1, 0),
        || {
            let source = string_owner_embedded_init(temporary, FIRSTTIME.as_ptr());
            path_object_construct_from_string_object(path, source);
            (*temporary).vtable = &STRING_OBJECT_VTABLE;
            string_object_release_payload(temporary);
            construct(addon, path.cast(), 0, 0, 0x400, 1, 0);
        },
        || {
            destroy(addon);
            string_object_destroy_veneer(path);
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;

    #[test]
    fn root_status_precedence_without_request() {
        for query_status in [0, 13, 1, 12, 14, u32::MAX] {
            for create_status in [0, 13, 27, u32::MAX] {
                let mut flag = 0;
                let result = unsafe {
                    prepare_with(&mut flag, |_| query_status, |_| create_status,
                        || panic!("no marker requested"), || panic!("no marker cleanup"))
                };
                assert_eq!(result, if query_status == 0 || query_status == 13 {
                    create_status
                } else { query_status });
                assert_eq!(flag, 0);
            }
        }
    }

    #[test]
    fn marker_overrides_errors_and_clears_before_cleanup() {
        for root_status in [0, 13, 27] {
            for nested_status in [0, 13, 27] {
                for requested in [1, 255] {
                    let mut flag = requested;
                    let request = &mut flag as *mut u8;
                    let root_updates = Cell::new(0);
                    let marker_exists = Cell::new(false);
                    let cleaned = Cell::new(false);
                    let result = unsafe {
                        prepare_with(request,
                            |path| if path == CONTROL.as_ptr() { root_status } else {
                                assert_eq!(path, ITUNES.as_ptr());
                                nested_status
                            },
                            |path| {
                                // The nested query intentionally updates the root again.
                                assert_eq!(path, CONTROL.as_ptr());
                                root_updates.set(root_updates.get() + 1);
                                27
                            },
                            || {
                                assert_eq!(*request, requested);
                                marker_exists.set(true);
                            },
                            || {
                                assert_eq!(*request, 0);
                                assert!(marker_exists.get());
                                cleaned.set(true);
                            })
                    };
                    assert_eq!(result, 0);
                    assert_eq!(flag, 0);
                    assert!(marker_exists.get() && cleaned.get());
                    assert_eq!(root_updates.get(),
                        u32::from(root_status == 0 || root_status == 13)
                        + u32::from(nested_status == 0 || nested_status == 13));
                }
            }
        }
    }

    #[test]
    fn request_is_sampled_after_root_operation() {
        let mut flag = 0u8;
        let request = &mut flag as *mut u8;
        let marked = Cell::new(false);
        let result = unsafe {
            prepare_with(request, |_| 13, |_| { *request = 1; 77 },
                || marked.set(true), || assert_eq!(*request, 0))
        };
        assert_eq!(result, 0);
        assert!(marked.get());
    }
}
