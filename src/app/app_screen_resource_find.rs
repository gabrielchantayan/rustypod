//! `app_screen_resource_find` — original: `FUN_0812ff38` @ `0x0812ff38`.
//! True extent: **64 bytes**, `0x0812ff38..0x0812ff78`; the next entry
//! begins with its own push. Whole-image aligned A32 decoding verifies
//! **two inbound plain BLs** (0x0812fa68, 0x0812fb20), zero predicated BLs.
//! The body has three plain BLs and zero predicated BLs.
//!
//! Ignore the owner argument, obtain the app screen, read its cached position,
//! resolve `(kind, id, position)` through the selector-aware resource chain,
//! write the result unconditionally, and return 1 for non-NULL or 0 for NULL.
//! Deliberate deviations: native host pointers for the output and providers;
//! no target behavioral deviations, validation, or NULL guards.

use super::app_screen_cached_position::app_screen_cached_position;
use super::resource_chain::{resource_chain_find_with_selector, ResourceKind};
use super::singletons::app_screen_get;

/// # Safety
/// The screen singleton must be a valid selector-aware provider with its
/// cached position readable at +0x2c. `out` must be writable and aligned.
/// `owner` is ignored and may be NULL.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn app_screen_resource_find(
    _owner: *mut u8,
    kind: ResourceKind,
    id: u32,
    out: *mut *mut u8,
) -> u32 {
    let screen = app_screen_get();
    let position = app_screen_cached_position(screen);
    let found = resource_chain_find_with_selector(screen.cast(), kind, id, position);
    out.write(found);
    (!found.is_null()) as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::registry::FrameworkObject;
    use super::super::resource_chain::{ResourceProvider, ResourceSelectorProvider, ResourceSelectorProviderVTable};
    use super::super::singletons::{APP_SCREEN, APP_SCREEN_SIZE, SINGLETON_LOCK};
    use core::ptr;

    unsafe extern "C" fn cast(_: *mut FrameworkObject, _: u32) -> *mut u8 {
        panic!("the accepting head must not walk children")
    }

    unsafe extern "C" fn fallback(_: *mut ResourceProvider, _: ResourceKind, _: u32, _: *mut *mut u8) -> u32 {
        panic!("the accepting head must not fall back")
    }

    unsafe extern "C" fn find(
        provider: *mut ResourceSelectorProvider, kind: ResourceKind, id: u32,
        selector: u32, out: *mut *mut u8,
    ) -> u32 {
        out.write(if kind == ResourceKind::STRING && id == 7 && selector == 0 {
            (*provider).state_below_next[0]
        } else { ptr::null_mut() });
        0x8000_0000
    }

    #[test]
    fn resource_presence_normalizes_return_and_always_replaces_output() {
        let _lock = SINGLETON_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let vtable = ResourceSelectorProviderVTable {
            slots_below: [None; 5], cast_to_class: cast,
            slots_between: [None; 19], find: fallback,
            slots_between_find_and_selector: [None; 6], find_with_selector: find,
        };
        // Full-size, pointer-aligned screen. Cached position zero also leaves
        // the native-width host next pointer NULL (it overlaps +0x2c).
        let mut screen = [0usize; APP_SCREEN_SIZE / core::mem::size_of::<usize>()];
        let mut resource = 0x5au8;
        let resource_ptr = &mut resource as *mut u8;
        unsafe {
            let screen_ptr = screen.as_mut_ptr().cast::<u8>();
            screen_ptr.cast::<ResourceSelectorProvider>().write(ResourceSelectorProvider {
                vtable: &vtable, state_below_next: [resource_ptr, ptr::null_mut(), ptr::null_mut(), ptr::null_mut()],
                next: ptr::null_mut(),
            });
            let saved = APP_SCREEN;
            struct Restore(*mut u8);
            impl Drop for Restore {
                fn drop(&mut self) { unsafe { APP_SCREEN = self.0; } }
            }
            let _restore = Restore(saved);
            APP_SCREEN = screen_ptr;
            for (kind, id, expected) in [
                (ResourceKind::STRING, 7, resource_ptr),
                (ResourceKind::STRING, 8, ptr::null_mut()),
                (ResourceKind::BITMAP, 7, ptr::null_mut()),
            ] {
                let mut output = resource_ptr;
                let actual = app_screen_resource_find(ptr::null_mut(), kind, id, &mut output);
                assert_eq!(output, expected);
                assert_eq!(actual, if expected.is_null() { 0 } else { 1 });
            }
            assert_eq!(resource, 0x5a);
        }
    }
}
