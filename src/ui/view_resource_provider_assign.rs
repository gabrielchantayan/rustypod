//! retailOS view resource-provider assignment port.

use crate::app::resource_chain::ResourceProvider;
use crate::ui::view_base::{ViewBase, VIEW_BASE_RESOURCE_OPS};
#[cfg(test)]
use crate::ui::view_base::{ViewBaseResourceOps, DEFAULT_VIEW_BASE_RESOURCE_OPS};

/// view_resource_provider_assign — original `FUN_082722a0` @ **0x082722a0**.
///
/// Raw words establish the true 68-byte extent, `0x082722a0..0x082722e4`;
/// `mov r0,#0; bx lr` begins the next real function. It has one predicated
/// `blne` to resource_provider_detach_view (0x08124dbc), no plain `bl`, and
/// one predicated tail branch to resource_provider_attach_view (0x08124af4).
/// It returns early for an unchanged provider; otherwise it detaches a
/// non-NULL old provider, stores the replacement at target-word +0x14, and
/// attaches a non-NULL replacement. Deliberate deviation: Rust calls rather
/// than tail-branches to the shared provider-operation seam.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn view_resource_provider_assign(
    view: *mut ViewBase,
    replacement: *mut ResourceProvider,
) {
    let provider_slot = unsafe { view.cast::<u32>().add(5) };
    let current = unsafe { provider_slot.read_volatile() as usize as *mut ResourceProvider };
    if current == replacement {
        return;
    }
    if !current.is_null() {
        unsafe { (VIEW_BASE_RESOURCE_OPS.detach_view)(current, view, 0) };
    }
    unsafe { provider_slot.write_volatile(replacement as usize as u32) };
    if !replacement.is_null() {
        unsafe { (VIEW_BASE_RESOURCE_OPS.attach_view)(replacement, view) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, try_map_u32_slab};
    use crate::ui::view_base::VIEW_BASE_RESOURCE_OPS_TEST_LOCK;
    use core::ptr;

    static mut DETACH: Option<(*mut ResourceProvider, *mut ViewBase, u32)> = None;
    static mut ATTACH: Option<(*mut ResourceProvider, *mut ViewBase)> = None;

    unsafe extern "C" fn record_detach(provider: *mut ResourceProvider, view: *mut ViewBase, flags: u32) {
        unsafe { DETACH = Some((provider, view, flags)) };
    }

    unsafe extern "C" fn record_attach(provider: *mut ResourceProvider, view: *mut ViewBase) {
        unsafe { ATTACH = Some((provider, view)) };
    }

    #[test]
    fn replaces_detaches_and_attaches_target_width_provider() {
        let _guard = VIEW_BASE_RESOURCE_OPS_TEST_LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::VIEW_RESOURCE_PROVIDER_ASSIGN, 0x1000) else {
            return;
        };
        let view = slab.cast::<ViewBase>();
        let old = unsafe { slab.add(0x100).cast::<ResourceProvider>() };
        let replacement = unsafe { slab.add(0x200).cast::<ResourceProvider>() };
        unsafe {
            view.cast::<u32>().add(5).write(old as usize as u32);
            DETACH = None;
            ATTACH = None;
            VIEW_BASE_RESOURCE_OPS = ViewBaseResourceOps {
                attach_view: record_attach,
                detach_view: record_detach,
            };
            view_resource_provider_assign(view, replacement);
            assert_eq!(view.cast::<u32>().add(5).read(), replacement as usize as u32);
            assert_eq!(DETACH, Some((old, view, 0)));
            assert_eq!(ATTACH, Some((replacement, view)));

            DETACH = None;
            ATTACH = None;
            view_resource_provider_assign(view, replacement);
            assert_eq!(DETACH, None);
            assert_eq!(ATTACH, None);

            view_resource_provider_assign(view, ptr::null_mut());
            assert_eq!(view.cast::<u32>().add(5).read(), 0);
            assert_eq!(DETACH, Some((replacement, view, 0)));
            assert_eq!(ATTACH, None);
            VIEW_BASE_RESOURCE_OPS = DEFAULT_VIEW_BASE_RESOURCE_OPS;
        }
    }
}
