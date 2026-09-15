//! `ui_element_refresh` — original: `FUN_0826f014` @ 0x0826f014 (140 bytes).
//!
//! Raw ARM establishes the true extent: `push {r4,r5,r6,lr}` begins at
//! 0x0826f014 and the tail `b 0x0826db38` is at 0x0826f09c; the distinct
//! next function opens at 0x0826f0a0. There are five direct `bl` call sites:
//! four unconditional and one predicated (`blxne r1`); no direct tail callers.
//!
//! # Algorithm
//!
//! A zero `reason` first tests the element's virtual +0x18 predicate; when it
//! succeeds, it invokes virtual +0x1c and asks the navigation manager to focus
//! the element. If its render context (+0x3c) owns this element (+0x78), it
//! sets that context suspended for reason 0 and clear for every other reason.
//! Finally, the element or its parent must have flag 0x10 before it tail-calls
//! the existing geometry-changed redraw helper.
//!
//! # Deliberate deviations
//!
//! The unported navigation-manager call at 0x081106a0 is retained as an
//! address-named seam: its complete manager semantics are not inferred here.
//! The stock tail branch is an ordinary call to the existing geometry-changed
//! seam, preserving side effects and returning the original element pointer.

#[cfg(test)]
extern crate std;

use crate::ui::render_context_suspend::render_context_set_suspended;
use crate::ui::set_geometry::{ViewBaseGeometryChanged, VIEW_BASE_GEOMETRY_CHANGED};

const RENDER_CONTEXT_OFFSET: usize = 0x3c;
const FLAGS_OFFSET: usize = 0x48;
const PARENT_OFFSET: usize = 0x34;
const CONTEXT_OWNER_OFFSET: usize = 0x78;
const NAVIGATION_MANAGER_FOCUS_ADDRESS: usize = 0x0811_06a0;

pub type NavigationManagerFocus = unsafe extern "C" fn(*mut u8) -> u32;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_navigation_manager_focus(element: *mut u8) -> u32 {
    core::mem::transmute::<usize, NavigationManagerFocus>(NAVIGATION_MANAGER_FOCUS_ADDRESS)(element)
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_navigation_manager_focus(_element: *mut u8) -> u32 { 0 }

#[cfg(target_os = "none")]
static mut NAVIGATION_MANAGER_FOCUS: NavigationManagerFocus = firmware_navigation_manager_focus;
#[cfg(not(target_os = "none"))]
static mut NAVIGATION_MANAGER_FOCUS: NavigationManagerFocus = missing_navigation_manager_focus;

#[inline(always)]
unsafe fn target_word(base: *mut u8, offset: usize) -> u32 {
    base.add(offset).cast::<u32>().read_unaligned()
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn zero_reason_navigation(element: *mut u8) {
    let vtable = target_word(element, 0) as usize as *const u32;
    let predicate: unsafe extern "C" fn(*mut u8) -> u32 = core::mem::transmute(vtable.add(6).read());
    if predicate(element) != 0 && *element.add(12) == 2 {
        let release: unsafe extern "C" fn(*mut u8) = core::mem::transmute(vtable.add(7).read());
        release(element);
        NAVIGATION_MANAGER_FOCUS(element);
    }
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn zero_reason_navigation(_element: *mut u8) {}

/// Refreshes the UI element's navigation and redraw state. `element` must be
/// a valid retailOS UI-element layout; there is deliberately no NULL guard.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ui_element_refresh(element: *mut u8, reason: u32) -> *mut u8 {
    if reason == 0 {
        zero_reason_navigation(element);
    }

    let context = target_word(element, RENDER_CONTEXT_OFFSET) as usize as *mut u8;
    if !context.is_null() && target_word(context, CONTEXT_OWNER_OFFSET) as usize == element as usize {
        render_context_set_suspended(context, u32::from(reason == 0));
    }

    let parent = target_word(element, PARENT_OFFSET) as usize as *mut u8;
    if target_word(element, FLAGS_OFFSET) & 0x10 == 0
        && (parent.is_null() || target_word(parent, FLAGS_OFFSET) & 0x10 == 0) {
        return element;
    }
    let redraw: ViewBaseGeometryChanged = VIEW_BASE_GEOMETRY_CHANGED;
    redraw(element.cast());
    element
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refresh_returns_element_when_no_redraw_flag_is_set() {
        let Some(element) = crate::testing::try_map_u32_slab(
            crate::testing::hints::UI_ELEMENT_REFRESH, 0x200,
        ) else {
            crate::testing::note_missing_u32_fixture("ui/element_refresh");
            return;
        };
        unsafe {
            assert_eq!(ui_element_refresh(element, 1), element);
            element.add(FLAGS_OFFSET).cast::<u32>().write_unaligned(0x10);
            assert_eq!(ui_element_refresh(element, 1), element);
        }
    }
}
