//! Reset the stage-progress tracker and select the fallback command view.
//!
//! Original `FUN_081143b4` at 0x081143b4: true extent 84 bytes through
//! 0x08114408 (80 code bytes plus the 0x0dad0de0 literal). Raw word decoding
//! finds two incoming plain BLs (0x08116430, 0x081164b8), zero predicated
//! incoming BLs, eight outgoing plain BLs, zero predicated outgoing BLs,
//! and a virtual tail BX through list slot +4.
//!
//! Reset the singleton tracker, dispatch disk-mode resource 0x8ca8, then
//! ask retailOS to display its current view if present. A nonzero answer
//! stops selection. Otherwise select controller history without a callback,
//! dispatch resource 0x0dad0ddf / command 0x0dad0de0 with aux zero, and hand
//! the result to the node-list singleton's virtual slot +4.
//!
//! Deliberate deviations: preserve r0 as usize rather than Ghidra's void;
//! use pointer-width vtable slots on hosts, four-byte slots on ARM. The
//! unidentified virtual method is not replaced by an invented callee. The
//! unported display-if-present helper uses a volatile dependency seam.

use crate::app::node_list::{NodeList, node_list_get};

pub type DisplayIfPresent = unsafe extern "C" fn() -> u32;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_display_if_present() -> u32 {
    let call: DisplayIfPresent = core::mem::transmute(0x0815_9108usize);
    call()
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_display_if_present() -> u32 {
    panic!("stage_progress_reset_and_select requires display-if-present 0x08159108")
}

/// 0x08159108 checks [0x089cc790 + 4], calls view_clear_flag_display when
/// nonzero, and returns exactly zero or one. No new identity for its view.
pub static mut DISPLAY_IF_PRESENT: DisplayIfPresent = firmware_display_if_present;

#[inline(always)]
fn select_unless_displayed(displayed: u32, select: impl FnOnce() -> usize) -> usize {
    if displayed != 0 { displayed as usize } else { select() }
}

#[inline(always)]
unsafe fn deliver_selection(list: *mut NodeList, selection: *mut u8) -> usize {
    // Word indexing works with both target and host pointer widths; the
    // existing NodeListVtable represents this slot as unresolved_04_8c[0].
    let method: unsafe extern "C" fn(*mut NodeList, *mut u8) -> usize =
        core::mem::transmute((*(*list).vtable).unresolved_04_8c[0]);
    method(list, selection)
}

/// Reset tracker state and display an existing view or select the fallback.
/// Address 0x081143b4; 84 bytes; two plain / zero predicated BL callers.
/// Caller must provide the initialized retailOS singleton environment.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn stage_progress_reset_and_select() -> usize {
    let tracker = crate::app::singletons::stage_progress_tracker_get();
    crate::app::stage_progress::stage_progress_tracker_ctor(tracker.cast());
    crate::app::disk_mode_resource_8ca8_dispatch::disk_mode_resource_8ca8_dispatch();
    let display = core::ptr::read_volatile(core::ptr::addr_of!(DISPLAY_IF_PRESENT));
    select_unless_displayed(display(), || {
        crate::app::controller_history_select::controller_history_select_without_callback();
        let dispatcher = crate::app::singletons::command_dispatcher_get();
        let selection = crate::app::command_dispatch::command_dispatch_by_resource(
            dispatcher, 0x0dad_0ddf, 0x0dad_0de0, 0,
        );
        deliver_selection(node_list_get(), selection)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::node_list::NodeListVtable;

    #[test]
    fn displayed_view_preserves_selection_and_return_word() {
        let mut current = 17;
        for displayed in [1, 0x8000_0000, u32::MAX] {
            assert_eq!(select_unless_displayed(displayed, || {
                current = 23;
                0
            }), displayed as usize);
            assert_eq!(current, 17);
        }
        assert_eq!(select_unless_displayed(0, || { current = 23; usize::MAX }), usize::MAX);
        assert_eq!(current, 23);
    }

    #[repr(C)]
    struct Fixture {
        list: NodeList,
        selection: *mut u8,
    }

    unsafe extern "C" fn install(list: *mut NodeList, selection: *mut u8) -> usize {
        let fixture = list.cast::<Fixture>();
        (*fixture).selection = selection;
        selection as usize
    }

    #[test]
    fn fallback_installs_null_and_nonnull_selection_through_slot_one() {
        unsafe {
            let mut vtable = NodeListVtable {
                complete_drain: unused_complete,
                unresolved_04_8c: [0; 35],
                advance: unused_advance,
                measure: unused_measure,
            };
            vtable.unresolved_04_8c[0] = install as *const () as usize;
            let mut fixture = core::mem::MaybeUninit::<Fixture>::zeroed();
            let fixture = fixture.as_mut_ptr();
            core::ptr::addr_of_mut!((*fixture).list.vtable).write(&vtable);
            let mut value = 7u8;
            for selection in [&mut value as *mut u8, core::ptr::null_mut()] {
                let result = select_unless_displayed(0, || deliver_selection(
                    core::ptr::addr_of_mut!((*fixture).list), selection,
                ));
                assert_eq!((*fixture).selection, selection);
                assert_eq!(result, selection as usize);
            }
        }
    }

    unsafe extern "C" fn unused_complete(_: *mut NodeList, _: *mut core::ffi::c_void, _: u8) { panic!("wrong slot") }
    unsafe extern "C" fn unused_advance(_: *mut NodeList, _: u32, _: u32, _: i32) { panic!("wrong slot") }
    unsafe extern "C" fn unused_measure(_: *mut NodeList, _: i32) -> i32 { panic!("wrong slot") }
}
