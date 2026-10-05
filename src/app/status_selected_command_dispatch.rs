//! Status-selected command dispatch — `FUN_081cab4c` @ 0x081cab4c.
//! True extent: 68 bytes (60 code + 8 literal pool), ending at the next
//! function's push at 0x081cab90. Raw-word scan verifies two inbound plain
//! BL sites (0x081162f0, 0x081a5ca8), no predicated inbound BL; the body has
//! three plain BL instructions, no predicated BL, and a terminal B.
//!
//! Query whether the singleton's virtual status is three, obtain the command
//! dispatcher, and dispatch resource 0x0dad0dfa with command 0x0dad0dfc for
//! nonzero status or 0x0dad0dfb for zero, auxiliary argument zero. Return the
//! dispatched object unchanged. Ghidra incorrectly inlines the tail callee.
//! Deliberate deviations: none in this wrapper; existing callees retain their
//! documented constructor and host-seam limitations. LLVM may merge the two
//! mutually exclusive getter call sites into one; each path still calls once.

const STATUS_RESOURCE: u32 = 0x0dad_0dfa;

#[inline(always)]
fn command_for_status(status_is_three: u32) -> u32 {
    STATUS_RESOURCE + if status_is_three != 0 { 2 } else { 1 }
}

/// Dispatch the status-dependent command and return its object.
///
/// # Safety
/// The existing singleton constructors, virtual method, resource resolver,
/// and command-dispatch dependencies must be initialized for retailOS.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn status_selected_command_dispatch() -> *mut u8 {
    let status = crate::util::vtable_slot_0x5c_result_is_three::vtable_slot_0x5c_result_is_three();
    let dispatcher = crate::app::singletons::command_dispatcher_get();
    crate::app::command_dispatch::command_dispatch_by_resource(
        dispatcher, STATUS_RESOURCE, command_for_status(status), 0,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_selects_adjacent_command_and_any_nonzero_selects_second() {
        assert_eq!(command_for_status(0), 0x0dad_0dfb);
        for status in [1, 2, 3, 0x8000_0000, u32::MAX] {
            assert_eq!(command_for_status(status), 0x0dad_0dfc);
        }
    }
}
