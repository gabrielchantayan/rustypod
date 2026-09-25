//! Stops one event-handler source child and retires lower-ranked active children.
//!
//! Port: [`event_handler_source_child_stop`] — original: `FUN_0800796c` @
//! `0x0800796c` (**196 bytes; 10 plain `bl` instructions and one predicated
//! `blne`, binary-verified from `osos.dec`; no tail call**). The next real
//! function starts at `0x08007a30`.
//!
//! ## Algorithm
//!
//! Ask the child to begin stopping, complete that request, and record a
//! nonzero result in the source's pending transition state. Configure its
//! 8-second stop operation. If it remains enabled, decrement the source's
//! active-child count, capture its rank, finish it, then finish every enabled
//! child in the source's eight-word child table with a strictly greater rank.
//!
//! ## Deliberate deviations
//!
//! The child implementation and remaining retail veneers are not independently
//! identified. Target builds retain direct calls to their verified retailOS
//! addresses; the ported child-rank veneer reads the decoded rank halfword
//! directly on host builds.

use crate::kernel::thunks::{event_handler_source_child_enabled, event_handler_source_child_rank};

const SOURCE_ACTIVE_CHILD_COUNT_OFFSET: usize = 0x50;
const SOURCE_CHILD_COUNT: usize = 8;

type ChildResult = unsafe extern "C" fn(*mut u8) -> u32;
type ChildAction = unsafe extern "C" fn(*mut u8);
type SourceTransition = unsafe extern "C" fn(*mut u8, u32, u32, u32);
type ChildConfigure = unsafe extern "C" fn(*mut u8, u32, u32, u32);

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_child_stop_begin(child: *mut u8) -> u32 {
    core::mem::transmute::<usize, ChildResult>(0x0800_3970)(child)
}
#[cfg(target_os = "none")]
unsafe extern "C" fn retail_child_stop_complete(child: *mut u8) { core::mem::transmute::<usize, ChildAction>(0x0800_3978)(child) }
#[cfg(target_os = "none")]
unsafe extern "C" fn retail_source_transition(source: *mut u8, operation: u32, result: u32, context: u32) { core::mem::transmute::<usize, SourceTransition>(0x0800_7c04)(source, operation, result, context) }
#[cfg(target_os = "none")]
unsafe extern "C" fn retail_child_clear(child: *mut u8) { core::mem::transmute::<usize, unsafe extern "C" fn(*mut u8, u32)>(0x0800_3980)(child, 0) }
#[cfg(target_os = "none")]
unsafe extern "C" fn retail_child_configure(child: *mut u8, duration: u32, count: u32, mode: u32) { core::mem::transmute::<usize, ChildConfigure>(0x0800_3988)(child, duration, count, mode) }
#[cfg(target_os = "none")]
unsafe extern "C" fn retail_child_finish(child: *mut u8) { core::mem::transmute::<usize, ChildAction>(0x0800_3968)(child) }
#[cfg(target_os = "none")]
unsafe extern "C" fn retail_child_retire(child: *mut u8) { core::mem::transmute::<usize, ChildAction>(0x0800_3990)(child) }

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_result(_: *mut u8) -> u32 { 0 }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_action(_: *mut u8) {}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_transition(_: *mut u8, _: u32, _: u32, _: u32) {}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_configure(_: *mut u8, _: u32, _: u32, _: u32) {}

static mut CHILD_STOP_BEGIN: ChildResult = {
    #[cfg(target_os = "none")] { retail_child_stop_begin }
    #[cfg(not(target_os = "none"))] { host_result }
};
static mut CHILD_STOP_COMPLETE: ChildAction = {
    #[cfg(target_os = "none")] { retail_child_stop_complete }
    #[cfg(not(target_os = "none"))] { host_action }
};
static mut SOURCE_TRANSITION: SourceTransition = {
    #[cfg(target_os = "none")] { retail_source_transition }
    #[cfg(not(target_os = "none"))] { host_transition }
};
static mut CHILD_CLEAR: ChildAction = {
    #[cfg(target_os = "none")] { retail_child_clear }
    #[cfg(not(target_os = "none"))] { host_action }
};
static mut CHILD_CONFIGURE: ChildConfigure = {
    #[cfg(target_os = "none")] { retail_child_configure }
    #[cfg(not(target_os = "none"))] { host_configure }
};
static mut CHILD_FINISH: ChildAction = {
    #[cfg(target_os = "none")] { retail_child_finish }
    #[cfg(not(target_os = "none"))] { host_action }
};
static mut CHILD_RETIRE: ChildAction = {
    #[cfg(target_os = "none")] { retail_child_retire }
    #[cfg(not(target_os = "none"))] { host_action }
};

/// Stops `child`, then retires enabled source children with a greater rank.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.event_handler_source_child_stop")]
#[inline(never)]
pub unsafe extern "C" fn event_handler_source_child_stop(source: *mut u8, child: *mut u8) {
    let result = core::ptr::read_volatile(core::ptr::addr_of!(CHILD_STOP_BEGIN))(child);
    core::ptr::read_volatile(core::ptr::addr_of!(CHILD_STOP_COMPLETE))(child);
    if result != 0 {
        core::ptr::read_volatile(core::ptr::addr_of!(SOURCE_TRANSITION))(source, 0, result, 0);
        core::ptr::read_volatile(core::ptr::addr_of!(CHILD_CLEAR))(child);
    }
    core::ptr::read_volatile(core::ptr::addr_of!(CHILD_CONFIGURE))(child, 8000, 8, 1);
    if event_handler_source_child_enabled(child) == 0 { return; }
    let count = source.add(SOURCE_ACTIVE_CHILD_COUNT_OFFSET) as *mut u16;
    core::ptr::write_volatile(count, core::ptr::read_volatile(count).wrapping_sub(1));
    let rank = event_handler_source_child_rank(child);
    core::ptr::read_volatile(core::ptr::addr_of!(CHILD_FINISH))(child);
    let children = source.cast::<*mut u8>();
    for index in 0..SOURCE_CHILD_COUNT {
        let other = core::ptr::read_volatile(children.add(index));
        if rank < event_handler_source_child_rank(other)
            && event_handler_source_child_enabled(other) != 0 {
            core::ptr::read_volatile(core::ptr::addr_of!(CHILD_RETIRE))(other);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_child_only_runs_the_stop_setup() {
        let mut source = [0u32; 32];
        let mut child = [0u8; 0x6a];
        unsafe { event_handler_source_child_stop(source.as_mut_ptr().cast(), child.as_mut_ptr()); }
        assert_eq!(source[0x50 / 4], 0);
    }
}
