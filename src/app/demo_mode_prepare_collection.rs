//! Demo-mode collection preparation — FUN_08187c08 @ 0x08187c08.
//! True extent: 80 bytes through 0x08187c58 (76 code, 4-byte class literal).
//! Raw A32 scan: 2 plain inbound BLs, 0 predicated; body has 2 plain BLs,
//! 0 predicated BLs and a conditional tail B to timer_restart.
//! Nonzero defer clears +0x118 and restarts the embedded +0xec timer.
//! Otherwise cast the +0x28 object to class 0x7d80; on success run resident
//! collection processing with single_step=0 and completion byte +0x118,
//! then force that byte to 1. Failed casts leave it untouched.
//! Deviations: tail B is a Rust call; resident 0x081b9878 uses a fixed-address
//! BLX and a host-only seam. Its saved incoming r3 is unused scratch before
//! the first iterator call overwrites it; no fourth argument is invented.
//! ARM comparison: 19 stock instructions versus 37 Rust instructions (including
//! literals); LLVM expands timer_restart into timer_stop, the running-state
//! store at demo+0x10c and the TimerOps arm dispatch. Both branch paths retain
//! their offsets and completion ordering. No on-device execution performed.

use crate::app::registry::{object_cast_to_class, FrameworkObject};
use crate::drivers::timer::timer_restart;

pub type ProcessCollection = unsafe extern "C" fn(*mut u8, u32, *mut u8);
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_collection(_: *mut u8, _: u32, _: *mut u8) {
    panic!("demo collection processing requires resident firmware")
}
#[cfg(not(target_os = "none"))]
pub static mut DEMO_COLLECTION_PROCESS: ProcessCollection = missing_collection;

/// # Safety
/// `demo` is aligned and writable through +0x118, contains a valid target-width
/// object pointer at +0x28 and an initialized timer at +0xec. Resident collection
/// dependencies must be initialized for a successful cast.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn demo_mode_prepare_collection(demo: *mut u8, defer: u32) {
    let completed = demo.add(0x118);
    if defer != 0 {
        completed.write_volatile(0);
        timer_restart(demo.add(0xec));
        return;
    }
    let object = demo.add(0x28).cast::<u32>().read() as usize as *mut FrameworkObject;
    let collection = object_cast_to_class(object, 0x7d80);
    if collection.is_null() { return; }
    #[cfg(target_os = "none")]
    let process: ProcessCollection = core::mem::transmute(0x081b_9878usize);
    #[cfg(not(target_os = "none"))]
    let process = core::ptr::addr_of!(DEMO_COLLECTION_PROCESS).read_volatile();
    process(collection, 0, completed);
    completed.write_volatile(1);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::app::registry::FrameworkObjectVtable;
    use crate::drivers::timer::{self, TIMER_OPS, TIMER_PENDING_HEAD, TIMER_STATE_RUNNING};
    use crate::testing::{hints, try_map_u32_slab, note_missing_u32_fixture, TIMER_OPS_TEST_LOCK};
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::LazyLock;
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::DEMO_MODE_PREPARE_COLLECTION, 0x1000).map(|p| p as usize)
    });
    unsafe extern "C" fn cast(object: *mut FrameworkObject, id: u32) -> *mut u8 {
        assert_eq!(id, 0x7d80);
        if object.cast::<u8>().add(0x20).read() == 0 { core::ptr::null_mut() }
        else { object.cast() }
    }
    static VTABLE: FrameworkObjectVtable = FrameworkObjectVtable {
        unresolved_00: [0; 5], cast_to_class: cast,
    };
    unsafe extern "C" fn process(_: *mut u8, step: u32, completed: *mut u8) {
        assert_eq!(step, 0);
        // A resident write must not defeat the parent's final completion store.
        completed.write(0);
    }
    unsafe extern "C" fn validate(_: *mut u8) {}
    unsafe extern "C" fn notify(_: *const u32) {}
    unsafe extern "C" fn tick() -> u32 { 0xffff_ff00 }

    #[test]
    fn failed_cast_preserves_completion_success_sets_it_and_defer_restarts_timer() {
        let _lock = TIMER_OPS_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let Some(base) = *SLAB else { note_missing_u32_fixture("demo_mode_prepare_collection"); return; };
        unsafe {
            let demo = base as *mut u8;
            core::ptr::write_bytes(demo, 0, 0x1000);
            let object = demo.add(0x400).cast::<FrameworkObject>();
            object.write(FrameworkObject { vtable: &VTABLE });
            for pointer in [0, object as usize as u32] {
                demo.add(0x28).cast::<u32>().write(pointer);
                demo.add(0x118).write(0xa5);
                demo_mode_prepare_collection(demo, 0);
                assert_eq!(demo.add(0x118).read(), 0xa5);
            }
            object.cast::<u8>().add(0x20).write(1);
            let saved_process = addr_of!(DEMO_COLLECTION_PROCESS).read();
            addr_of_mut!(DEMO_COLLECTION_PROCESS).write(process);
            demo_mode_prepare_collection(demo, 0);
            addr_of_mut!(DEMO_COLLECTION_PROCESS).write(saved_process);
            assert_eq!(demo.add(0x118).read(), 1);
            let saved_ops = addr_of!(TIMER_OPS).read_volatile();
            let saved_head = addr_of!(TIMER_PENDING_HEAD).read_volatile();
            let mut ops = saved_ops;
            ops.trace_assert = validate; ops.trace_validate = validate;
            ops.notify_pending = notify; ops.tick = tick;
            ops.arm_timer = timer::timer_arm; ops.compare_deadlines = timer::timer_deadline_is_after;
            addr_of_mut!(TIMER_OPS).write_volatile(ops);
            let timer = demo.add(0xec).cast::<u32>();
            for defer in [1, 0x8000_0000, u32::MAX] {
                core::ptr::write_bytes(timer, 0, 11);
                timer.add(1).write(1);
                demo.add(0x118).write(0xa5);
                // Invalid object proves deferred path never dereferences +0x28.
                demo.add(0x28).cast::<u32>().write(u32::MAX);
                addr_of_mut!(TIMER_PENDING_HEAD).write_volatile(0);
                demo_mode_prepare_collection(demo, defer);
                assert_eq!(demo.add(0x118).read(), 0);
                assert_eq!(timer.add(8).read(), TIMER_STATE_RUNNING);
                assert_eq!(timer.add(2).read(), 744);
                assert_eq!(addr_of!(TIMER_PENDING_HEAD).read_volatile(), timer as usize as u32);
            }
            addr_of_mut!(TIMER_OPS).write_volatile(saved_ops);
            addr_of_mut!(TIMER_PENDING_HEAD).write_volatile(saved_head);
        }
    }
}
