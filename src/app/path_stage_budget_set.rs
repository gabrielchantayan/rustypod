//! Sets a stage-progress budget from a filesystem path's size.
//!
//! Port: [`path_stage_budget_set`] — original: `FUN_080ac06c` @
//! **0x080ac06c** (**88 bytes**; **3 plain unconditional `bl` call sites,
//! 0 predicated `bl` forms**, independently decoded from `osos.dec`; the next
//! real function starts at 0x080ac0c4).
//!
//! It starts with a zero budget, probes whether `path_object` exists, and only
//! then asks the facade slot-+0x68 operation for its byte size. The stored
//! budget is that size divided by 1024, at the requested stage's word in the
//! lazy stage-progress tracker. The two facade operations remain their existing
//! seams: their target defaults call retailOS, while host tests replace them.
//! Deliberate deviation: `stage_progress_tracker_get` uses the crate singleton
//! cache instead of the retail global word; its returned raw allocation is cast
//! to the verified `StageProgressTracker` layout.

use crate::app::path_probe::{
    path_probe_via_facade, PATH_FACADE_SLOT_68_FROM_PATH_OBJECT,
};
use crate::app::singletons::stage_progress_tracker_get;
use crate::app::stage_progress::StageProgressTracker;
use crate::cxx::string_object::StringObject;

/// Writes the KiB-sized budget for `stage` after conditionally querying
/// `path_object` through the filesystem facade.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn path_stage_budget_set(stage: u32, path_object: *mut StringObject) {
    let mut budget_kib = 0;
    if path_probe_via_facade(path_object, 0) != 0 {
        let size_query = core::ptr::addr_of!(PATH_FACADE_SLOT_68_FROM_PATH_OBJECT).read_volatile();
        size_query(path_object, &mut budget_kib, 0);
        budget_kib >>= 10;
    }

    let tracker = stage_progress_tracker_get().cast::<StageProgressTracker>();
    core::ptr::addr_of_mut!((*tracker).stage_budgets)
        .cast::<u32>()
        .add(stage as usize)
        .write(budget_kib);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::app::path_probe::{
        FacadeFetch, FacadeObject, FacadeVtable, GuardConstruct, GuardDestroy, InterfaceGuard,
        PathFacadeSlot68FromPathObject, PathProbeQuery, FACADE_PATH_PROBE_SLOT_INDEX,
        FACADE_VTABLE_SLOTS, PATH_PROBE_FACADE_FETCH, PATH_PROBE_GUARD_CTOR,
        PATH_PROBE_GUARD_DTOR,
    };
    use crate::app::singletons::{SINGLETON_LOCK, STAGE_PROGRESS_TRACKER};
    use core::ptr;
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut TRACKER: [u32; 11] = [0; 11];
    static mut VTABLE: FacadeVtable = FacadeVtable { slots: [0; FACADE_VTABLE_SLOTS] };
    static mut FACADE: FacadeObject = FacadeObject { vtable: ptr::null() };

    unsafe extern "C" fn guard_ctor(guard: *mut InterfaceGuard, _: u32) -> *mut InterfaceGuard {
        guard
    }
    unsafe extern "C" fn guard_dtor(guard: *mut InterfaceGuard) -> *mut InterfaceGuard { guard }
    unsafe extern "C" fn fetch(_: *mut InterfaceGuard, _: u32) -> *mut FacadeObject {
        ptr::addr_of_mut!(FACADE)
    }
    unsafe extern "C" fn path_absent(_: *mut FacadeObject, _: *mut StringObject) -> u32 { 0 }
    unsafe extern "C" fn path_present(_: *mut FacadeObject, _: *mut StringObject) -> u32 { 1 }
    unsafe extern "C" fn report_size(_: *mut StringObject, out: *mut u32, _: u32) -> i32 {
        out.write(7 * 1024 + 1023);
        -1
    }

    #[test]
    fn stores_zero_for_an_absent_path_and_kib_for_a_present_path() {
        let _test = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _singleton = SINGLETON_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _probe = crate::app::path_probe::tests::PATH_PROBE_TEST_LOCK.lock()
            .unwrap_or_else(|e| e.into_inner());
        unsafe {
            let saved_tracker = ptr::read_volatile(ptr::addr_of!(STAGE_PROGRESS_TRACKER));
            let saved_ctor = ptr::read_volatile(ptr::addr_of!(PATH_PROBE_GUARD_CTOR));
            let saved_fetch = ptr::read_volatile(ptr::addr_of!(PATH_PROBE_FACADE_FETCH));
            let saved_dtor = ptr::read_volatile(ptr::addr_of!(PATH_PROBE_GUARD_DTOR));
            let saved_size = ptr::read_volatile(ptr::addr_of!(crate::app::path_probe::PATH_FACADE_SLOT_68_FROM_PATH_OBJECT));

            STAGE_PROGRESS_TRACKER = ptr::addr_of_mut!(TRACKER).cast();
            TRACKER = [0; 11];
            TRACKER[4..].fill(0xfeed_face);
            PATH_PROBE_GUARD_CTOR = guard_ctor as GuardConstruct;
            PATH_PROBE_FACADE_FETCH = fetch as FacadeFetch;
            PATH_PROBE_GUARD_DTOR = guard_dtor as GuardDestroy;
            VTABLE.slots[FACADE_PATH_PROBE_SLOT_INDEX] = path_absent as PathProbeQuery as usize;
            FACADE.vtable = ptr::addr_of!(VTABLE);
            crate::app::path_probe::PATH_FACADE_SLOT_68_FROM_PATH_OBJECT = report_size as PathFacadeSlot68FromPathObject;

            path_stage_budget_set(2, ptr::null_mut());
            assert_eq!(TRACKER[4 + 2], 0, "the absent-path default probe skips the size query");

            VTABLE.slots[FACADE_PATH_PROBE_SLOT_INDEX] = path_present as PathProbeQuery as usize;
            path_stage_budget_set(5, ptr::null_mut());
            assert_eq!(TRACKER[4 + 5], 7, "the size is floored from bytes to KiB");
            assert_eq!(TRACKER[4 + 1], 0xfeed_face, "only the requested stage word changes");

            STAGE_PROGRESS_TRACKER = saved_tracker;
            PATH_PROBE_GUARD_CTOR = saved_ctor;
            PATH_PROBE_FACADE_FETCH = saved_fetch;
            PATH_PROBE_GUARD_DTOR = saved_dtor;
            crate::app::path_probe::PATH_FACADE_SLOT_68_FROM_PATH_OBJECT = saved_size;
        }
    }
}
