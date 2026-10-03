//! `object_deactivate` — `FUN_08237174` at load address `0x08237174`.
//! True size: 52 bytes (`0x08237174..0x082371a8`); the next entry is
//! `bx lr`. Raw A32 decoding verifies two inbound plain BLs (0x0823714c,
//! 0x08237374), zero predicated inbound BLs, three outbound plain BLs,
//! zero predicated outbound BLs, and one indirect BLX at 0x08237190.
//!
//! Clear byte +0x70, invoke vtable slot +0xd4 with (INT_MAX, 0), fetch
//! the record manager, process its secondary records via 0x081c88b8,
//! then release the global object via 0x08153d78. Ignore operation results
//! and return zero. Both callers are cleanup paths, including a destructor.
//!
//! Deliberate deviations: host operations replace firmware addresses and
//! target-width virtual dispatch. Firmware retains the original getter
//! (0x081c83b4, named record_manager_get), because the existing Rust getter's
//! zeroing constructor and inert destructor are not faithful on this path.
//! No firmware behavior changes; unported callees remain retail calls.

pub type DeactivateDispatch = unsafe extern "C" fn(*mut u8, u32, u32) -> u32;
pub type RecordManagerGet = unsafe extern "C" fn() -> *mut u8;
pub type ProcessSecondaryRecords = unsafe extern "C" fn(*mut u8) -> u32;
pub type ReleaseGlobalObject = unsafe extern "C" fn() -> u32;

#[derive(Clone, Copy)]
pub struct ObjectDeactivateOps {
    pub dispatch: DeactivateDispatch,
    pub manager_get: RecordManagerGet,
    pub process_secondary_records: ProcessSecondaryRecords,
    pub release_global_object: ReleaseGlobalObject,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_dispatch(_: *mut u8, _: u32, _: u32) -> u32 {
    panic!("install object-deactivation host operations before dispatch")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_manager() -> *mut u8 {
    panic!("install object-deactivation host operations before manager lookup")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_process(_: *mut u8) -> u32 {
    panic!("install object-deactivation host operations before processing")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_release() -> u32 {
    panic!("install object-deactivation host operations before release")
}

/// Host-only operations; replacement requires exclusive access to this port.
#[cfg(not(target_os = "none"))]
pub static mut OBJECT_DEACTIVATE_OPS: ObjectDeactivateOps = ObjectDeactivateOps {
    dispatch: missing_dispatch, manager_get: missing_manager,
    process_secondary_records: missing_process, release_global_object: missing_release,
};

#[cfg(target_os = "none")]
unsafe extern "C" fn dispatch_target(object: *mut u8, limit: u32, mode: u32) -> u32 {
    let vtable = object.cast::<u32>().read() as usize as *const u32;
    let dispatch: DeactivateDispatch = core::mem::transmute(vtable.add(0xd4 / 4).read() as usize);
    dispatch(object, limit, mode)
}

/// Deactivate an opaque retail object and perform its shared cleanup.
///
/// # Safety
/// `object` must have a writable byte at +0x70 and a valid target vtable
/// with callable slot +0xd4. Retail global state must be initialized as
/// required by the callees. Host builds require installed operations.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn object_deactivate(object: *mut u8) -> u32 {
    #[cfg(target_os = "none")]
    let ops = ObjectDeactivateOps {
        dispatch: dispatch_target,
        manager_get: core::mem::transmute(0x081c_83b4usize),
        process_secondary_records: core::mem::transmute(0x081c_88b8usize),
        release_global_object: core::mem::transmute(0x0815_3d78usize),
    };
    #[cfg(not(target_os = "none"))]
    let ops = core::ptr::addr_of!(OBJECT_DEACTIVATE_OPS).read();
    object.add(0x70).write(0);
    (ops.dispatch)(object, 0x7fff_ffff, 0);
    let manager = (ops.manager_get)();
    (ops.process_secondary_records)(manager);
    (ops.release_global_object)();
    0
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::cell::RefCell;

    struct State {
        object: *mut u8,
        manager: [u32; 0xcd8 / 4],
        stage: u32,
    }
    std::thread_local! {
        static STATE: RefCell<State> = RefCell::new(State {
            object: core::ptr::null_mut(), manager: [0; 0xcd8 / 4], stage: 0,
        });
    }
    unsafe extern "C" fn dispatch(object: *mut u8, limit: u32, mode: u32) -> u32 {
        STATE.with(|state| {
            let mut state = state.borrow_mut();
            assert_eq!(state.stage, 0);
            assert_eq!(object, state.object);
            assert_eq!(object.add(0x70).read(), 0);
            assert_eq!((limit, mode), (i32::MAX as u32, 0));
            // A real virtual operation may change the byte: do not clear it again.
            object.add(0x70).write(0x39);
            state.stage = 1;
        });
        u32::MAX
    }
    unsafe extern "C" fn manager_get() -> *mut u8 {
        STATE.with(|state| {
            let mut state = state.borrow_mut();
            assert_eq!(state.stage, 1);
            state.stage = 2;
            state.manager.as_mut_ptr().cast()
        })
    }
    unsafe extern "C" fn process(manager: *mut u8) -> u32 {
        STATE.with(|state| {
            let mut state = state.borrow_mut();
            assert_eq!(state.stage, 2);
            assert_eq!(manager, state.manager.as_mut_ptr().cast());
            manager.add(0xa0c).write(0);
            state.stage = 3;
        });
        1
    }
    unsafe extern "C" fn release() -> u32 {
        STATE.with(|state| {
            let mut state = state.borrow_mut();
            assert_eq!(state.stage, 3);
            assert_eq!(state.manager.as_ptr().cast::<u8>().add(0xa0c).read(), 0);
            state.stage = 4;
        });
        17
    }

    #[test]
    fn clears_every_flag_before_dispatch_and_finishes_despite_nonzero_results() {
        unsafe {
            let saved = core::ptr::addr_of!(OBJECT_DEACTIVATE_OPS).read();
            OBJECT_DEACTIVATE_OPS = ObjectDeactivateOps {
                dispatch, manager_get, process_secondary_records: process,
                release_global_object: release,
            };
            let mut object = [0xa5; 0x78];
            for flag in 0..=u8::MAX {
                object[0x70] = flag;
                STATE.with(|state| {
                    let mut state = state.borrow_mut();
                    state.object = object.as_mut_ptr();
                    state.stage = 0;
                    state.manager.as_mut_ptr().cast::<u8>().add(0xa0c).write(4);
                });
                assert_eq!(object_deactivate(object.as_mut_ptr()), 0);
                STATE.with(|state| assert_eq!(state.borrow().stage, 4));
                let mut expected = [0xa5; 0x78];
                expected[0x70] = 0x39;
                assert_eq!(object, expected);
            }
            OBJECT_DEACTIVATE_OPS = saved;
        }
    }
}
