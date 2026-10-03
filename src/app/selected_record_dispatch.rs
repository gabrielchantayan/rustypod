//! Selected-record dispatch — `FUN_0826a4d4` @ 0x0826a4d4.
//! True extent: 96 bytes, [0x0826a4d4, 0x0826a534); the next independently
//! called function begins with push {r4-r9,lr}. Raw words contain three plain
//! outbound BLs, zero predicated BLs; two plain inbound BLs, zero predicated.
//! Increment the dispatch counter with wrapping arithmetic, build a discarded
//! callback result from a snapshot of the record identifier, dispatch the record
//! through the owner's collection, then append its freshly reread identifier.
//! Deliberate deviations: reuse the Rust callback_result_build port; retain
//! resident calls at 0x082686e0 (collection virtual dispatch) and 0x083e7140
//! (two-word vector append). These are structural identities, not class names.
//! Host operations replace resident code; target pointer fields remain u32.

use crate::util::callback_result_build::{callback_result_build, CallbackResult};

type BuildResult = unsafe extern "C" fn(*mut CallbackResult, *mut u8, *const u32);
type DispatchRecord = unsafe extern "C" fn(*mut u8, *mut u32, *mut u32);
type AppendIdentifier = unsafe extern "C" fn(*mut u32, *const u32);

#[derive(Clone, Copy)]
pub struct SelectedRecordDispatchOps {
    pub build_result: BuildResult,
    pub dispatch_record: DispatchRecord,
    pub append_identifier: AppendIdentifier,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_dispatch(_: *mut u8, _: *mut u32, _: *mut u32) {
    panic!("install selected-record collection dispatch")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_append(_: *mut u32, _: *const u32) {
    panic!("install selected-record identifier append")
}
#[cfg(not(target_os = "none"))]
pub static mut SELECTED_RECORD_DISPATCH_OPS: SelectedRecordDispatchOps = SelectedRecordDispatchOps {
    build_result: callback_result_build,
    dispatch_record: missing_dispatch,
    append_identifier: missing_append,
};

/// # Safety
/// `owner` is aligned, writable storage through target offset +0x5b; `record`
/// has four aligned readable words and satisfies the resident dispatch contract.
/// Owner +4/+0x48 are valid target pointers; +0x3c/+0x50 are resident vectors.
/// On hosts, installed operations must satisfy those same member contracts.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn selected_record_dispatch(owner: *mut u32, record: *mut u32) {
    #[cfg(target_os = "none")]
    let ops = SelectedRecordDispatchOps {
        build_result: callback_result_build,
        dispatch_record: core::mem::transmute(0x0826_86e0usize),
        append_identifier: core::mem::transmute(0x083e_7140usize),
    };
    #[cfg(not(target_os = "none"))]
    let ops = core::ptr::addr_of!(SELECTED_RECORD_DISPATCH_OPS).read();
    dispatch(owner, record, ops);
}

unsafe fn dispatch(owner: *mut u32, record: *mut u32, ops: SelectedRecordDispatchOps) {
    owner.add(6).write(owner.add(6).read().wrapping_add(1));
    let before = [record.add(2).read(), record.add(3).read()];
    let mut result = core::mem::MaybeUninit::<CallbackResult>::uninit();
    (ops.build_result)(result.as_mut_ptr(), owner.add(18).read() as usize as *mut u8, before.as_ptr());
    (ops.dispatch_record)(owner.add(1).read() as usize as *mut u8, record, owner.add(20));
    let after = [record.add(2).read(), record.add(3).read()];
    (ops.append_identifier)(owner.add(15), after.as_ptr());
}

#[cfg(test)]
mod tests {
    use super::*;

    // Model a resident callback mutating the owner and record through its context.
    // Native pointers live only in the test harness, never in target word fields.
    static LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    static mut OWNER: *mut u32 = core::ptr::null_mut();
    static mut RECORD: *mut u32 = core::ptr::null_mut();

    unsafe extern "C" fn build(_: *mut CallbackResult, _: *mut u8, input: *const u32) {
        assert_eq!(OWNER.add(6).read(), 0);
        assert_eq!([input.read(), input.add(1).read()], [0xffff_ffff, 0x8000_0000]);
        RECORD.add(2).write(17);
        OWNER.add(1).write(0x1234);
    }
    unsafe extern "C" fn dispatch_record(collection: *mut u8, record: *mut u32, _: *mut u32) {
        assert_eq!(collection as usize, 0x1234);
        assert_eq!(record.add(2).read(), 17);
        record.add(2).write(0);
        record.add(3).write(0xffff_ffff);
    }
    unsafe extern "C" fn append(vector: *mut u32, input: *const u32) {
        // A concrete vector fast-path model: write both words and advance its end.
        vector.write(input.read());
        vector.add(1).write(input.add(1).read());
        vector.add(2).write(vector.add(2).read().wrapping_add(8));
    }

    #[test]
    fn wrapping_counter_and_mutating_callbacks_preserve_snapshot_order() {
        let _lock = LOCK.lock();
        let mut owner = [0x5555_5555u32; 24];
        let mut record = [0, 0, 0xffff_ffff, 0x8000_0000];
        owner[6] = u32::MAX;
        owner[17] = 0xffff_fff8;
        unsafe {
            OWNER = owner.as_mut_ptr();
            RECORD = record.as_mut_ptr();
            dispatch(OWNER, RECORD, SelectedRecordDispatchOps {
                build_result: build, dispatch_record, append_identifier: append,
            });
            OWNER = core::ptr::null_mut();
            RECORD = core::ptr::null_mut();
        }
        assert_eq!(owner[6], 0);
        assert_eq!(&owner[15..18], &[0, u32::MAX, 0]);
        for index in [0, 2, 3, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 18, 19, 20, 21, 22, 23] {
            assert_eq!(owner[index], 0x5555_5555);
        }
    }
}
