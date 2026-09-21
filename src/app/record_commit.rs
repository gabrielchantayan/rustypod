//! `record_commit` — original: `FUN_082e4218` @ 0x082e4218 (152 bytes).
//!
//! Raw `osos.dec` establishes the body at 0x082e4218..0x082e42ac: the next
//! separately entered function begins with `push {r4-r8,lr}` at 0x082e42b0.
//! It contains five plain unconditional `bl` instructions and no predicated
//! `bl`; it ends in a tail `b 0x082e149c`. The function first rejects a record
//! whose descriptor state at +0x24 is greater than one, reports code 8 on
//! either rejection or prepare failure, then prepares the descriptor range,
//! saves and clears its selection, binds the record, releases the saved
//! selection, and runs the final commit step.
//!
//! # Deliberate deviations
//!
//! The six called retailOS functions are not ported and have no recovered
//! identities in `names.yaml`. Target builds call their verified addresses;
//! host tests install an operation seam. The stock tail branch supplies the
//! context halfword in r0, but 0x082e149c immediately overwrites r0 before
//! its first call, so the final seam deliberately takes no argument.

#[cfg(not(target_os = "none"))]
use core::ptr;

const RETAIL_RECORD_RANGE_PREPARE: usize = 0x082e_0520;
const RETAIL_RECORD_SELECTION_READ: usize = 0x082e_1378;
const RETAIL_RECORD_SELECTION_CLEAR: usize = 0x082e_3d30;
const RETAIL_RECORD_BIND: usize = 0x082e_48bc;
const RETAIL_RECORD_SELECTION_RELEASE: usize = 0x082e_18f8;
const RETAIL_RECORD_FINALIZE: usize = 0x082e_149c;
const RETAIL_RECORD_COMMIT_REPORT: usize = 0x082e_406c;

#[derive(Clone, Copy)]
pub struct RecordCommitOps {
    pub prepare_range: unsafe extern "C" fn(*mut u32, *mut u32) -> u32,
    pub selection_read: unsafe extern "C" fn(*mut u32, *mut u32) -> u32,
    pub selection_clear: unsafe extern "C" fn(*mut u32, *mut u32, u32),
    pub bind: unsafe extern "C" fn(*mut u32, u32, u32) -> u32,
    pub selection_release: unsafe extern "C" fn(*mut u32, u32),
    pub finalize: unsafe extern "C" fn() -> u32,
    pub report: unsafe extern "C" fn(u32),
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_prepare_range(_context: *mut u32, _range: *mut u32) -> u32 { 0 }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_selection_read(_context: *mut u32, _descriptor: *mut u32) -> u32 { 0 }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_selection_clear(_context: *mut u32, _descriptor: *mut u32, _selection: u32) {}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_bind(_record: *mut u32, _first: u32, _second: u32) -> u32 { 0 }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_selection_release(_context: *mut u32, _selection: u32) {}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_finalize() -> u32 { 0 }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_report(_code: u32) {}

#[cfg(not(target_os = "none"))]
pub static mut RECORD_COMMIT_OPS: RecordCommitOps = RecordCommitOps {
    prepare_range: missing_prepare_range,
    selection_read: missing_selection_read,
    selection_clear: missing_selection_clear,
    bind: missing_bind,
    selection_release: missing_selection_release,
    finalize: missing_finalize,
    report: missing_report,
};

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn record_commit_ops() -> RecordCommitOps {
    RecordCommitOps {
        prepare_range: core::mem::transmute(RETAIL_RECORD_RANGE_PREPARE),
        selection_read: core::mem::transmute(RETAIL_RECORD_SELECTION_READ),
        selection_clear: core::mem::transmute(RETAIL_RECORD_SELECTION_CLEAR),
        bind: core::mem::transmute(RETAIL_RECORD_BIND),
        selection_release: core::mem::transmute(RETAIL_RECORD_SELECTION_RELEASE),
        finalize: core::mem::transmute(RETAIL_RECORD_FINALIZE),
        report: core::mem::transmute(RETAIL_RECORD_COMMIT_REPORT),
    }
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn record_commit_ops() -> RecordCommitOps {
    ptr::read_volatile(ptr::addr_of!(RECORD_COMMIT_OPS))
}

/// Commits `record` after preparing its descriptor range and replacing its
/// current selection. Returns zero on a rejected, unprepared, or unbound
/// record; otherwise returns the final commit step's status.
///
/// # Safety
///
/// `record` must point to the retailOS record layout: context at word zero and
/// descriptor at word one. The descriptor must provide words through +0x40.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn record_commit(record: *mut u32) -> u32 {
    let ops = record_commit_ops();
    let descriptor = record.add(1).read_volatile() as *mut u32;
    if descriptor.add(9).read_volatile() as i32 > 1 {
        (ops.report)(8);
        return 0;
    }
    descriptor.cast::<u8>().write_volatile(0xe5);

    let context = record.read_volatile() as *mut u32;
    if (ops.prepare_range)(context, descriptor.add(16)) == 0 {
        (ops.report)(8);
        return 0;
    }

    let selection = (ops.selection_read)(context, descriptor);
    (ops.selection_clear)(context, descriptor, 0);
    if (ops.bind)(record, 1, 1) == 0 {
        return 0;
    }
    (ops.selection_release)(context, selection);
    let _ = context.cast::<u8>().add(0x78).cast::<u16>().read_volatile();
    (ops.finalize)()
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::Mutex;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: [u32; 7] = [0; 7];
    static mut PREPARE_RESULT: u32 = 1;
    static mut BIND_RESULT: u32 = 1;
    static mut FINALIZE_RESULT: u32 = 1;
    static mut SELECTION: u32 = 0;
    static mut RELEASED: u32 = 0;

    unsafe extern "C" fn prepare(_context: *mut u32, _range: *mut u32) -> u32 { unsafe { CALLS[0] += 1; PREPARE_RESULT } }
    unsafe extern "C" fn read_selection(_context: *mut u32, _descriptor: *mut u32) -> u32 { unsafe { CALLS[1] += 1; SELECTION } }
    unsafe extern "C" fn clear_selection(_context: *mut u32, _descriptor: *mut u32, selection: u32) { unsafe { CALLS[2] += 1; assert_eq!(selection, 0); } }
    unsafe extern "C" fn bind(_record: *mut u32, first: u32, second: u32) -> u32 { unsafe { CALLS[3] += 1; assert_eq!((first, second), (1, 1)); BIND_RESULT } }
    unsafe extern "C" fn release_selection(_context: *mut u32, selection: u32) { unsafe { CALLS[4] += 1; RELEASED = selection; } }
    unsafe extern "C" fn finalize() -> u32 { unsafe { CALLS[5] += 1; FINALIZE_RESULT } }
    unsafe extern "C" fn report(code: u32) { unsafe { CALLS[6] += 1; assert_eq!(code, 8); } }

    struct Restore;
    impl Drop for Restore {
        fn drop(&mut self) { unsafe { RECORD_COMMIT_OPS = RecordCommitOps { prepare_range: missing_prepare_range, selection_read: missing_selection_read, selection_clear: missing_selection_clear, bind: missing_bind, selection_release: missing_selection_release, finalize: missing_finalize, report: missing_report }; } }
    }

    fn install() -> (parking_lot::MutexGuard<'static, ()>, Restore) {
        let guard = OPS_LOCK.lock();
        unsafe {
            CALLS = [0; 7]; PREPARE_RESULT = 1; BIND_RESULT = 1; FINALIZE_RESULT = 0x37; SELECTION = 0x1234; RELEASED = 0;
            RECORD_COMMIT_OPS = RecordCommitOps { prepare_range: prepare, selection_read: read_selection, selection_clear: clear_selection, bind, selection_release: release_selection, finalize, report };
        }
        (guard, Restore)
    }

    unsafe fn record_with_state(hint: usize, state: i32) -> Option<*mut u32> {
        let slab = crate::testing::try_map_u32_slab(hint, 4096)?;
        let record = slab.cast::<u32>();
        let descriptor = slab.add(0x100).cast::<u32>();
        descriptor.add(9).write(state as u32);
        record.write(record as usize as u32);
        record.add(1).write(descriptor as usize as u32);
        Some(record)
    }

    #[test]
    fn rejects_states_above_one_and_reports_eight() {
        let (_guard, _restore) = install();
        let Some(record) = (unsafe { record_with_state(crate::testing::hints::RECORD_COMMIT_REJECT, 2) }) else {
            assert!(crate::testing::note_missing_u32_fixture("app/record_commit"));
            return;
        };
        assert_eq!(unsafe { record_commit(record) }, 0);
        assert_eq!(unsafe { CALLS }, [0, 0, 0, 0, 0, 0, 1]);
    }

    #[test]
    fn prepare_or_bind_failure_stops_at_its_stock_boundary() {
        let (_guard, _restore) = install();
        let Some(record) = (unsafe { record_with_state(crate::testing::hints::RECORD_COMMIT_FAILURE, 1) }) else {
            assert!(crate::testing::note_missing_u32_fixture("app/record_commit"));
            return;
        };
        unsafe { PREPARE_RESULT = 0; }
        assert_eq!(unsafe { record_commit(record) }, 0);
        assert_eq!(unsafe { CALLS }, [1, 0, 0, 0, 0, 0, 1]);
        unsafe { PREPARE_RESULT = 1; BIND_RESULT = 0; CALLS = [0; 7]; }
        assert_eq!(unsafe { record_commit(record) }, 0);
        assert_eq!(unsafe { CALLS }, [1, 1, 1, 1, 0, 0, 0]);
    }

    #[test]
    fn successful_commit_releases_saved_selection_then_returns_final_status() {
        let (_guard, _restore) = install();
        let Some(record) = (unsafe { record_with_state(crate::testing::hints::RECORD_COMMIT_SUCCESS, -1) }) else {
            assert!(crate::testing::note_missing_u32_fixture("app/record_commit"));
            return;
        };
        assert_eq!(unsafe { record_commit(record) }, 0x37);
        assert_eq!(unsafe { CALLS }, [1, 1, 1, 1, 1, 1, 0]);
        assert_eq!(unsafe { RELEASED }, 0x1234);
    }
}
