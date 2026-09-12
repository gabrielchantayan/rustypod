//! `pump_record_work_queue` — original: `FUN_08148578` @ `0x08148578`.
//!
//! **68 bytes** (`0x08148578..0x081485bc`; the next function starts with
//! `push {r2, r3, r4, r5, r6, lr}` at `0x081485bc`) and **8 direct `bl`
//! call sites**, all unconditional: `0x08136270`, `0x0816c5d4`,
//! `0x0816c648`, `0x0816c8b4`, `0x0816ca20`, `0x08186efc`, `0x081dc634`,
//! and `0x081dcf5c`. Decoding every ARM B/BL word in `osos.dec` found no
//! predicated direct call or tail branch to this entry.
//!
//! # Algorithm
//!
//! The record embeds a work source at `+0x08`. Its vtable slot `+0x18` is
//! called first on every pass. A zero result stops immediately. A nonzero
//! result is then gated by the two adjacent status bytes at `+0x62` and
//! `+0x63`: either nonzero byte stops the pump. Only while both are zero
//! does the function call the unported sibling lifecycle routines
//! `FUN_081482c0(record)` and `FUN_0814848c(record)`, in that order, and
//! repeat from the source query.
//!
//! The two direct siblings have no recovered identity, so target builds
//! retain their retail addresses through [`WORK_RECORD_PUMP_OPS`]; host
//! tests install recording replacements. The virtual source method is not
//! given an invented callee name either: only its observed vtable slot and
//! `u32` readiness result are modeled. Host vtables are structurally widened
//! so their function pointers are never truncated to target-width words.

#[cfg(target_os = "none")]
/// The work-source virtual entry at target vtable offset `+0x18`.
pub type WorkSourceHasWork = unsafe extern "C" fn(*mut WorkSourceTarget) -> u32;

/// Target-layout embedded source. Its physical vtable word is 32 bits.
#[cfg(target_os = "none")]
#[repr(C)]
pub struct WorkSourceTarget {
    pub vtable: u32,
}

/// The target record fields observed by this function.
#[cfg(target_os = "none")]
#[repr(C)]
pub struct WorkRecordTarget {
    /// `+0x00..+0x04`: not read here.
    pub header: [u32; 2],
    /// `+0x08`: embedded source whose vtable slot `+0x18` is queried.
    pub work_source: WorkSourceTarget,
    /// `+0x0c..+0x5f`: not read here.
    pub state_before_status: [u32; 21],
    /// `+0x60..+0x61`: not read here.
    pub state_60_61: [u8; 2],
    /// `+0x62`: first stop status.
    pub primary_status: u8,
    /// `+0x63`: second stop status, read only when `primary_status` is zero.
    pub secondary_status: u8,
}

#[cfg(target_os = "none")]
const _: [u8; 0x62] = [0; core::mem::offset_of!(WorkRecordTarget, primary_status)];
#[cfg(target_os = "none")]
const _: [u8; 0x63] = [0; core::mem::offset_of!(WorkRecordTarget, secondary_status)];

/// Host vtable with the same seventh-word role as target slot `+0x18`.
#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostWorkSourceVtable {
    pub unresolved_00_14: [usize; 6],
    pub has_work: unsafe extern "C" fn(*mut HostWorkSource) -> u32,
}

/// Host model of the embedded source.
#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostWorkSource {
    pub vtable: *const HostWorkSourceVtable,
}

/// Host model of the record. Fields preserve their target roles rather than
/// target byte offsets, because pointers widen on the 64-bit host.
#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostWorkRecord {
    pub header: [usize; 2],
    pub work_source: HostWorkSource,
    pub state_before_status: [usize; 21],
    pub state_60_61: [u8; 2],
    pub primary_status: u8,
    pub secondary_status: u8,
}

/// The two unported direct sibling calls in the exact order used by the pump.
#[derive(Clone, Copy)]
pub struct WorkRecordPumpOps {
    /// `FUN_081482c0(record)`, called only after a nonzero source result and
    /// two clear status bytes.
    pub advance_work: unsafe extern "C" fn(*mut u8),
    /// `FUN_0814848c(record)`, immediately following `advance_work`.
    pub teardown_work: unsafe extern "C" fn(*mut u8),
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_advance_work(record: *mut u8) {
    let f: unsafe extern "C" fn(*mut u8) = core::mem::transmute(0x0814_82c0usize);
    f(record)
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_teardown_work(record: *mut u8) {
    let f: unsafe extern "C" fn(*mut u8) = core::mem::transmute(0x0814_848cusize);
    f(record)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_advance_work(_record: *mut u8) {
    panic!("pump_record_work_queue requires FUN_081482c0")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_teardown_work(_record: *mut u8) {
    panic!("pump_record_work_queue requires FUN_0814848c")
}

/// Direct sibling dispatches. The target defaults are the original functions;
/// host tests replace them because neither sibling is ported.
pub static mut WORK_RECORD_PUMP_OPS: WorkRecordPumpOps = WorkRecordPumpOps {
    #[cfg(target_os = "none")]
    advance_work: firmware_advance_work,
    #[cfg(not(target_os = "none"))]
    advance_work: missing_advance_work,
    #[cfg(target_os = "none")]
    teardown_work: firmware_teardown_work,
    #[cfg(not(target_os = "none"))]
    teardown_work: missing_teardown_work,
};

#[inline(always)]
unsafe fn work_record_pump_ops() -> WorkRecordPumpOps {
    core::ptr::read_volatile(core::ptr::addr_of!(WORK_RECORD_PUMP_OPS))
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn source_has_work(record: *mut WorkRecordTarget) -> u32 {
    const HAS_WORK_VTABLE_WORD: usize = 6;
    let source = core::ptr::addr_of_mut!((*record).work_source);
    let vtable_address = core::ptr::read_volatile(core::ptr::addr_of!((*source).vtable));
    let entry_address = core::ptr::read_volatile(
        (vtable_address as usize as *const u32).add(HAS_WORK_VTABLE_WORD),
    );
    let has_work: WorkSourceHasWork = core::mem::transmute(entry_address as usize);
    has_work(source)
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn source_has_work(record: *mut HostWorkRecord) -> u32 {
    let source = core::ptr::addr_of_mut!((*record).work_source);
    let vtable = core::ptr::read_volatile(core::ptr::addr_of!((*source).vtable));
    ((*vtable).has_work)(source)
}

/// pump_record_work_queue — original: `FUN_08148578` @ `0x08148578`
/// (68 bytes; 8 unconditional `bl` call sites, no predicated calls).
///
/// Polls the record's embedded work-source vtable slot `+0x18`. A zero result
/// or either nonzero stop-status byte ends the pump. Otherwise it advances
/// then tears down the current work state and polls again. Deliberate
/// deviation: the two unported direct siblings use [`WORK_RECORD_PUMP_OPS`]
/// on host; target builds call their fixed retailOS addresses.
#[cfg(target_os = "none")]
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.pump_record_work_queue")]
pub unsafe extern "C" fn pump_record_work_queue(record: *mut WorkRecordTarget) {
    let ops = work_record_pump_ops();
    loop {
        if source_has_work(record) == 0 {
            return;
        }
        if (*record).primary_status != 0 || (*record).secondary_status != 0 {
            return;
        }
        (ops.advance_work)(record.cast());
        (ops.teardown_work)(record.cast());
    }
}

/// Host entry point with the same ABI and behavior as the target export.
#[cfg(not(target_os = "none"))]
#[inline(never)]
pub unsafe extern "C" fn pump_record_work_queue(record: *mut HostWorkRecord) {
    let ops = work_record_pump_ops();
    loop {
        if source_has_work(record) == 0 {
            return;
        }
        if (*record).primary_status != 0 || (*record).secondary_status != 0 {
            return;
        }
        (ops.advance_work)(record.cast());
        (ops.teardown_work)(record.cast());
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr::{addr_of, addr_of_mut};
    use parking_lot::Mutex;

    static WORK_RECORD_PUMP_TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut PROBES: [u32; 4] = [0; 4];
    static mut PROBE_COUNT: usize = 0;
    static mut ADVANCES: usize = 0;
    static mut TEARDOWNS: usize = 0;
    static mut EVENTS: [u8; 8] = [0; 8];
    static mut EVENT_COUNT: usize = 0;
    static mut SET_PRIMARY_ON_ADVANCE: bool = false;

    struct OpsGuard(WorkRecordPumpOps);

    impl OpsGuard {
        unsafe fn replace() -> Self {
            let saved = addr_of!(WORK_RECORD_PUMP_OPS).read_volatile();
            addr_of_mut!(WORK_RECORD_PUMP_OPS).write_volatile(WorkRecordPumpOps {
                advance_work: advance,
                teardown_work: teardown,
            });
            Self(saved)
        }
    }

    impl Drop for OpsGuard {
        fn drop(&mut self) {
            unsafe { addr_of_mut!(WORK_RECORD_PUMP_OPS).write_volatile(self.0) }
        }
    }

    unsafe extern "C" fn has_work(_source: *mut HostWorkSource) -> u32 {
        let index = PROBE_COUNT;
        PROBE_COUNT += 1;
        PROBES[index]
    }

    unsafe extern "C" fn advance(record: *mut u8) {
        ADVANCES += 1;
        EVENTS[EVENT_COUNT] = b'A';
        EVENT_COUNT += 1;
        if SET_PRIMARY_ON_ADVANCE {
            (*record.cast::<HostWorkRecord>()).primary_status = 1;
        }
    }

    unsafe extern "C" fn teardown(_record: *mut u8) {
        TEARDOWNS += 1;
        EVENTS[EVENT_COUNT] = b'T';
        EVENT_COUNT += 1;
    }

    static VTABLE: HostWorkSourceVtable = HostWorkSourceVtable {
        unresolved_00_14: [0; 6],
        has_work,
    };

    unsafe fn reset(probes: [u32; 4], set_primary_on_advance: bool) {
        PROBES = probes;
        PROBE_COUNT = 0;
        ADVANCES = 0;
        TEARDOWNS = 0;
        EVENTS = [0; 8];
        EVENT_COUNT = 0;
        SET_PRIMARY_ON_ADVANCE = set_primary_on_advance;
    }

    fn record(primary_status: u8, secondary_status: u8) -> HostWorkRecord {
        HostWorkRecord {
            header: [0; 2],
            work_source: HostWorkSource { vtable: &VTABLE },
            state_before_status: [0; 21],
            state_60_61: [0; 2],
            primary_status,
            secondary_status,
        }
    }

    #[test]
    fn zero_source_result_stops_without_status_or_lifecycle_calls() {
        let _lock = WORK_RECORD_PUMP_TEST_LOCK.lock();
        unsafe {
            reset([0, 1, 1, 1], false);
            let _ops = OpsGuard::replace();
            let mut value = record(0, 0);
            pump_record_work_queue(&mut value);
            assert_eq!(PROBE_COUNT, 1);
            assert_eq!(ADVANCES, 0);
            assert_eq!(TEARDOWNS, 0);
        }
    }

    #[test]
    fn either_nonzero_status_stops_after_the_source_probe() {
        let _lock = WORK_RECORD_PUMP_TEST_LOCK.lock();
        unsafe {
            for (primary, secondary) in [(1, 0), (0, 1)] {
                reset([1, 0, 0, 0], false);
                let _ops = OpsGuard::replace();
                let mut value = record(primary, secondary);
                pump_record_work_queue(&mut value);
                assert_eq!(PROBE_COUNT, 1);
                assert_eq!(ADVANCES, 0);
                assert_eq!(TEARDOWNS, 0);
            }
        }
    }

    #[test]
    fn clear_statuses_repeat_lifecycle_pair_until_source_stops() {
        let _lock = WORK_RECORD_PUMP_TEST_LOCK.lock();
        unsafe {
            reset([1, 1, 0, 0], false);
            let _ops = OpsGuard::replace();
            let mut value = record(0, 0);
            pump_record_work_queue(&mut value);
            assert_eq!(PROBE_COUNT, 3);
            assert_eq!(ADVANCES, 2);
            assert_eq!(TEARDOWNS, 2);
        }
    }

    #[test]
    fn lifecycle_pair_finishes_before_a_newly_set_stop_status_is_observed() {
        let _lock = WORK_RECORD_PUMP_TEST_LOCK.lock();
        unsafe {
            reset([1, 1, 0, 0], true);
            let _ops = OpsGuard::replace();
            let mut value = record(0, 0);
            pump_record_work_queue(&mut value);
            assert_eq!(PROBE_COUNT, 2, "the next pass probes before it tests status");
            assert_eq!(ADVANCES, 1);
            assert_eq!(TEARDOWNS, 1, "advance does not suppress its paired teardown");
            assert_eq!(&EVENTS[..EVENT_COUNT], b"AT");
        }
    }
}
