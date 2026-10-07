use crate::kernel::sync_mutex::{mutex_lock, mutex_unlock, Mutex};
use crate::kernel::condvar::{condvar_wait_forever, CondVar};

/// Native-pointer layout; target offsets are 0, 8, 0x14, 0x18, 0x1c, 0x20.
#[repr(C)]
pub struct RecordGate {
    pub mutex: Mutex,
    pub changed: CondVar,
    pub blocked_key: u32,
    pub reserved_key: u32,
    pub blocked_record: *const GateRecord,
    pub reserved_record: *const GateRecord,
}

#[repr(C)]
pub struct GateRecord {
    pub key: u32,
    pub value: u32,
}

type Query = unsafe extern "C" fn(*mut RecordGate, *const GateRecord) -> u32;

#[cfg(target_os = "none")]
unsafe extern "C" fn record_gate_query(gate: *mut RecordGate, record: *const GateRecord) -> u32 {
    core::mem::transmute::<usize, Query>(0x0813_b48c)(gate, record)
}

#[cfg(target_os = "none")]
unsafe extern "C" fn record_gate_reserve(gate: *mut RecordGate, record: *const GateRecord) -> u32 {
    core::mem::transmute::<usize, Query>(0x0813_b3e8)(gate, record)
}

// Host models of the two unported firmware boundaries, verified from raw
// words. These are not additional target ports or exported firmware symbols.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn record_gate_query(gate: *mut RecordGate, record: *const GateRecord) -> u32 {
    if (*gate).blocked_key == u32::MAX - 1 { return 2; }
    if (*gate).blocked_record == record { return 1; }
    if (*record).value != u32::MAX { return 2; }
    if (*record).key == (*gate).blocked_key { 1 } else { 3 }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn record_gate_reserve(gate: *mut RecordGate, record: *const GateRecord) -> u32 {
    if !(*gate).reserved_record.is_null() || (*gate).reserved_key != u32::MAX { return 0; }
    (*gate).reserved_key = (*record).key;
    (*gate).reserved_record = record;
    1
}

unsafe fn acquire_with(
    gate: *mut RecordGate,
    record: *const GateRecord,
    blocking: u32,
    query: Query,
    reserve: Query,
    mut wait: impl FnMut(*mut CondVar),
) -> u32 {
    mutex_lock(core::ptr::addr_of_mut!((*gate).mutex));
    let result = loop {
        match query(gate, record) {
            2 => break 1,
            1 => {
                if blocking == 0 { break 0; }
                wait(core::ptr::addr_of_mut!((*gate).changed));
            }
            3 => break reserve(gate, record),
            _ => {}
        }
    };
    mutex_unlock(core::ptr::addr_of_mut!((*gate).mutex));
    result
}

/// Acquire a record gate — `FUN_0813b36c` @ 0x0813b36c.
/// True extent: 124 bytes, [0x0813b36c, 0x0813b3e8), no literals.
/// Verified calls: five outbound plain BLs, zero predicated BLs; two
/// inbound plain BLs (0x0814b8a0, 0x0814c334), zero predicated BLs.
/// Lock the gate and query the record. Status 2 succeeds without reserving;
/// status 1 fails when nonblocking, otherwise waits on gate+8 and retries;
/// status 3 returns the reservation result. Other statuses retry without
/// sleeping. Unlock on every returning path. The two unported helpers stay
/// at their original addresses; mutex and condvar operations reuse ports.
/// Deviations: hosts widen pointer fields and model the two firmware helpers.
/// No target behavioral deviations; nonzero blocking values are equivalent.
///
/// # Safety
/// `gate` must be an initialized gate with a valid mutex and condition
/// variable; `record` must remain valid across waits and helper calls.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn record_gate_acquire(
    gate: *mut RecordGate,
    record: *const GateRecord,
    blocking: u32,
) -> u32 {
    acquire_with(gate, record, blocking, record_gate_query, record_gate_reserve,
        |changed| condvar_wait_forever(changed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr::null_mut;
    use crate::kernel::condvar::ListHead;

    fn gate() -> RecordGate {
        RecordGate {
            mutex: Mutex { sem_cell: null_mut(), unused: 0 },
            changed: CondVar { lock_obj: null_mut(), waiters: ListHead { head: null_mut(), tail: null_mut() } },
            blocked_key: u32::MAX,
            reserved_key: u32::MAX,
            blocked_record: core::ptr::null(),
            reserved_record: core::ptr::null(),
        }
    }

    #[test]
    fn immediate_success_does_not_reserve_and_blocked_nonblocking_fails() {
        let record = GateRecord { key: 17, value: u32::MAX };
        for disabled in [false, true] {
            for value in [0, 1, u32::MAX - 1, u32::MAX] {
                let record = GateRecord { key: record.key, value };
                let mut gate = gate();
                gate.blocked_key = if disabled { u32::MAX - 1 } else { record.key };
                let expected = if disabled || value != u32::MAX { 1 } else { 0 };
                unsafe { assert_eq!(record_gate_acquire(&mut gate, &record, 0), expected); }
                assert_eq!(gate.reserved_key, u32::MAX);
                assert!(gate.reserved_record.is_null());
            }
        }
        let mut gate = gate();
        gate.blocked_record = &record;
        unsafe { assert_eq!(record_gate_acquire(&mut gate, &record, 0), 0); }
        assert!(gate.reserved_record.is_null());
    }

    #[test]
    fn reservation_requires_both_empty_fields_and_preserves_busy_state() {
        for key in [0, 17, u32::MAX - 1, u32::MAX] {
            for occupied_pointer in [false, true] {
                for reserved_key in [0, u32::MAX] {
                    let record = GateRecord { key, value: u32::MAX };
                    let other = GateRecord { key: 99, value: 0 };
                    let mut gate = gate();
                    gate.blocked_key = key.wrapping_add(1);
                    if gate.blocked_key == u32::MAX - 1 { gate.blocked_key = 42; }
                    gate.reserved_key = reserved_key;
                    gate.reserved_record = if occupied_pointer { &other } else { core::ptr::null() };
                    let old_pointer = gate.reserved_record;
                    let accepted = !occupied_pointer && reserved_key == u32::MAX;
                    unsafe { assert_eq!(record_gate_acquire(&mut gate, &record, 0), accepted as u32); }
                    assert_eq!(gate.reserved_key, if accepted { key } else { reserved_key });
                    assert_eq!(gate.reserved_record, if accepted { &record } else { old_pointer });
                }
            }
        }
    }

    #[test]
    fn blocking_requeries_after_spurious_wakeup_and_reserves_changed_record() {
        for blocking in [1, u32::MAX] {
            let mut record = GateRecord { key: 17, value: u32::MAX };
            let mut gate = gate();
            gate.blocked_key = 17;
            let record_ptr = &mut record as *mut GateRecord;
            let gate_ptr = &mut gate as *mut RecordGate;
            let mut waits = 0;
            unsafe {
                let result = acquire_with(gate_ptr, record_ptr, blocking,
                    record_gate_query, record_gate_reserve, |changed| {
                        assert_eq!(changed, core::ptr::addr_of_mut!((*gate_ptr).changed));
                        waits += 1;
                        if waits == 2 { (*record_ptr).key = 23; }
                        assert!(waits <= 2);
                    });
                assert_eq!(result, 1);
            }
            assert_eq!(waits, 2);
            assert_eq!(gate.reserved_key, 23);
            assert_eq!(gate.reserved_record, record_ptr.cast_const());
        }
    }
}
