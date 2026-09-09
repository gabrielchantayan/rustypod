//! `app_boot_metrics_submit` — original: `FUN_082664b4` @ **0x082664b4**
//! (**116 bytes**, `0x082664b4..0x08266524`; the next separately linked
//! function begins at `0x08266528`).
//!
//! A direct scan of every ARM B/BL word in `osos.dec` independently finds
//! **13 incoming `bl` calls**, all unconditional (`cond = AL`), and **0
//! predicated `bl` forms**. The function itself makes two direct `bl` calls
//! (`operator new` and the initializer) and one virtual `blx` dispatch.
//!
//! Algorithm: reject immediately unless `channel[0x19]` and then
//! `channel[0x18]` are both nonzero. Allocate a 12-byte record through the
//! ported `operator_new`, initialize it with unported `FUN_0815a554`, and
//! accept it when the initializer's word at `+0x08` is nonzero or its event
//! id lies in the inclusive range `0x16..=0x21`. An accepted record receives
//! the event id and value at `+0x00` / `+0x04`; its pointer is then stored in
//! a stack slot and that slot's address is passed to channel-vtable slot
//! `+0x1c`. A rejected initialized record is immediately released through the
//! ported `operator_delete`.
//!
//! `FUN_0815a554` has no recovered identity: target builds call its fixed
//! retailOS address, while host builds expose the smallest deterministic seam
//! (the observed three-word zeroing initializer by default). The virtual
//! target also has no recovered identity. Target dispatch reads physical
//! 32-bit words at channel `+0x00` and vtable `+0x1c`; the widened host-only
//! fixture preserves the slot's role without truncating a 64-bit function
//! pointer. Rust cannot express the final conditional tail branch to
//! `operator_delete`, so rejection uses a normal call instead.

use core::ptr::addr_of_mut;
#[cfg(not(target_os = "none"))]
use core::ptr::addr_of;

use crate::heap::veneers::{operator_delete, operator_new};

const RETAIL_RECORD_INITIALIZE: usize = 0x0815_a554;
const CHANNEL_ENABLED_OFFSET: usize = 0x19;
const CHANNEL_ACCEPTING_OFFSET: usize = 0x18;
const CHANNEL_VTABLE_DISPATCH_WORD: usize = 7;
const EVENT_ID_FIRST: u32 = 0x16;
const EVENT_ID_LAST: u32 = 0x21;

/// The exact 12-byte target allocation initialized by `FUN_0815a554`.
#[repr(C)]
pub struct AppBootMetricsRecord {
    pub event_id: u32,
    pub value: u32,
    pub initializer_result: u32,
}

/// ABI of unported `FUN_0815a554`; its recovered behavior zeroes the first
/// two words, calls `FUN_0815a50c`, stores that answer at `+0x08`, and returns
/// the record pointer.
pub type AppBootMetricsRecordInitialize =
    unsafe extern "C" fn(*mut AppBootMetricsRecord) -> *mut AppBootMetricsRecord;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn initialize_record(record: *mut AppBootMetricsRecord) -> *mut AppBootMetricsRecord {
    let initialize: AppBootMetricsRecordInitialize = core::mem::transmute(RETAIL_RECORD_INITIALIZE);
    initialize(record)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn zeroing_record_initialize(
    record: *mut AppBootMetricsRecord,
) -> *mut AppBootMetricsRecord {
    core::ptr::write(record, AppBootMetricsRecord {
        event_id: 0,
        value: 0,
        initializer_result: 0,
    });
    record
}

/// Host seam for unported `FUN_0815a554`. Target builds always call the
/// firmware address; the host default is the initializer's observed zeroing
/// shape, making calls deterministic without inventing its identity.
#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct AppBootMetricsSubmitOps {
    pub initialize_record: AppBootMetricsRecordInitialize,
}

#[cfg(not(target_os = "none"))]
pub const DEFAULT_APP_BOOT_METRICS_SUBMIT_OPS: AppBootMetricsSubmitOps = AppBootMetricsSubmitOps {
    initialize_record: zeroing_record_initialize,
};

#[cfg(not(target_os = "none"))]
pub static mut APP_BOOT_METRICS_SUBMIT_OPS: AppBootMetricsSubmitOps =
    DEFAULT_APP_BOOT_METRICS_SUBMIT_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn initialize_record(record: *mut AppBootMetricsRecord) -> *mut AppBootMetricsRecord {
    let initialize = core::ptr::read_volatile(addr_of!(APP_BOOT_METRICS_SUBMIT_OPS.initialize_record));
    initialize(record)
}

/// Performs the target's virtual call using its physical ARM layout: the
/// channel's first 32-bit word is its vtable address and word seven is slot
/// `+0x1c`.
#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn dispatch_record_slot(channel: *mut u8, record_slot: *mut *mut AppBootMetricsRecord) {
    let vtable_address = core::ptr::read_volatile(channel.cast::<u32>());
    let dispatch_address = core::ptr::read_volatile(
        (vtable_address as usize as *const u32).add(CHANNEL_VTABLE_DISPATCH_WORD),
    );
    let dispatch: unsafe extern "C" fn(*mut u8, *mut *mut AppBootMetricsRecord) =
        core::mem::transmute(dispatch_address as usize);
    dispatch(channel, record_slot);
}

/// Widened host-only channel fixture. Its dispatch field has the same seventh
/// vtable-word role as target slot `+0x1c`, but `usize` prevents host function
/// pointers from being truncated to target-width integers.
#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostAppBootMetricsChannelVtable {
    pub unresolved_00_to_18: [usize; CHANNEL_VTABLE_DISPATCH_WORD],
    pub dispatch: unsafe extern "C" fn(*mut u8, *mut *mut AppBootMetricsRecord),
}

#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostAppBootMetricsChannel {
    pub vtable: *const HostAppBootMetricsChannelVtable,
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn dispatch_record_slot(channel: *mut u8, record_slot: *mut *mut AppBootMetricsRecord) {
    let host_channel = channel.cast::<HostAppBootMetricsChannel>();
    let vtable = core::ptr::read_volatile(addr_of!((*host_channel).vtable));
    ((*vtable).dispatch)(channel, record_slot);
}

/// Submits an application-boot metrics record to `channel` when both channel
/// gates are enabled.
///
/// # Safety
///
/// `channel` must point to at least `0x1a` readable bytes and, on an accepted
/// record, to a valid target-layout vtable. The allocated record and the
/// virtual dispatch target must satisfy their retailOS contracts.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn app_boot_metrics_submit(
    channel: *mut u8,
    event_id: u32,
    value: u32,
) {
    if core::ptr::read_volatile(channel.add(CHANNEL_ENABLED_OFFSET)) == 0 {
        return;
    }
    if core::ptr::read_volatile(channel.add(CHANNEL_ACCEPTING_OFFSET)) == 0 {
        return;
    }

    let mut record = initialize_record(operator_new(core::mem::size_of::<AppBootMetricsRecord>()).cast());
    if (*record).initializer_result != 0 || (EVENT_ID_FIRST..=EVENT_ID_LAST).contains(&event_id) {
        (*record).event_id = event_id;
        (*record).value = value;
        dispatch_record_slot(channel, addr_of_mut!(record));
    } else {
        operator_delete(record.cast());
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::{Mutex, MutexGuard};

    static SUBMIT_LOCK: Mutex<()> = Mutex::new(());
    static mut INITIALIZER_RESULT: u32 = 0;
    static mut INITIALIZER_CALLS: usize = 0;
    static mut DISPATCH_CALL: Option<(*mut u8, *mut *mut AppBootMetricsRecord)> = None;
    static mut DISPATCH_RECORD: Option<(u32, u32, u32)> = None;
    static mut DISPATCH_RECORD_POINTER: *mut AppBootMetricsRecord = core::ptr::null_mut();

    unsafe extern "C" fn recording_initialize(
        record: *mut AppBootMetricsRecord,
    ) -> *mut AppBootMetricsRecord {
        INITIALIZER_CALLS += 1;
        core::ptr::write(record, AppBootMetricsRecord {
            event_id: 0,
            value: 0,
            initializer_result: INITIALIZER_RESULT,
        });
        record
    }

    unsafe extern "C" fn recording_dispatch(
        channel: *mut u8,
        record_slot: *mut *mut AppBootMetricsRecord,
    ) {
        DISPATCH_CALL = Some((channel, record_slot));
        let record = *record_slot;
        DISPATCH_RECORD_POINTER = record;
        DISPATCH_RECORD = Some(((*record).event_id, (*record).value, (*record).initializer_result));
    }

    static VTABLE: HostAppBootMetricsChannelVtable = HostAppBootMetricsChannelVtable {
        unresolved_00_to_18: [0; CHANNEL_VTABLE_DISPATCH_WORD],
        dispatch: recording_dispatch,
    };

    fn install(
        initializer_result: u32,
        record: *mut AppBootMetricsRecord,
    ) -> (MutexGuard<'static, ()>, MutexGuard<'static, ()>) {
        let submit_guard = SUBMIT_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let heap_guard = crate::heap::veneers::tests::mock_heap();
        unsafe {
            INITIALIZER_RESULT = initializer_result;
            INITIALIZER_CALLS = 0;
            DISPATCH_CALL = None;
            DISPATCH_RECORD = None;
            DISPATCH_RECORD_POINTER = core::ptr::null_mut();
            addr_of_mut!(APP_BOOT_METRICS_SUBMIT_OPS).write(AppBootMetricsSubmitOps {
                initialize_record: recording_initialize,
            });
            crate::heap::veneers::tests::set_alloc_ret(record.cast());
        }
        (submit_guard, heap_guard)
    }

    fn restore(guards: (MutexGuard<'static, ()>, MutexGuard<'static, ()>)) {
        unsafe {
            addr_of_mut!(APP_BOOT_METRICS_SUBMIT_OPS).write(DEFAULT_APP_BOOT_METRICS_SUBMIT_OPS);
            addr_of_mut!(crate::heap::veneers::HEAP_OPS).write(crate::heap::veneers::DEFAULT_HEAP_OPS);
            addr_of_mut!(crate::heap::types::DEFAULT_HEAP).write(core::ptr::null_mut());
        }
        drop(guards);
    }

    fn channel_fixture() -> [usize; 4] {
        let mut storage = [0usize; 4];
        let channel = storage.as_mut_ptr().cast::<u8>();
        unsafe {
            channel.cast::<HostAppBootMetricsChannel>().write(HostAppBootMetricsChannel { vtable: &VTABLE });
            channel.add(CHANNEL_ENABLED_OFFSET).write(1);
            channel.add(CHANNEL_ACCEPTING_OFFSET).write(1);
        }
        storage
    }

    #[test]
    fn channel_enabled_gate_short_circuits_before_allocation() {
        let mut record = AppBootMetricsRecord { event_id: 0, value: 0, initializer_result: 0 };
        let guards = install(1, addr_of_mut!(record));
        let mut storage = channel_fixture();
        unsafe { storage.as_mut_ptr().cast::<u8>().add(CHANNEL_ENABLED_OFFSET).write(0) };

        unsafe { app_boot_metrics_submit(storage.as_mut_ptr().cast(), EVENT_ID_FIRST, 7) };

        unsafe {
            assert_eq!(INITIALIZER_CALLS, 0);
            assert_eq!(crate::heap::veneers::tests::alloc_log().0, 0);
            assert!(DISPATCH_CALL.is_none());
        }
        restore(guards);
    }

    #[test]
    fn channel_accepting_gate_short_circuits_before_allocation() {
        let mut record = AppBootMetricsRecord { event_id: 0, value: 0, initializer_result: 0 };
        let guards = install(1, addr_of_mut!(record));
        let mut storage = channel_fixture();
        unsafe { storage.as_mut_ptr().cast::<u8>().add(CHANNEL_ACCEPTING_OFFSET).write(0) };

        unsafe { app_boot_metrics_submit(storage.as_mut_ptr().cast(), EVENT_ID_FIRST, 7) };

        unsafe {
            assert_eq!(INITIALIZER_CALLS, 0);
            assert_eq!(crate::heap::veneers::tests::alloc_log().0, 0);
            assert!(DISPATCH_CALL.is_none());
        }
        restore(guards);
    }

    #[test]
    fn zero_initializer_result_accepts_inclusive_event_boundaries() {
        for event_id in [EVENT_ID_FIRST, EVENT_ID_LAST] {
            let mut record = AppBootMetricsRecord { event_id: 0, value: 0, initializer_result: 0 };
            let guards = install(0, addr_of_mut!(record));
            let mut storage = channel_fixture();

            unsafe { app_boot_metrics_submit(storage.as_mut_ptr().cast(), event_id, 0xfeed_cafe) };

            unsafe {
                assert_eq!(INITIALIZER_CALLS, 1);
                assert_eq!(crate::heap::veneers::tests::alloc_log(), (1, 12, 2));
                assert_eq!(DISPATCH_RECORD, Some((event_id, 0xfeed_cafe, 0)));
                let (called_channel, record_slot) = DISPATCH_CALL.unwrap();
                assert_eq!(called_channel, storage.as_mut_ptr().cast());
                assert!(!record_slot.is_null());
                assert_eq!(DISPATCH_RECORD_POINTER, addr_of_mut!(record));
                assert_eq!(crate::heap::veneers::tests::free_log().0, 0);
            }
            restore(guards);
        }
    }

    #[test]
    fn nonzero_initializer_result_accepts_event_outside_range() {
        let mut record = AppBootMetricsRecord { event_id: 0, value: 0, initializer_result: 0 };
        let guards = install(0x80, addr_of_mut!(record));
        let mut storage = channel_fixture();

        unsafe { app_boot_metrics_submit(storage.as_mut_ptr().cast(), EVENT_ID_LAST + 1, 0x31) };

        unsafe {
            assert_eq!(DISPATCH_RECORD, Some((EVENT_ID_LAST + 1, 0x31, 0x80)));
            assert_eq!(DISPATCH_CALL.unwrap().0, storage.as_mut_ptr().cast());
            assert_eq!(crate::heap::veneers::tests::free_log().0, 0);
        }
        restore(guards);
    }

    #[test]
    fn rejected_initialized_record_is_immediately_deleted() {
        let mut record = AppBootMetricsRecord { event_id: 0, value: 0, initializer_result: 0 };
        let guards = install(0, addr_of_mut!(record));
        let mut storage = channel_fixture();

        unsafe { app_boot_metrics_submit(storage.as_mut_ptr().cast(), EVENT_ID_LAST + 1, 0x31) };

        unsafe {
            assert!(DISPATCH_CALL.is_none());
            assert_eq!(crate::heap::veneers::tests::free_log(), (1, addr_of_mut!(record).cast(), 2));
        }
        restore(guards);
    }
}
