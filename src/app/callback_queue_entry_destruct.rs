//! Destroys a callback-queue entry and its embedded base state.
//!
//! `callback_queue_entry_destruct` — original: `FUN_0820760c` @ 0x0820760c
//! (96 bytes, `0x0820760c..0x0820766c`; the next real function begins at
//! 0x0820766c). Raw ARM decoding verifies four plain `bl` instructions and one
//! predicated indirect `blxne` through vtable slot +4.
//!
//! It submits the entry to the shared callback queue, destroys its embedded
//! state at +4, releases the optional +0x34 object and then the owned +0x00
//! object (clearing only the latter), and destroys the embedded base at +4.
//! The base destructor's returned pointer is rebased by -4 for the result.
//!
//! Deliberate deviations: the queue submitter (0x081fb52c), embedded-state
//! destructor (0x08206f5c), and base destructor (0x08207330) have no recovered
//! names. Target builds call their verified retail addresses; host tests supply
//! role-based operations. Host object and vtable pointers are widened.

use crate::app::callback_queue::callback_queue_instance_get;

const RETAIL_CALLBACK_QUEUE_SUBMIT: usize = 0x081f_b52c;
const RETAIL_EMBEDDED_STATE_DESTRUCT: usize = 0x0820_6f5c;
const RETAIL_ENTRY_BASE_DESTRUCT: usize = 0x0820_7330;

type CallbackQueueSubmit = unsafe extern "C" fn(*mut u8, *mut CallbackQueueEntry);
type EmbeddedStateDestruct = unsafe extern "C" fn(*mut u8);
type EntryBaseDestruct = unsafe extern "C" fn(*mut u8) -> *mut u8;
type Release = unsafe extern "C" fn(*mut u8);

#[cfg(target_os = "none")]
#[repr(C)]
pub struct CallbackQueueEntry {
    pub owned: u32,
    pub embedded_state: [u32; 12],
    pub optional: u32,
}

#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct CallbackQueueEntry {
    pub owned: *mut HostReleaseObject,
    pub embedded_state: [u32; 12],
    pub optional: *mut HostReleaseObject,
}

#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostReleaseVtable {
    pub unresolved_00: usize,
    pub release: Release,
}

#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostReleaseObject {
    pub vtable: *const HostReleaseVtable,
}

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct CallbackQueueEntryDestructOps {
    pub submit: CallbackQueueSubmit,
    pub destruct_embedded_state: EmbeddedStateDestruct,
    pub destruct_base: EntryBaseDestruct,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_submit(_queue: *mut u8, _entry: *mut CallbackQueueEntry) { panic!("install callback-queue entry teardown host operations") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_destruct_embedded_state(_state: *mut u8) { panic!("install callback-queue entry teardown host operations") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_destruct_base(_base: *mut u8) -> *mut u8 { panic!("install callback-queue entry teardown host operations") }

#[cfg(not(target_os = "none"))]
pub static mut CALLBACK_QUEUE_ENTRY_DESTRUCT_OPS: CallbackQueueEntryDestructOps = CallbackQueueEntryDestructOps {
    submit: missing_submit,
    destruct_embedded_state: missing_destruct_embedded_state,
    destruct_base: missing_destruct_base,
};

#[inline(always)]
unsafe fn submit(queue: *mut u8, entry: *mut CallbackQueueEntry) {
    #[cfg(target_os = "none")]
    unsafe { (core::mem::transmute::<usize, CallbackQueueSubmit>(RETAIL_CALLBACK_QUEUE_SUBMIT))(queue, entry) }
    #[cfg(not(target_os = "none"))]
    unsafe { (core::ptr::addr_of!(CALLBACK_QUEUE_ENTRY_DESTRUCT_OPS.submit).read_volatile())(queue, entry) }
}

#[inline(always)]
unsafe fn destruct_embedded_state(state: *mut u8) {
    #[cfg(target_os = "none")]
    unsafe { (core::mem::transmute::<usize, EmbeddedStateDestruct>(RETAIL_EMBEDDED_STATE_DESTRUCT))(state) }
    #[cfg(not(target_os = "none"))]
    unsafe { (core::ptr::addr_of!(CALLBACK_QUEUE_ENTRY_DESTRUCT_OPS.destruct_embedded_state).read_volatile())(state) }
}

#[inline(always)]
unsafe fn destruct_base(base: *mut u8) -> *mut u8 {
    #[cfg(target_os = "none")]
    unsafe { (core::mem::transmute::<usize, EntryBaseDestruct>(RETAIL_ENTRY_BASE_DESTRUCT))(base) }
    #[cfg(not(target_os = "none"))]
    unsafe { (core::ptr::addr_of!(CALLBACK_QUEUE_ENTRY_DESTRUCT_OPS.destruct_base).read_volatile())(base) }
}

#[cfg(target_os = "none")]
unsafe fn release(object: u32) {
    let vtable = (object as usize as *const u32).read_volatile();
    let method: Release = core::mem::transmute((vtable as usize as *const u32).add(1).read_volatile() as usize);
    method(object as usize as *mut u8);
}

#[cfg(not(target_os = "none"))]
unsafe fn release(object: *mut HostReleaseObject) {
    let vtable = core::ptr::addr_of!((*object).vtable).read_volatile();
    ((*vtable).release)(object.cast());
}

/// # Safety
///
/// `entry` must identify a writable target-layout entry. Non-null owned and
/// optional fields must name objects with a readable vtable slot +4.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn callback_queue_entry_destruct(entry: *mut CallbackQueueEntry) -> *mut CallbackQueueEntry {
    unsafe {
        submit(callback_queue_instance_get(), entry);
        destruct_embedded_state(entry.cast::<u8>().add(4));

        #[cfg(target_os = "none")]
        {
            let optional = core::ptr::addr_of!((*entry).optional).read_volatile();
            if optional != 0 { release(optional); }
            let owned = core::ptr::addr_of!((*entry).owned).read_volatile();
            if owned != 0 { release(owned); }
            core::ptr::addr_of_mut!((*entry).owned).write_volatile(0);
        }
        #[cfg(not(target_os = "none"))]
        {
            let optional = core::ptr::addr_of!((*entry).optional).read_volatile();
            if !optional.is_null() { release(optional); }
            let owned = core::ptr::addr_of!((*entry).owned).read_volatile();
            if !owned.is_null() { release(owned); }
            core::ptr::addr_of_mut!((*entry).owned).write_volatile(core::ptr::null_mut());
        }

        destruct_base(entry.cast::<u8>().add(4)).sub(4).cast()
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: [u8; 5] = [0; 5];
    static mut CALL_COUNT: usize = 0;
    static mut BASE_RESULT: *mut u8 = core::ptr::null_mut();

    unsafe fn record(call: u8) { CALLS[CALL_COUNT] = call; CALL_COUNT += 1; }
    unsafe extern "C" fn submit(_queue: *mut u8, _entry: *mut CallbackQueueEntry) { unsafe { record(1) } }
    unsafe extern "C" fn embedded(_state: *mut u8) { unsafe { record(2) } }
    unsafe extern "C" fn base(_state: *mut u8) -> *mut u8 { unsafe { record(5); BASE_RESULT } }
    unsafe extern "C" fn release_optional(_object: *mut u8) { unsafe { record(3) } }
    unsafe extern "C" fn release_owned(_object: *mut u8) { unsafe { record(4) } }

    #[test]
    fn submits_destroys_releases_in_order_and_rebases_base_result() {
        let _guard = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let optional_vtable = HostReleaseVtable { unresolved_00: 0, release: release_optional };
        let owned_vtable = HostReleaseVtable { unresolved_00: 0, release: release_owned };
        let mut optional = HostReleaseObject { vtable: &optional_vtable };
        let mut owned = HostReleaseObject { vtable: &owned_vtable };
        let mut entry = CallbackQueueEntry { owned: &mut owned, embedded_state: [0; 12], optional: &mut optional };
        unsafe {
            CALLS = [0; 5]; CALL_COUNT = 0;
            BASE_RESULT = (&mut entry as *mut CallbackQueueEntry).cast::<u8>().add(4);
            CALLBACK_QUEUE_ENTRY_DESTRUCT_OPS = CallbackQueueEntryDestructOps { submit, destruct_embedded_state: embedded, destruct_base: base };
            assert!(core::ptr::eq(callback_queue_entry_destruct(&mut entry), &mut entry));
            assert_eq!(CALLS, [1, 2, 3, 4, 5]);
            assert!(entry.owned.is_null());
            assert!(core::ptr::eq(entry.optional, &mut optional));
        }
    }

    #[test]
    fn skips_null_releases_but_still_runs_all_direct_calls() {
        let _guard = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let mut entry = CallbackQueueEntry { owned: core::ptr::null_mut(), embedded_state: [0; 12], optional: core::ptr::null_mut() };
        unsafe {
            CALLS = [0; 5]; CALL_COUNT = 0;
            BASE_RESULT = (&mut entry as *mut CallbackQueueEntry).cast::<u8>().add(4);
            CALLBACK_QUEUE_ENTRY_DESTRUCT_OPS = CallbackQueueEntryDestructOps { submit, destruct_embedded_state: embedded, destruct_base: base };
            assert!(core::ptr::eq(callback_queue_entry_destruct(&mut entry), &mut entry));
            assert_eq!(&CALLS[..CALL_COUNT], [1, 2, 5]);
        }
    }
}
